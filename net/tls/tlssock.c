/*
 * af_tls: TLS/DTLS socket
 *
 * Copyright (C) 2016
 *
 * Original authors:
 *   Fridolin Pokorny <fridolin.pokorny@gmail.com>
 *   Nikos Mavrogiannopoulos <nmav@gnults.org>
 *   Dave Watson <davejwatson@fb.com>
 *   Lance Chao <lancerchao@fb.com>
 *
 * Based on RFC 5288, RFC 6347, RFC 5246, RFC 6655
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 */

#include <crypto/aead.h>
#include <crypto/if_alg.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/strparser.h>
#include <linux/skbuff.h>
#include <linux/log2.h>
#include <net/tls.h>
#include <uapi/linux/tls.h>

/* Async worker */
static struct workqueue_struct *tls_rx_wq;
static struct workqueue_struct *tls_tx_wq;

struct tls_rx_msg {
	/* strp_rx_msg must be first to match strparser */
	struct strp_rx_msg rxm;
	int decrypted;
	struct aead_request* aead_req;
};

static inline struct tls_rx_msg *tls_rx_msg(struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct tls_rx_msg) > sizeof(skb->cb));
	return (struct tls_rx_msg *)((void *)skb->cb +
		offsetof(struct qdisc_skb_cb, data));
}

static inline struct tls_sock *tls_sk(struct sock *sk)
{
	return (struct tls_sock *)sk;
}

static inline bool tls_stream_memory_free(const struct sock *sk)
{
	const struct tls_sock *tsk = (const struct tls_sock *)sk;

	return tsk->unsent < TLS_MAX_PAYLOAD_SIZE && !tsk->async_encrypt;
}

static int tls_do_decryption(struct tls_sock *tsk,
			     struct scatterlist *sgin,
			     struct scatterlist *sgout,
			     char *header_recv,
			size_t data_len,
			struct sk_buff* skb);

static inline void tls_make_aad(struct tls_sock *tsk,
				int recv,
				char *buf,
				size_t size,
				char *nonce_explicit);

static int tls_post_process(struct tls_sock *tsk, struct sk_buff *skb);
static void tls_err_abort(struct tls_sock *tsk);

static void increment_seqno(unsigned char *seq, struct tls_sock *tsk)
{
	int i;

	for (i = 7; i >= 0; i--) {
		++seq[i];
		if (seq[i] != 0)
			break;
	}
	/* Check for overflow. If overflowed, connection must
	 * disconnect.  Raise an error and notify userspace.
	 */
	if (unlikely((IS_TLS(tsk) && i == -1) || (IS_DTLS(tsk) && i <= 1)))
		tls_err_abort(tsk);
}

/* Must be called with socket callback locked */
static void tls_unattach(struct tls_sock *tsk)
{
	write_lock_bh(&tsk->socket->sk->sk_callback_lock);
	tsk->rx_stopped = 1;
	strp_stop(&tsk->strp);
	tsk->socket->sk->sk_data_ready = tsk->saved_sk_data_ready;
	tsk->socket->sk->sk_write_space = tsk->saved_sk_write_space;
	tsk->socket->sk->sk_user_data = NULL;
	write_unlock_bh(&tsk->socket->sk->sk_callback_lock);
	release_sock(&tsk->sk);
	strp_done(&tsk->strp);
	lock_sock(&tsk->sk);
	sockfd_put(tsk->socket);
	tsk->socket = NULL;
}

static void tls_err_abort(struct tls_sock *tsk)
{
	struct sock *sk;

	printk("tls_err_abort\n");
	sk = (struct sock *)tsk;
	xchg(&tsk->rx_stopped, 1);
	xchg(&sk->sk_err, EBADMSG);
	sk->sk_error_report(sk);
	if (tsk->saved_sk_data_ready && tsk->socket) {
		tsk->saved_sk_data_ready(tsk->socket->sk);
	}
}

static void tls_abort_cb(struct strparser *strp, int err)
{
	struct tls_sock *tsk;

	tsk = strp->sk->sk_user_data;
	if (tsk)
		tls_err_abort(tsk);
}

static int decrypt_skb(struct tls_sock *tsk, struct sk_buff *skb)
{
	int ret, nsg;
	size_t prepend, overhead;
	struct strp_rx_msg *rxm;

	prepend = IS_TLS(tsk) ? TLS_TLS_PREPEND_SIZE : TLS_DTLS_PREPEND_SIZE;
	overhead = IS_TLS(tsk) ? TLS_TLS_OVERHEAD : TLS_DTLS_OVERHEAD;
	rxm = strp_rx_msg(skb);

	/* Copy header to pass into decryption routine.  Cannot use
	 * tsk->header_recv as that would cause a race between here
	 * and data_ready
	 */
	ret = skb_copy_bits(skb, rxm->offset, tsk->header_recv2, prepend);

	if (ret < 0)
		goto decryption_fail;

	sg_init_table(tsk->sgin, ARRAY_SIZE(tsk->sgin));
	sg_set_buf(&tsk->sgin[0], tsk->aad_recv, sizeof(tsk->aad_recv));

	nsg = skb_to_sgvec(skb, &tsk->sgin[1], rxm->offset +
			prepend,
			rxm->full_len - prepend);

	/* The length of sg into decryption must not be over
	 * ALG_MAX_PAGES. The aad takes the first sg, so the payload
	 * must be less than ALG_MAX_PAGES - 1
	 */
	if (nsg > ALG_MAX_PAGES - 1) {
		ret = -EBADMSG;
		printk("nsg too big\n");
		goto decryption_fail;
	}

	tls_make_aad(tsk, 1, tsk->aad_recv,
		     rxm->full_len - overhead,
		     tsk->iv_recv);

	/* Decrypt in place.  After this function call, the decrypted
	 * data will be in rxm->offset. We must therefore account for
	 * the fact that the lengths of skbuff_in and skbuff_out are
	 * different
	 */

	skb->sk = &tsk->sk;
	ret = tls_do_decryption(tsk,
				tsk->sgin,
				tsk->sgin,
				tsk->header_recv2,
				rxm->full_len - overhead,
				skb);

	if (ret < 0)
		goto decryption_fail;

	ret = tls_post_process(tsk, skb);

	if (ret < 0)
		goto decryption_fail;

	return 0;
decryption_fail:
	return ret;
}

/* Returns the length of the unencrypted message, plus overhead Note
 * that this function also populates tsk->header which is later used
 * for decryption. In TLS we automatically bail if we see a non-TLS
 * message. In DTLS we should determine if we got a corrupted message
 * vs a control msg Right now if the TLS magic bit got corrupted it
 * would incorrectly misinterpret it as a non-TLS message Returns 0 if
 * more data is necessary to determine length Returns <0 if error
 * occurred
 */
static inline ssize_t tls_read_size(struct tls_sock *tsk, struct sk_buff *skb)
{
	int ret;
	size_t data_len = 0;
	size_t datagram_len;
	size_t prepend;
	char first_byte;
	char *header;
	struct strp_rx_msg *rxm;

	prepend = IS_TLS(tsk) ? TLS_TLS_PREPEND_SIZE : TLS_DTLS_PREPEND_SIZE;
	header = tsk->header_recv;

	rxm = strp_rx_msg(skb);

	ret = skb_copy_bits(skb, rxm->offset, &first_byte, 1);
	if (ret < 0)
		goto read_failure;

	/* Check the first byte to see if its a TLS record */
	if (first_byte != TLS_RECORD_DATA) {
		ret = -EBADMSG;
		goto read_failure;
	}

	/* We have a TLS record. Check that msglen is long enough to
	 * read the length of record.  We must not check this before
	 * checking the first byte, since that will cause unencrypted
	 * messages shorter than TLS_TLS_PREPEND_SIZE to not be read
	 */
	if (rxm->offset + prepend > skb->len) {
		ret = 0;
		goto read_failure;
	}

	/* Copy header to read size.  An optimization could be to
	 * zero-copy, but you'd have to be able to walk
	 * frag_lists. This function call takes care of that.
	 * Overhead is relatively small (13 bytes for TLS, 21 for
	 * DTLS)
	 */
	ret = skb_copy_bits(skb, rxm->offset, header, prepend);

	if (ret < 0)
		goto read_failure;

	if (IS_TLS(tsk)) {
		data_len = ((header[4] & 0xFF) | (header[3] << 8));
		data_len = data_len - TLS_TAG_SIZE - TLS_IV_SIZE;
		datagram_len = data_len + TLS_TLS_OVERHEAD;
	} else {
		data_len = ((header[12] & 0xFF) | (header[11] << 8));
		data_len = data_len - TLS_TAG_SIZE - TLS_IV_SIZE;
		datagram_len = data_len + TLS_DTLS_OVERHEAD;
	}

	if (data_len > TLS_MAX_PAYLOAD_SIZE) {
		ret = -E2BIG;
		goto read_failure;
	}
	return datagram_len;

read_failure:
	/* TLS couldn't handle this message. Pass it directly to userspace */
	if (ret == -EBADMSG)
		tls_err_abort(tsk);

	return ret;
}

static int tls_parse_cb(struct strparser *strp, struct sk_buff *skb)
{
	struct tls_sock *tsk;

	tsk = strp->sk->sk_user_data;

	if (tsk)
		return tls_read_size(tsk, skb);
	else
		return -1;
}

static void tls_queue(struct strparser *strp, struct sk_buff *skb)
{
	struct tls_sock *tsk;
	int ret;
	struct strp_rx_msg *rxm;

	rxm = strp_rx_msg(skb);
	tsk = strp->sk->sk_user_data;

	if (!tsk || tsk->rx_stopped) {
		kfree_skb(skb);
		return;
	}

	tls_rx_msg(skb)->decrypted = 0;
	bh_lock_sock(&tsk->sk);

	ret = sock_queue_rcv_skb((struct sock *)tsk, skb);
	if (ret < 0) {
		/* skb receive queue is full. Apply backpressure on
		 * TCP socket
		 */
		skb_queue_tail(&tsk->rx_hold_queue, skb);
		strp->rx_paused = 1;
		tsk->sk.sk_data_ready(&tsk->sk);
	}
	bh_unlock_sock(&tsk->sk);
}

/* Called with lower socket held */
static void tls_data_ready(struct sock *sk)
{
	struct tls_sock *tsk;

	read_lock_bh(&sk->sk_callback_lock);

	tsk = (struct tls_sock *)sk->sk_user_data;
	if (unlikely(!tsk || tsk->rx_stopped))
		goto out;

	if (IS_TLS(tsk))
		strp_data_ready(&tsk->strp);
	else
		queue_work(tls_rx_wq, &tsk->recv_work);

out:
	read_unlock_bh(&sk->sk_callback_lock);
}

/* Called with lower socket held */
static void tls_write_space(struct sock *sk)
{
	struct tls_sock *tsk;

	read_lock_bh(&sk->sk_callback_lock);

	tsk = (struct tls_sock *)sk->sk_user_data;
	if (unlikely(!tsk || tsk->tx_stopped))
		goto out;

	queue_work(tls_tx_wq, &tsk->send_work);

out:
	read_unlock_bh(&sk->sk_callback_lock);
}

#include "dtls-window.c"

/* Loop through the SKBs. Decrypt each one and, if valid, add it to recv queue
*/
static int dtls_udp_read_sock(struct tls_sock *tsk)
{
	struct sk_buff *p, *next, *skb;
	int ret = 0;

	skb_queue_walk_safe(&tsk->socket->sk->sk_receive_queue, p, next) {
		ssize_t len;
		struct strp_rx_msg *rxm;

		rxm = strp_rx_msg(p);
		memset(rxm, 0, sizeof(*rxm));

		/* For UDP, set the offset such that the headers are
		 * ignored.  Full_len is length of skb minus the
		 * headers
		 */
		rxm->full_len = p->len - sizeof(struct udphdr);
		rxm->offset = sizeof(struct udphdr);
		len = tls_read_size(tsk, p);

		if (!len)
			goto record_pop;
		if (len < 0) {
			if (len == -EBADMSG) {
				/* Data does not appear to be a TLS
				 * record Make userspace handle it
				 */
				ret = -EBADMSG;
				break;
			}
			/* Failed for some other reason. Drop the
			 * packet
			 */
			goto record_pop;
		}
		if (dtls_window(tsk, tsk->header_recv +
					TLS_DTLS_SEQ_NUM_OFFSET) < 0)
			goto record_pop;

		skb = skb_clone(p, GFP_ATOMIC);
		if (!skb) {
			ret = -ENOMEM;
			break;
		}
		sock_queue_rcv_skb((struct sock *)tsk, skb);
record_pop:
		skb_unlink(p, &tsk->socket->sk->sk_receive_queue);
		kfree_skb(p);
	}
	return ret;
}

static void do_dtls_data_ready(struct tls_sock *tsk)
{
	int ret;

	ret = dtls_udp_read_sock(tsk);
	if (ret == -ENOMEM) /* No memory. Do it later */
		queue_work(tls_rx_wq, &tsk->recv_work);

	/* TLS couldn't handle this message. Pass it directly to
	 * userspace
	 */
	else if (ret == -EBADMSG)
		tls_err_abort(tsk);
}

static void do_dtls_sock_rx_work(struct tls_sock *tsk)
{
	struct sock *sk = tsk->socket->sk;

	lock_sock(sk);
	read_lock_bh(&sk->sk_callback_lock);

	if (unlikely(!tsk || sk->sk_user_data != tsk))
		goto out;

	if (unlikely(tsk->rx_stopped))
		goto out;

	if (!TLS_RECV_READY(tsk))
		goto out;

	do_dtls_data_ready(tsk);

out:
	read_unlock_bh(&sk->sk_callback_lock);
	release_sock(sk);
}

static void check_rcv(struct tls_sock *tsk)
{
	if (IS_TLS(tsk))
		strp_check_rcv(&tsk->strp);
	else
		do_dtls_sock_rx_work(tsk);
}

static void tls_rx_work(struct work_struct *w)
{
	do_dtls_sock_rx_work(container_of(w, struct tls_sock, recv_work));
}

static void tls_kernel_sendpage(struct tls_sock *tsk);

static void tls_tx_work(struct work_struct *w)
{
	struct tls_sock *tsk = container_of(w, struct tls_sock, send_work);

	struct sock *sk = &tsk->sk;

	lock_sock(sk);

	if (!tsk->tx_stopped)
		tls_kernel_sendpage(tsk);
	release_sock(sk);
}

static int tls_set_iv(struct socket *sock,
		      int recv,
		      char __user *src,
		      size_t src_len)
{
	int ret;
	unsigned char **iv;
	struct sock *sk;
	struct tls_sock *tsk;

	sk = sock->sk;
	tsk = tls_sk(sk);

	if (!src)
		return -EBADMSG;

	if (src_len != TLS_IV_SIZE)
		return -EBADMSG;

	iv = recv ? &tsk->iv_recv : &tsk->iv_send;

	if (!*iv) {
		*iv = kmalloc(src_len, GFP_KERNEL);
		if (!*iv)
			return -ENOMEM;
	}

	ret = copy_from_user(*iv, src, src_len);

	return ret ?: src_len;
}

static int tls_init_aead(struct tls_sock *tsk, int recv)
{
	int ret;
	struct crypto_aead *aead;
	struct tls_key *k;
	char keyval[TLS_KEY_SIZE + TLS_SALT_SIZE];
	size_t keyval_len;

	k = recv ? &tsk->key_recv : &tsk->key_send;
	aead = recv ? tsk->aead_recv : tsk->aead_send;

	/* We need salt and key in order to construct 20B key
	 * according to RFC5288, otherwise we will handle this once
	 * both will be provided
	 */
	if (k->keylen == 0 || k->saltlen == 0)
		return 0;

	keyval_len = k->keylen + k->saltlen;

	memcpy(keyval, k->key, k->keylen);
	memcpy(keyval + k->keylen, k->salt, k->saltlen);

	ret = crypto_aead_setkey(aead, keyval, keyval_len);
	if (ret)
		goto init_aead_end;

	ret = crypto_aead_setauthsize(aead, TLS_TAG_SIZE);

init_aead_end:
	return ret ?: 0;
}

static int tls_set_key(struct socket *sock,
		       int recv,
		       char __user *src,
		       size_t src_len)
{
	int ret;
	struct tls_sock *tsk;
	struct tls_key *k;

	tsk = tls_sk(sock->sk);

	if (src_len == 0 || !src)
		return -EBADMSG;

	if (src_len != TLS_KEY_SIZE)
		return -EBADMSG;

	k = recv ? &tsk->key_recv : &tsk->key_send;

	if (src_len > k->keylen) {
		kfree(k->key);
		k->key = kmalloc(src_len, GFP_KERNEL);
		if (!k->key)
			return -ENOMEM;
	}

	ret = copy_from_user(k->key, src, src_len);
	if (ret)
		goto set_key_end;

	k->keylen = src_len;

	ret = tls_init_aead(tsk, recv);

set_key_end:
	return ret < 0 ? ret : src_len;
}

static int tls_set_salt(struct socket *sock,
			int recv,
			char __user *src,
			size_t src_len)
{
	int ret;
	struct tls_sock *tsk;
	struct tls_key *k;

	tsk = tls_sk(sock->sk);

	k = recv ? &tsk->key_recv : &tsk->key_send;

	if (src_len != TLS_SALT_SIZE)
		return -EBADMSG;

	ret = copy_from_user(k->salt, src, src_len);
	if (ret)
		goto set_salt_end;

	k->saltlen = src_len;

	ret = tls_init_aead(tsk, recv);

set_salt_end:
	return ret < 0 ? ret : src_len;
}

static void tls_do_unattach(struct socket *sock)
{
	struct tls_sock *tsk;
	struct sock *sk;

	tsk = tls_sk(sock->sk);
	sk = tsk->socket->sk;

	tls_unattach(tsk);
}

static int tls_setsockopt(struct socket *sock,
			  int level, int optname,
			  char __user *optval,
			  unsigned int optlen)
{
	int ret;
	struct tls_sock *tsk;

	tsk = tls_sk(sock->sk);
	if (level != AF_TLS)
		return -ENOPROTOOPT;

	lock_sock(sock->sk);

	ret = -EBADMSG;
	if (!TLS_SETSOCKOPT_READY(tsk))
		goto setsockopt_end;

	switch (optname) {
	case TLS_SET_IV_RECV:
		ret = tls_set_iv(sock, 1, optval, optlen);
		break;
	case TLS_SET_KEY_RECV:
		ret = tls_set_key(sock, 1, optval, optlen);
		break;
	case TLS_SET_SALT_RECV:
		ret = tls_set_salt(sock, 1, optval, optlen);
		break;
	case TLS_SET_IV_SEND:
		ret = tls_set_iv(sock, 0, optval, optlen);
		break;
	case TLS_SET_KEY_SEND:
		ret = tls_set_key(sock, 0, optval, optlen);
		break;
	case TLS_SET_SALT_SEND:
		ret = tls_set_salt(sock, 0, optval, optlen);
		break;
	case TLS_UNATTACH:
		tls_do_unattach(sock);
		ret = 0;
		break;
	default:
		break;
	}

setsockopt_end:
	release_sock(sock->sk);
	return ret < 0 ? ret : 0;
}

static int tls_get_iv(const struct tls_sock *tsk,
		      int recv,
		      char __user *dst,
		      size_t dst_len)
{
	int ret;
	char *iv;

	if (dst_len < TLS_IV_SIZE)
		return -ENOMEM;

	iv = recv ? tsk->iv_recv : tsk->iv_send;

	if (!iv)
		return -EBADMSG;

	ret = copy_to_user(dst, iv, TLS_IV_SIZE);
	if (ret)
		return ret;

	return TLS_IV_SIZE;
}

static int tls_get_key(const struct tls_sock *tsk,
		       int recv,
		       char __user *dst,
		       size_t dst_len)
{
	int ret;
	const struct tls_key *k;

	k = recv ? &tsk->key_recv : &tsk->key_send;

	if (k->keylen == 0)
		return -EBADMSG;

	if (dst_len < k->keylen)
		return -ENOMEM;

	ret = copy_to_user(dst, k->key, k->keylen);

	return ret ?: k->keylen;
}

static int tls_get_salt(const struct tls_sock *tsk,
			int recv,
			char __user *dst,
			size_t dst_len)
{
	int ret;
	const struct tls_key *k;

	k = recv ? &tsk->key_recv : &tsk->key_send;

	if (k->saltlen == 0)
		return -EBADMSG;

	if (dst_len < k->saltlen)
		return -ENOMEM;

	ret = copy_to_user(dst, k->salt, k->saltlen);

	return ret ?: k->saltlen;
}

static int tls_getsockopt(struct socket *sock,
			  int level,
			  int optname,
			  char __user *optval,
			  int __user *optlen)
{
	int ret;
	int len;
	const struct tls_sock *tsk;

	tsk = tls_sk(sock->sk);

	if (level != AF_TLS)
		return -ENOPROTOOPT;

	if (!optlen || !optval)
		return -EBADMSG;

	if (get_user(len, optlen))
		return -EFAULT;

	lock_sock(sock->sk);

	ret = -EBADMSG;
	if (!TLS_GETSOCKOPT_READY(tsk))
		goto end;

	switch (optname) {
	case TLS_GET_IV_RECV:
		ret = tls_get_iv(tsk, 1, optval, len);
		break;
	case TLS_GET_KEY_RECV:
		ret = tls_get_key(tsk, 1, optval, len);
		break;
	case TLS_GET_SALT_RECV:
		ret = tls_get_salt(tsk, 1, optval, len);
		break;
	case TLS_GET_IV_SEND:
		ret = tls_get_iv(tsk, 0, optval, len);
		break;
	case TLS_GET_KEY_SEND:
		ret = tls_get_key(tsk, 0, optval, len);
		break;
	case TLS_GET_SALT_SEND:
		ret = tls_get_salt(tsk, 0, optval, len);
		break;
	default:
		ret = -EBADMSG;
		break;
	}

	if (ret < 0)
		goto end;

	ret = copy_to_user(optlen, &ret, sizeof(*optlen));

end:
	release_sock(sock->sk);
	return ret;
}

static inline void tls_make_prepend(struct tls_sock *tsk,
				    char *buf,
				    size_t plaintext_len)
{
	size_t pkt_len;

	pkt_len = plaintext_len + TLS_IV_SIZE + TLS_TAG_SIZE;

	/* we cover nonce explicit here as well, so buf should be of
	 * size TLS_DTLS_HEADER_SIZE + TLS_DTLS_NONCE_EXPLICIT_SIZE
	 */
	buf[0] = TLS_RECORD_DATA;
	buf[1] = tsk->version[0];
	buf[2] = tsk->version[1];
	/* we can use IV for nonce explicit according to spec */
	if (IS_TLS(tsk)) {
		buf[3] = pkt_len >> 8;
		buf[4] = pkt_len & 0xFF;
		memcpy(buf + TLS_TLS_NONCE_OFFSET, tsk->iv_send, TLS_IV_SIZE);
	} else {
		memcpy(buf + 3, tsk->iv_send, TLS_IV_SIZE);
		buf[11] = pkt_len >> 8;
		buf[12] = pkt_len & 0xFF;
		memcpy(buf + TLS_DTLS_NONCE_OFFSET,
		       tsk->iv_send,
		       TLS_IV_SIZE);
	}
}

static inline void tls_make_aad(struct tls_sock *tsk,
				int recv,
				char *buf,
				size_t size,
				char *nonce_explicit)
{
	memcpy(buf, nonce_explicit, TLS_NONCE_SIZE);

	buf[8] = TLS_RECORD_DATA;
	buf[9] = tsk->version[0];
	buf[10] = tsk->version[1];
	buf[11] = size >> 8;
	buf[12] = size & 0xFF;
}

void tls_send_done(struct crypto_async_request *req, int err);
static int tls_do_encryption(struct tls_sock *tsk,
			     struct scatterlist *sgin,
			     struct scatterlist *sgout,
			size_t data_len,
			struct sk_buff* skb)

{
	int ret;
	unsigned int req_size = sizeof(struct aead_request) +
		crypto_aead_reqsize(tsk->aead_recv);
	struct tls_rx_msg* msg = tls_rx_msg(skb);
	msg->aead_req = (void *)kmalloc(req_size, GFP_ATOMIC);

	if (!msg->aead_req)
		return -ENOMEM;

	aead_request_set_tfm(msg->aead_req, tsk->aead_send);
	aead_request_set_ad(msg->aead_req, TLS_AAD_SPACE_SIZE);
	aead_request_set_crypt(msg->aead_req, sgin, sgout, data_len, tsk->iv_send);
	aead_request_set_callback(msg->aead_req, 0, tls_send_done, skb);

	ret = crypto_aead_encrypt(msg->aead_req);
	if (ret == -EINPROGRESS) {
//		printk("async encrypt\n");
		tsk->async_encrypt = 1;
		sock_hold(&tsk->sk);
		return 0;
	}

 	kfree(msg->aead_req);
	if (ret < 0)
		return ret;
	tls_kernel_sendpage(tsk);

	return ret;
}

/* Allocates enough pages to hold the decrypted data, as well as
 * setting tsk->sg_tx_data to the pages
 */
static int tls_pre_encrypt(struct tls_sock *tsk, size_t data_len)
{
	int i;
	unsigned int npages;
	size_t aligned_size;
	size_t encrypt_len;
	struct scatterlist *sg;
	int ret = 0;

	encrypt_len = data_len + TLS_OVERHEAD(tsk);
	npages = encrypt_len / PAGE_SIZE;
	aligned_size = npages * PAGE_SIZE;
	if (aligned_size < encrypt_len)
		npages++;

	tsk->order_npages = order_base_2(npages);
	WARN_ON(tsk->order_npages < 0 || tsk->order_npages > 3);
	/* The first entry in sg_tx_data is AAD so skip it */
	sg_init_table(tsk->sg_tx_data, TLS_SG_DATA_SIZE);
	sg_set_buf(&tsk->sg_tx_data[0], tsk->aad_send, sizeof(tsk->aad_send));
	tsk->pages_send = alloc_pages(GFP_KERNEL | __GFP_COMP,
				      tsk->order_npages);
	if (!tsk->pages_send) {
		ret = -ENOMEM;
		return ret;
	}

	sg = tsk->sg_tx_data + 1;
	/* For the first page, leave room for prepend. It will be
	 * copied into the page later
	 */
	sg_set_page(sg, tsk->pages_send, PAGE_SIZE - TLS_PREPEND_SIZE(tsk),
		    TLS_PREPEND_SIZE(tsk));
	for (i = 1; i < npages; i++)
		sg_set_page(sg + i, tsk->pages_send + i, PAGE_SIZE, 0);
	return ret;
}

static int tls_push(struct tls_sock *tsk);
static void tls_kernel_sendpage(struct tls_sock *tsk)
{
	int ret;
	struct sk_buff *head;

	if (!tsk->socket)
		return;

	ret = kernel_sendpage(
		tsk->socket, tsk->pages_send, /* offset */ tsk->send_offset,
		tsk->send_len + TLS_OVERHEAD(tsk) - tsk->send_offset,
		MSG_DONTWAIT);

	if (ret > 0) {
		tsk->send_offset += ret;
		if (tsk->send_offset >= tsk->send_len + TLS_OVERHEAD(tsk)) {
			/* Successfully sent the whole packet, account for it.*/
			head = skb_peek(&tsk->sk.sk_write_queue);
			skb_dequeue(&tsk->sk.sk_write_queue);
			kfree_skb(head);
			tsk->sk.sk_wmem_queued -= tsk->send_len;
			tsk->unsent -= tsk->send_len;
			increment_seqno(tsk->iv_send, tsk);
			__free_pages(tsk->pages_send, tsk->order_npages);
			tsk->pages_send = NULL;
			tsk->async_encrypt = 0;
			tsk->sk.sk_write_space(&tsk->sk);
		}
	} else if (ret != -EAGAIN) {
		tls_err_abort(tsk);
	}
}

static int tls_push(struct tls_sock *tsk)
{
	int bytes = min_t(int, tsk->unsent, (int)TLS_MAX_PAYLOAD_SIZE);
	int nsg, ret = 0;
	struct sk_buff *head = skb_peek(&tsk->sk.sk_write_queue);

//	printk("tls_push head %p async_encrypt %i\n", head, tsk->async_encrypt);
	if (!head)
		return 0;

	if (tsk->async_encrypt)
		return -EAGAIN;

	bytes = min_t(int, bytes, head->len);
//	printk("tls_push bytes %i headlen %i unsent %i\n", bytes, head->len, tsk->unsent);

	sg_init_table(tsk->sg_tx_data2, ARRAY_SIZE(tsk->sg_tx_data2));
	nsg = skb_to_sgvec(head, &tsk->sg_tx_data2[0], 0, bytes);

	/* The length of sg into decryption must not be over
	 * ALG_MAX_PAGES. The aad takes the first sg, so the payload
	 * must be less than ALG_MAX_PAGES - 1
	 */
	if (nsg > ALG_MAX_PAGES - 1) {
		printk("tls_push: more than ALG_MAX_PAGES");
		ret = -EBADMSG;
		goto out;
	}


	tls_make_aad(tsk, 0, tsk->aad_send, bytes, tsk->iv_send);

	sg_chain(tsk->sgaad_send, 2, tsk->sg_tx_data2);
	sg_chain(tsk->sg_tx_data2,
		 nsg + 1,
		 tsk->sgtag_send);

	ret = tls_pre_encrypt(tsk, bytes);
	if (ret < 0)
		goto out;

	tls_make_prepend(tsk, page_address(tsk->pages_send), bytes);

	tsk->send_len = bytes;
	tsk->send_offset = 0;
	head->sk = &tsk->sk;


	ret = tls_do_encryption(tsk,
				tsk->sgaad_send,
				tsk->sg_tx_data,
				bytes, head);

	if (ret < 0)
		goto out;

out:
	if (ret < 0) {
		tsk->sk.sk_err = EPIPE;
//		printk("tls_push err: %i\n", ret);
		return ret;
	}

	return 0;
}

static int tls_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;
	struct tls_sock *tsk = tls_sk(sk);
	int ret = 0;
	long timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	bool eor = !(msg->msg_flags & MSG_MORE) || IS_DTLS(tsk);
	struct sk_buff *skb = NULL;
	size_t copy, copied = 0;

	lock_sock(sock->sk);

	if (msg->msg_flags & MSG_OOB) {
		ret = -ENOTSUPP;
		goto send_end;
	}
	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	if (!TLS_SEND_READY(tsk)) {
		ret = -EBADMSG;
		goto send_end;
	}

	if (size > TLS_MAX_PAYLOAD_SIZE && IS_DTLS(tsk)) {
		ret = -E2BIG;
		goto send_end;
	}

	while (msg_data_left(msg)) {
		bool merge = true;
		int i;
		struct page_frag *pfrag;

		if (sk->sk_err)
			goto send_end;

		if (!sk_stream_memory_free(sk))
			goto wait_for_memory;

		skb = tcp_write_queue_tail(sk);

		while (!skb) {
			skb = alloc_skb(0, sk->sk_allocation);
			if (skb)
				__skb_queue_tail(&sk->sk_write_queue, skb);
		}

		i = skb_shinfo(skb)->nr_frags;
		pfrag = sk_page_frag(sk);

		if (!sk_page_frag_refill(sk, pfrag))
			goto wait_for_memory;

		if (!skb_can_coalesce(skb, i, pfrag->page,
				      pfrag->offset)) {
			if (i == ALG_MAX_PAGES) {
				struct sk_buff *tskb;

				tskb = alloc_skb(0, sk->sk_allocation);
				if (!tskb)
					goto wait_for_memory;

				if (skb)
					skb->next = tskb;
				else
					__skb_queue_tail(&sk->sk_write_queue,
							 tskb);

				skb = tskb;
				skb->ip_summed = CHECKSUM_UNNECESSARY;
				continue;
			}
			merge = false;
		}

		copy = min_t(int, msg_data_left(msg),
			     pfrag->size - pfrag->offset);
		copy = min_t(int, copy, TLS_MAX_PAYLOAD_SIZE - tsk->unsent);

		if (!sk_wmem_schedule(sk, copy))
			goto wait_for_memory;

		ret = skb_copy_to_page_nocache(sk, &msg->msg_iter, skb,
					       pfrag->page,
					       pfrag->offset,
					       copy);
		if (ret)
			goto send_end;

		/* Update the skb. */
		if (merge) {
			skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
		} else {
			skb_fill_page_desc(skb, i, pfrag->page,
					   pfrag->offset, copy);
			get_page(pfrag->page);
		}

		pfrag->offset += copy;
		copied += copy;
		tsk->unsent += copy;

		if (tsk->unsent >= TLS_MAX_PAYLOAD_SIZE) {
			ret = tls_push(tsk);
			if (ret == -EINPROGRESS)
				goto push_wait;
			else if (ret)
				goto send_end;
		}

		continue;

wait_for_memory:
		ret = tls_push(tsk);
		if (ret == -EINPROGRESS)
			goto push_wait;
		else if (ret)
			goto send_end;
push_wait:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		ret = sk_stream_wait_memory(sk, &timeo);
		if (ret)
			goto send_end;
	}

	if (eor)
		ret = tls_push(tsk);

send_end:
	ret = sk_stream_error(sk, msg->msg_flags, ret);

	/* make sure we wake any epoll edge trigger waiter */
	if (unlikely(skb_queue_len(&sk->sk_write_queue) == 0 && ret == -EAGAIN))
		sk->sk_write_space(sk);

	release_sock(sk);

	return ret < 0 ? ret : size;
}

void tls_recv_done(struct crypto_async_request *req, int err)
{
	struct sk_buff *skb = req->data;
	struct tls_sock *tsk = tls_sk(skb->sk);

	if (err == -EINPROGRESS)
		return;

	bh_lock_sock(&tsk->sk);
	tsk->async_decrypt = 0;
	tls_post_process(tsk, skb);

 	kfree(tls_rx_msg(skb)->aead_req);
	tsk->sk.sk_data_ready(&tsk->sk);
	bh_unlock_sock(&tsk->sk);
	sock_put(&tsk->sk);
}

void tls_send_done(struct crypto_async_request *req, int err)
{
	struct sk_buff *skb = req->data;
	struct tls_sock *tsk = tls_sk(skb->sk);

	if (err == -EINPROGRESS)
		return;

	// TODO: encrypted flag for sending?
	// There is a race between tls_kernel_sendpage and
	// the next tls_sendmsg call which might smash the
	// encrypted data before it is sent.
	//
	// Potentially pop off sending skb?
	bh_lock_sock(&tsk->sk);
 	kfree(tls_rx_msg(skb)->aead_req);
	queue_work(tls_tx_wq, &tsk->send_work);
	bh_unlock_sock(&tsk->sk);

	sock_put(&tsk->sk);
}


static int tls_do_decryption(struct tls_sock *tsk,
			     struct scatterlist *sgin,
			     struct scatterlist *sgout,
			     char *header_recv,
			size_t data_len,
			struct sk_buff* skb)
{
	int ret;
	unsigned int req_size = sizeof(struct aead_request) +
		crypto_aead_reqsize(tsk->aead_recv);
	struct tls_rx_msg* msg = tls_rx_msg(skb);
	msg->aead_req = (void *)kmalloc(req_size, GFP_ATOMIC);
	if (!msg->aead_req)
		return -ENOMEM;

	aead_request_set_tfm(msg->aead_req, tsk->aead_recv);
	aead_request_set_ad(msg->aead_req, TLS_AAD_SPACE_SIZE);
	aead_request_set_crypt(msg->aead_req, sgin, sgout,
			       data_len + TLS_TAG_SIZE,
			       (u8 *)header_recv + TLS_NONCE_OFFSET(tsk));
	aead_request_set_callback(msg->aead_req, 0, tls_recv_done, skb);
	ret = crypto_aead_decrypt(msg->aead_req);
	if (ret == -EINPROGRESS) {
		sock_hold(&tsk->sk);
		tsk->async_decrypt = 1;
		return ret;
	}

	kfree(msg->aead_req);

	return ret;
}

static int tls_post_process(struct tls_sock *tsk, struct sk_buff *skb)
{
	size_t prepend, overhead;
	struct strp_rx_msg *rxm;

	int err = 0;

	prepend = IS_TLS(tsk) ? TLS_TLS_PREPEND_SIZE : TLS_DTLS_PREPEND_SIZE;
	overhead = IS_TLS(tsk) ? TLS_TLS_OVERHEAD : TLS_DTLS_OVERHEAD;
	rxm = strp_rx_msg(skb);

	/* The crypto API does the following transformation.
	 * Before:
	 *   AAD(13) | DATA | TAG
	 * After:
	 *   AAD(13) | DECRYPTED | TAG
	 * The AAD and TAG is left untouched. However we don't want that
	 * returned to the user. Therefore we fix the offsets and lengths
	 */
	rxm->offset += prepend;
	rxm->full_len -= overhead;
	increment_seqno(tsk->iv_recv, tsk);

	if (!pskb_pull(skb, rxm->offset)) {
		err = -1;
		tls_err_abort(tsk);
		goto out;
	}
	if ((err = pskb_trim(skb, rxm->full_len))) {
		tls_err_abort(tsk);
		goto out;
	}
	rxm->offset = 0;

	tls_rx_msg(skb)->decrypted = 1;
out:
	return err;
}

static unsigned int tls_poll(struct file *file, struct socket *sock,
			     struct poll_table_struct *wait)
{
	unsigned int ret;
	struct tls_sock *tsk;
	unsigned int mask = 0;
	struct sock *sk;

	sk = sock->sk;
	tsk = tls_sk(sock->sk);

	/* Call POLL on the underlying socket, which will call
	 * sock_poll_wait on underlying socket. Used for POLLOUT and
	 * POLLHUP
	 */
	ret = tsk->socket->ops->poll(tsk->socket->file, tsk->socket, wait);

	/* Clear POLLIN bits. Data available in the underlying socket is not
	 * necessarily ready to be read. The data could still be in the process
	 * of decryption, or it could be meant for original fd.
	 */
	ret &= ~(POLLIN | POLLRDNORM);

	/* Used for POLLIN
	 * Call generic POLL on TLS socket, which works for any
	 * sockets provided the socket receive queue is only ever
	 * holding data ready to receive.  Data ready to be read are
	 * stored in TLS's sk_receive_queue
	 */
	if (!tsk->async_decrypt)
		mask = datagram_poll(file, sock, wait);

	/* Clear POLLOUT and POLLHUPbits. Even if TLS is ready to
	 * send, data won't be sent if the underlying socket is not
	 * ready. in addition, even if TLS was initialized as a
	 * stream socket, it's not actually connected to anything, so
	 * we ignore its POLLHUP.  Also, we don't support priority
	 * band writes in TLS
	 */
	mask &= ~(POLLOUT | POLLWRNORM | POLLHUP);

	ret |= mask;

	/* POLLERR should return if either socket is received error.
	 * We don't support high-priority data atm, so clear those
	 * bits
	 */
	ret &= ~(POLLWRBAND | POLLRDBAND);

	return ret;
}

static void tls_dequeue_held_data(struct tls_sock *tsk)
{
	if (tsk->strp.rx_paused) {
		int unpause = 1;
		struct sk_buff *skb;

		while ((skb = skb_dequeue(&tsk->rx_hold_queue))) {
			int ret = sock_queue_rcv_skb((struct sock *)tsk, skb);

			if (ret < 0) {
				skb_queue_head(&tsk->rx_hold_queue, skb);
				unpause = 0;
				break;
			}
		}
		if (unpause) {
			tsk->strp.rx_paused = 0;
			strp_check_rcv(&tsk->strp);
		}
	}
}

static struct sk_buff *tls_wait_data(struct tls_sock *tsk, int flags,
				     long timeo, int *err)
{
	struct sk_buff *skb;
	struct sock *sk;

	sk = (struct sock *)tsk;

	while (!(skb = skb_peek(&sk->sk_receive_queue)) || tsk->async_decrypt) {
		/* Don't clear sk_err since recvmsg may not return it
		 * immediately. Instead, clear it after the next
		 * attach
		 */
		if (sk->sk_err) {
			*err = -sk->sk_err;
			return NULL;
		}

		if (sock_flag(sk, SOCK_DONE))
			return NULL;

		if ((flags & MSG_DONTWAIT) || !timeo) {
			*err = -EAGAIN;
			return NULL;
		}

		DEFINE_WAIT(wait);

		prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);

		if (!skb) {
			sk_wait_event(sk, &timeo,
				skb_peek_tail(&sk->sk_receive_queue) != skb);
		} else {
			sk_wait_event(sk, &timeo,
				!tsk->async_decrypt);
		}
		sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		finish_wait(sk_sleep(sk), &wait);

		/* Handle signals */
		if (signal_pending(current)) {
			*err = sock_intr_errno(timeo);
			return NULL;
		}
	}

	return skb;
}


static int tls_recvmsg(struct socket *sock,
		       struct msghdr *msg,
		       size_t len,
		       int flags)
{
	ssize_t copied = 0;
	int err = 0;
	long timeo;
	struct tls_sock *tsk;
	struct strp_rx_msg *rxm;
	int ret = 0;
	struct sk_buff *skb;

	tsk = tls_sk(sock->sk);
	lock_sock(sock->sk);

	err = -tsk->sk.sk_err;
	if (err)
		goto recv_end;

	if (!TLS_RECV_READY(tsk)) {
		err = -EBADMSG;
		goto recv_end;
	}

	timeo = sock_rcvtimeo(&tsk->sk, flags & MSG_DONTWAIT);
	do {
		int chunk;

		tls_dequeue_held_data(tsk);
		skb = tls_wait_data(tsk, flags, timeo, &err);
		if (!skb)
			goto recv_end;

		rxm = strp_rx_msg(skb);
		/* It is possible that the message is already
		 * decrypted if the last call only read part of the
		 * message
		 */
		if (!tls_rx_msg(skb)->decrypted) {
			err = decrypt_skb(tsk, skb);
			if (err == -EINPROGRESS)
				continue;
			if (err < 0) {
				tls_err_abort(tsk);
				goto recv_end;
			}
			tls_rx_msg(skb)->decrypted = 1;
		}
		chunk = min_t(unsigned int, rxm->full_len, len);
		err = skb_copy_datagram_msg(skb, rxm->offset, msg, chunk);
		if (err < 0)
			goto recv_end;
		copied += chunk;
		len -= chunk;
		if (likely(!(flags & MSG_PEEK))) {
			if (chunk < rxm->full_len) {
				rxm->offset += chunk;
				rxm->full_len -= chunk;
			} else {
				/* Finished with message */
				skb_unlink(skb, &((struct sock *)tsk)
						->sk_receive_queue);
				kfree_skb(skb);
			}
		}

	} while (len);

recv_end:
	release_sock(sock->sk);
	if (err)
		BUG_ON(err > 0);
	ret = copied ? : err;

	return ret;
}

static int dtls_recvmsg(struct socket *sock,
			struct msghdr *msg,
			size_t len,
			int flags)
{
	ssize_t copied = 0;
	int err;
	struct tls_sock *tsk;
	struct strp_rx_msg *rxm;
	int ret = 0;
	struct sk_buff *skb;

	tsk = tls_sk(sock->sk);
	lock_sock(sock->sk);

	if (!TLS_RECV_READY(tsk)) {
		err = -EBADMSG;
		goto recv_end;
	}

again:
	tls_dequeue_held_data(tsk);
	skb = skb_recv_datagram((struct sock *)tsk, flags & ~MSG_DONTWAIT,
				flags & MSG_DONTWAIT, &err);
	if (!skb)
		goto recv_end;
	rxm = strp_rx_msg(skb);
	err = decrypt_skb(tsk, skb);
	if (err == -EINPROGRESS)
		goto again;
	if (err < 0) {
		tls_err_abort(tsk);
		goto recv_end;
	}
	err = skb_copy_datagram_msg(skb, rxm->offset, msg, rxm->full_len);
	if (err < 0)
		goto recv_end;
	copied = rxm->full_len;
	if (copied > len)
		msg->msg_flags |= MSG_TRUNC;
	if (likely(!(flags & MSG_PEEK))) {
		msg->msg_flags |= MSG_EOR;
		skb_free_datagram((struct sock *)tsk, skb);
	}
recv_end:

	release_sock(sock->sk);
	ret = copied ? : err;
	return ret;
}

static int tls_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	int ret;
	struct tls_sock *tsk;
	struct sockaddr_tls *sa_tls;
	struct strp_callbacks cb;

	if (!uaddr || sizeof(*sa_tls) != addr_len)
		return -EBADMSG;

	tsk = tls_sk(sock->sk);
	sa_tls = (struct sockaddr_tls *)uaddr;

	lock_sock(sock->sk);

	if (tsk->socket) {
		ret = -EINVAL;
		goto out;
	}

	switch (sa_tls->sa_cipher) {
	case TLS_CIPHER_AES_GCM_128:
		tsk->cipher_type = TLS_CIPHER_AES_GCM_128;
		tsk->cipher_crypto = "rfc5288(gcm(aes))";
		break;
	default:
		ret = -ENOENT;
		goto out;
	}

	switch (sa_tls->sa_version) {
	case TLS_VERSION_LATEST:
		/* passthrough */
	case TLS_VERSION_1_2:
		if (IS_TLS(tsk)) {
			tsk->version[0] = TLS_TLS_1_2_MAJOR;
			tsk->version[1] = TLS_TLS_1_2_MINOR;
		} else {
			tsk->version[0] = TLS_DTLS_1_2_MAJOR;
			tsk->version[1] = TLS_DTLS_1_2_MINOR;
		}
		break;
	default:
		ret = -ENOENT;
		goto out;
	}

	tsk->socket = sockfd_lookup(sa_tls->sa_socket, &ret);
	if (!tsk->socket) {
		ret = -ENOENT;
		goto out;
	}
	if (!IS_TCP(tsk->socket) && !IS_UDP(tsk->socket)) {
		ret = -EAFNOSUPPORT;
		goto bind_end;
	}

	/* Do not allow TLS over unreliable UDP */
	if (IS_TLS(tsk) && IS_UDP(tsk->socket)) {
		ret = -EBADF;
		goto bind_end;
	}

	if (!tsk->aead_recv) {
		tsk->aead_recv = crypto_alloc_aead(tsk->cipher_crypto,
				CRYPTO_ALG_INTERNAL, 0);
		if (IS_ERR(tsk->aead_recv)) {
			ret = PTR_ERR(tsk->aead_recv);
			tsk->aead_recv = NULL;
			goto bind_end;
		}
	}

	if (!tsk->aead_send) {
		tsk->aead_send = crypto_alloc_aead(tsk->cipher_crypto,
				CRYPTO_ALG_INTERNAL, 0);
		if (IS_ERR(tsk->aead_send)) {
			ret = PTR_ERR(tsk->aead_send);
			tsk->aead_send = NULL;
			goto bind_end;
		}
	}

	((struct sock *)tsk)->sk_err = 0;

	cb.rcv_msg = tls_queue;
	cb.abort_parser = tls_abort_cb;
	cb.parse_msg = tls_parse_cb;
	cb.read_sock_done = NULL;

	strp_init(&tsk->strp, tsk->socket->sk, &cb);

	write_lock_bh(&tsk->socket->sk->sk_callback_lock);
	tsk->rx_stopped = 0;
	tsk->saved_sk_data_ready = tsk->socket->sk->sk_data_ready;
	tsk->saved_sk_write_space = tsk->socket->sk->sk_write_space;
	tsk->socket->sk->sk_data_ready = tls_data_ready;
	tsk->socket->sk->sk_write_space = tls_write_space;
	tsk->socket->sk->sk_user_data = tsk;
	write_unlock_bh(&tsk->socket->sk->sk_callback_lock);

	sock->sk->sk_protocol = tsk->socket->sk->sk_protocol;

	tsk->tx_stopped = 0;

	release_sock(sock->sk);
	/* Check if any TLS packets have come in between the time the
	 * handshake was completed and bind() was called. If there
	 * were, the packets would have woken up TCP socket waiters,
	 * not TLS. Therefore, pull the packets from TCP and wake up
	 * TLS if necessary
	 */
	check_rcv(tsk);

	return 0;

bind_end:
	sockfd_put(tsk->socket);
	tsk->socket = NULL;
out:
	release_sock(sock->sk);
	return ret;
}


static int tls_release(struct socket *sock)
{
	struct tls_sock *tsk;

	tsk = tls_sk(sock->sk);

	if (sock->sk)
		sock_put(sock->sk);

	return 0;
}

static const struct proto_ops tls_stream_ops = {
	.family		=	PF_TLS,
	.owner		=	THIS_MODULE,

	.connect	=	sock_no_connect,
	.socketpair	=	sock_no_socketpair,
	.getname	=	sock_no_getname,
	.ioctl		=	sock_no_ioctl,
	.listen		=	sock_no_listen,
	.shutdown	=	sock_no_shutdown,
	.mmap		=	sock_no_mmap,
	.poll		=	tls_poll,
	.accept		=	sock_no_accept,

	.bind		=	tls_bind,
	.setsockopt	=	tls_setsockopt,
	.getsockopt	=	tls_getsockopt,
	.sendmsg	=	tls_sendmsg,
	.recvmsg	=	tls_recvmsg,
	.release	=	tls_release,
};

static const struct proto_ops tls_dgram_ops = {
	.family		=	PF_TLS,
	.owner		=	THIS_MODULE,

	.connect	=	sock_no_connect,
	.socketpair	=	sock_no_socketpair,
	.getname	=	sock_no_getname,
	.ioctl		=	sock_no_ioctl,
	.listen		=	sock_no_listen,
	.shutdown	=	sock_no_shutdown,
	.mmap		=	sock_no_mmap,
	.poll		=	tls_poll,
	.accept		=	sock_no_accept,

	.bind		=	tls_bind,
	.setsockopt	=	tls_setsockopt,
	.getsockopt	=	tls_getsockopt,
	.sendmsg	=	tls_sendmsg,
	.recvmsg	=	dtls_recvmsg,
	.release	=	tls_release,
};

static void tls_sock_destruct(struct sock *sk)
{
	struct tls_sock *tsk;

	tsk = tls_sk(sk);

	lock_sock(sk);

	tsk->tx_stopped = 1;

	/* restore callback and abandon socket */
	cancel_work_sync(&tsk->recv_work);
	cancel_work_sync(&tsk->send_work);

	strp_stop(&tsk->strp);
	if (tsk->socket) {
		write_lock_bh(&tsk->socket->sk->sk_callback_lock);
		tsk->rx_stopped = 1;
		tsk->socket->sk->sk_data_ready = tsk->saved_sk_data_ready;
		tsk->socket->sk->sk_write_space = tsk->saved_sk_write_space;
		tsk->socket->sk->sk_user_data = NULL;
		write_unlock_bh(&tsk->socket->sk->sk_callback_lock);
	}
	release_sock(sk);

	strp_done(&tsk->strp);
	lock_sock(sk);
 	if (tsk->socket) {
 		sockfd_put(tsk->socket);
 		tsk->socket = NULL;
	}

	kfree(tsk->iv_send);

	kfree(tsk->key_send.key);

	kfree(tsk->iv_recv);

	kfree(tsk->key_recv.key);

	crypto_free_aead(tsk->aead_send);

	crypto_free_aead(tsk->aead_recv);

 	if (tsk->pages_send)
		__free_pages(tsk->pages_send, tsk->order_npages);

	skb_queue_purge(&tsk->rx_hold_queue);
	skb_queue_purge(&sk->sk_receive_queue);
	skb_queue_purge(&sk->sk_write_queue);
	release_sock(sk);
}

static struct proto tls_proto = {
	.name				= "TLS",
	.owner			= THIS_MODULE,
	.obj_size		= sizeof(struct tls_sock),
	.stream_memory_free = tls_stream_memory_free,
};

static int tls_create(struct net *net,
		      struct socket *sock,
		      int protocol,
		      int kern)
{
	int ret;
	struct sock *sk;
	struct tls_sock *tsk;

	switch (sock->type) {
	case SOCK_STREAM:
		sock->ops = &tls_stream_ops;
		break;
	case SOCK_DGRAM:
		sock->ops = &tls_dgram_ops;
		break;
	default:
		return -ESOCKTNOSUPPORT;
	}

	if (protocol != 0)
		return -EPROTONOSUPPORT;

	sk = sk_alloc(net, PF_TLS, GFP_ATOMIC, &tls_proto, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);

	sk->sk_family = PF_TLS;
	sk->sk_destruct = tls_sock_destruct;

	/* initialize stored context */
	tsk = tls_sk(sk);

	tsk->async_decrypt = 0;
	tsk->async_encrypt = 0;
	tsk->iv_send = NULL;
	memset(&tsk->key_send, 0, sizeof(tsk->key_send));

	tsk->socket = NULL;

	tsk->iv_recv = NULL;
	memset(&tsk->key_recv, 0, sizeof(tsk->key_recv));

	tsk->cipher_crypto = NULL;
	memset(tsk->version, 0, sizeof(tsk->version));

	tsk->pages_send = NULL;
	tsk->unsent = 0;

	tsk->dtls_window.have_recv = 0;

	ret = -ENOMEM;
	/* Preallocation for sending
	 *   scatterlist: AAD | data | TAG (for crypto API)
	 *   vec: HEADER | data | TAG
	 */
	sg_init_table(tsk->sg_tx_data, TLS_SG_DATA_SIZE);
	sg_set_buf(&tsk->sg_tx_data[0], tsk->aad_send, sizeof(tsk->aad_send));

	sg_set_buf(tsk->sg_tx_data + TLS_SG_DATA_SIZE - 2,
		   tsk->tag_send, sizeof(tsk->tag_send));
	sg_mark_end(tsk->sg_tx_data + TLS_SG_DATA_SIZE - 1);

	sg_init_table(tsk->sgaad_send, 2);
	sg_init_table(tsk->sgtag_send, 2);

	sg_set_buf(&tsk->sgaad_send[0], tsk->aad_send, sizeof(tsk->aad_send));
	/* chaining to tag is performed on actual data size when sending */
	sg_set_buf(&tsk->sgtag_send[0], tsk->tag_send, sizeof(tsk->tag_send));

	sg_unmark_end(&tsk->sgaad_send[1]);
	INIT_WORK(&tsk->recv_work, tls_rx_work);
	INIT_WORK(&tsk->send_work, tls_tx_work);

	skb_queue_head_init(&tsk->rx_hold_queue);

	return 0;
}

static const struct net_proto_family tls_family = {
	.family	=	PF_TLS,
	.create	=	tls_create,
	.owner	=	THIS_MODULE,
};

static int __init tls_init(void)
{
	int ret = -ENOMEM;

	tls_rx_wq = create_workqueue("tls");
	if (!tls_rx_wq)
		goto tls_init_end;

	tls_tx_wq = create_workqueue("tls");
	if (!tls_tx_wq) {
		destroy_workqueue(tls_rx_wq);
		goto tls_init_end;
	}

	ret = proto_register(&tls_proto, 0);
	if (ret) {
		destroy_workqueue(tls_rx_wq);
		destroy_workqueue(tls_tx_wq);
		goto tls_init_end;
	}

	ret = sock_register(&tls_family);
	if (ret != 0) {
		proto_unregister(&tls_proto);
		destroy_workqueue(tls_rx_wq);
		destroy_workqueue(tls_tx_wq);
		goto tls_init_end;
	}

tls_init_end:
	return ret;
}

static void __exit tls_exit(void)
{
	sock_unregister(PF_TLS);
	proto_unregister(&tls_proto);
	destroy_workqueue(tls_rx_wq);
	destroy_workqueue(tls_tx_wq);
}

module_init(tls_init);
module_exit(tls_exit);
MODULE_LICENSE("GPL");
