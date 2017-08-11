/*
 * Copyright (c) 2016-2017, Mellanox Technologies. All rights reserved.
 * Copyright (c) 2016-2017, Dave Watson <davejwatson@fb.com>. All rights reserved.
 * Copyright (c) 2016-2017, Lance Chao <lancerchao@fb.com>. All rights reserved.
 * Copyright (c) 2016, Fridolin Pokorny <fridolin.pokorny@gmail.com>. All rights reserved.
 * Copyright (c) 2016, Nikos Mavrogiannopoulos <nmav@gnutls.org>. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/module.h>
#include <linux/sched/signal.h>
#include <crypto/aead.h>

#include <net/tls.h>
#include <net/strparser.h>

struct tls_rx_msg {
	/* strp_rx_msg must be first to match strparser */
	struct strp_rx_msg rxm;
	int decrypted;
};

static inline struct tls_rx_msg *tls_rx_msg(struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct tls_rx_msg) > sizeof(skb->cb));
	return (struct tls_rx_msg *)((void *)skb->cb +
				offsetof(struct qdisc_skb_cb, data));
}

static int tls_post_process(struct sock *sk, struct sk_buff *skb)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	size_t prepend, overhead;
	struct strp_rx_msg *rxm;

	int err = 0;

	prepend = 13;//TLS_PREPEND_SIZE;
	overhead = 21;//TLS_OVERHEAD;
	rxm = strp_rx_msg(skb);

	rxm->offset += prepend;
	rxm->full_len -= tls_ctx->rx.overhead_size;
	tls_advance_record_sn(sk, &tls_ctx->rx);

	if (!pskb_pull(skb, rxm->offset)) {
		err = -1;
		tls_err_abort(sk);
		goto out;
	}
	err = pskb_trim(skb, rxm->full_len);
	if (err) {
		tls_err_abort(sk);
		goto out;
	}
	rxm->offset = 0;

	tls_rx_msg(skb)->decrypted = 1;
out:
	return err;
}

static int tls_do_decryption(struct sock *sk,
			     struct scatterlist *sgin,
			     struct scatterlist *sgout,
			     char *iv_recv,
			     size_t data_len,
			struct sk_buff *skb,
			gfp_t flags)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	struct aead_request *aead_req;

	int ret;
	unsigned int req_size = sizeof(struct aead_request) +
		crypto_aead_reqsize(ctx->aead_recv);

	aead_req = kmalloc(req_size, flags);
	if (!aead_req)
		return -ENOMEM;

	aead_request_set_tfm(aead_req, ctx->aead_recv);
	aead_request_set_ad(aead_req, TLS_AAD_SPACE_SIZE);
	aead_request_set_crypt(aead_req, sgin, sgout,
			       data_len + tls_ctx->rx.tag_size,
			       (u8 *)iv_recv);
	ret = crypto_aead_decrypt(aead_req);
	if (ret < 0) {
		kfree(aead_req);
		return ret;
	}
	tls_post_process(sk, skb);
	kfree(aead_req);
	ctx->saved_data_ready(sk);

	return ret;
}

static inline void tls_make_aad(int recv,
				char *buf,
				size_t size,
				char *record_sequence,
				int record_sequence_size,
				unsigned char record_type)
{
	memcpy(buf, record_sequence, record_sequence_size);

	buf[8] = record_type;
	buf[9] = TLS_1_2_VERSION_MAJOR;
	buf[10] = TLS_1_2_VERSION_MINOR;
	buf[11] = size >> 8;
	buf[12] = size & 0xFF;
}

static void trim_sg(struct sock *sk, struct scatterlist *sg,
		    int *sg_num_elem, unsigned int *sg_size, int target_size)
{
	int i = *sg_num_elem - 1;
	int trim = *sg_size - target_size;

	if (trim <= 0) {
		WARN_ON(trim < 0);
		return;
	}

	*sg_size = target_size;
	while (trim >= sg[i].length) {
		trim -= sg[i].length;
		sk_mem_uncharge(sk, sg[i].length);
		put_page(sg_page(&sg[i]));
		i--;

		if (i < 0)
			goto out;
	}

	sg[i].length -= trim;
	sk_mem_uncharge(sk, trim);

out:
	*sg_num_elem = i + 1;
}

static void trim_both_sgl(struct sock *sk, int target_size)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);

	trim_sg(sk, ctx->sg_plaintext_data,
		&ctx->sg_plaintext_num_elem,
		&ctx->sg_plaintext_size,
		target_size);

	if (target_size > 0)
		target_size += tls_ctx->tx.overhead_size;

	trim_sg(sk, ctx->sg_encrypted_data,
		&ctx->sg_encrypted_num_elem,
		&ctx->sg_encrypted_size,
		target_size);
}

static int alloc_sg(struct sock *sk, int len, struct scatterlist *sg,
		    int *sg_num_elem, unsigned int *sg_size,
		    int first_coalesce)
{
	struct page_frag *pfrag;
	unsigned int size = *sg_size;
	int num_elem = *sg_num_elem, use = 0, rc = 0;
	struct scatterlist *sge;
	unsigned int orig_offset;

	len -= size;
	pfrag = sk_page_frag(sk);

	while (len > 0) {
		if (!sk_page_frag_refill(sk, pfrag)) {
			rc = -ENOMEM;
			goto out;
		}

		use = min_t(int, len, pfrag->size - pfrag->offset);

		if (!sk_wmem_schedule(sk, use)) {
			rc = -ENOMEM;
			goto out;
		}

		sk_mem_charge(sk, use);
		size += use;
		orig_offset = pfrag->offset;
		pfrag->offset += use;

		sge = sg + num_elem - 1;
		if (num_elem > first_coalesce && sg_page(sg) == pfrag->page &&
		    sg->offset + sg->length == orig_offset) {
			sg->length += use;
		} else {
			sge++;
			sg_unmark_end(sge);
			sg_set_page(sge, pfrag->page, use, orig_offset);
			get_page(pfrag->page);
			++num_elem;
			if (num_elem == MAX_SKB_FRAGS) {
				rc = -ENOSPC;
				break;
			}
		}

		len -= use;
	}
	goto out;

out:
	*sg_size = size;
	*sg_num_elem = num_elem;
	return rc;
}

static int alloc_encrypted_sg(struct sock *sk, int len)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	int rc = 0;

	rc = alloc_sg(sk, len, ctx->sg_encrypted_data,
		      &ctx->sg_encrypted_num_elem, &ctx->sg_encrypted_size, 0);

	return rc;
}

static int alloc_plaintext_sg(struct sock *sk, int len)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	int rc = 0;

	rc = alloc_sg(sk, len, ctx->sg_plaintext_data,
		      &ctx->sg_plaintext_num_elem, &ctx->sg_plaintext_size,
		      tls_ctx->pending_open_record_frags);

	return rc;
}

static void free_sg(struct sock *sk, struct scatterlist *sg,
		    int *sg_num_elem, unsigned int *sg_size)
{
	int i, n = *sg_num_elem;

	for (i = 0; i < n; ++i) {
		sk_mem_uncharge(sk, sg[i].length);
		put_page(sg_page(&sg[i]));
	}
	*sg_num_elem = 0;
	*sg_size = 0;
}

static void tls_free_both_sg(struct sock *sk)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);

	free_sg(sk, ctx->sg_encrypted_data, &ctx->sg_encrypted_num_elem,
		&ctx->sg_encrypted_size);

	free_sg(sk, ctx->sg_plaintext_data, &ctx->sg_plaintext_num_elem,
		&ctx->sg_plaintext_size);
}

static int tls_do_encryption(struct tls_context *tls_ctx,
			     struct tls_sw_context *ctx, size_t data_len,
			     gfp_t flags)
{
	unsigned int req_size = sizeof(struct aead_request) +
		crypto_aead_reqsize(ctx->aead_send);
	struct aead_request *aead_req;
	int rc;

	aead_req = kmalloc(req_size, flags);
	if (!aead_req)
		return -ENOMEM;

	ctx->sg_encrypted_data[0].offset += tls_ctx->tx.prepend_size;
	ctx->sg_encrypted_data[0].length -= tls_ctx->tx.prepend_size;

	aead_request_set_tfm(aead_req, ctx->aead_send);
	aead_request_set_ad(aead_req, TLS_AAD_SPACE_SIZE);
	aead_request_set_crypt(aead_req, ctx->sg_aead_in, ctx->sg_aead_out,
			       data_len, tls_ctx->tx.iv);
	rc = crypto_aead_encrypt(aead_req);

	ctx->sg_encrypted_data[0].offset -= tls_ctx->tx.prepend_size;
	ctx->sg_encrypted_data[0].length += tls_ctx->tx.prepend_size;

	kfree(aead_req);
	return rc;
}

static int tls_push_record(struct sock *sk, int flags,
			   unsigned char record_type)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	int rc;

	sg_mark_end(ctx->sg_plaintext_data + ctx->sg_plaintext_num_elem - 1);
	sg_mark_end(ctx->sg_encrypted_data + ctx->sg_encrypted_num_elem - 1);

	tls_make_aad(0, ctx->aad_space, ctx->sg_plaintext_size,
		     tls_ctx->tx.rec_seq, tls_ctx->tx.rec_seq_size,
		     record_type);

	tls_fill_prepend(tls_ctx,
			 page_address(sg_page(&ctx->sg_encrypted_data[0])) +
			 ctx->sg_encrypted_data[0].offset,
			 ctx->sg_plaintext_size, record_type);

	tls_ctx->pending_open_record_frags = 0;
	set_bit(TLS_PENDING_CLOSED_RECORD, &tls_ctx->flags);

	rc = tls_do_encryption(tls_ctx, ctx, ctx->sg_plaintext_size,
			       sk->sk_allocation);
	if (rc < 0) {
		/* If we are called from write_space and
		 * we fail, we need to set this SOCK_NOSPACE
		 * to trigger another write_space in the future.
		 */
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		return rc;
	}

	free_sg(sk, ctx->sg_plaintext_data, &ctx->sg_plaintext_num_elem,
		&ctx->sg_plaintext_size);

	ctx->sg_encrypted_num_elem = 0;
	ctx->sg_encrypted_size = 0;

	/* Only pass through MSG_DONTWAIT and MSG_NOSIGNAL flags */
	rc = tls_push_sg(sk, tls_ctx, ctx->sg_encrypted_data, 0, flags);
	if (rc < 0 && rc != -EAGAIN)
		tls_err_abort(sk);

	tls_advance_record_sn(sk, &tls_ctx->tx);
	return rc;
}

static int tls_sw_push_pending_record(struct sock *sk, int flags)
{
	return tls_push_record(sk, flags, TLS_RECORD_TYPE_DATA);
}

static int zerocopy_from_iter(struct sock *sk, struct iov_iter *from,
			int length, int *pages_used,
			unsigned int *size_used,
			struct scatterlist *to, int to_max_pages, bool charge)
{
	struct page *pages[MAX_SKB_FRAGS];

	size_t offset;
	ssize_t copied, use;
	int i = 0;
	unsigned int size = *size_used;
	int num_elem = *pages_used;
	int rc = 0;
	int maxpages;

	while (length > 0) {
		i = 0;
		maxpages = to_max_pages - num_elem;
		if (maxpages == 0) {
			rc = -EFAULT;
			goto out;
		}
		copied = iov_iter_get_pages(from, pages,
					    length,
					    maxpages, &offset);
		if (copied <= 0) {
			rc = -EFAULT;
			goto out;
		}

		iov_iter_advance(from, copied);

		length -= copied;
		size += copied;
		while (copied) {
			use = min_t(int, copied, PAGE_SIZE - offset);

			sg_set_page(&to[num_elem],
				    pages[i], use, offset);
			sg_unmark_end(&to[num_elem]);
			if (charge)
				sk_mem_charge(sk, use);

			offset = 0;
			copied -= use;

			++i;
			++num_elem;
		}
	}

out:
	*size_used = size;
	*pages_used = num_elem;

	return rc;
}

static int memcopy_from_iter(struct sock *sk, struct iov_iter *from,
			     int bytes)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	struct scatterlist *sg = ctx->sg_plaintext_data;
	int copy, i, rc = 0;

	for (i = tls_ctx->pending_open_record_frags;
	     i < ctx->sg_plaintext_num_elem; ++i) {
		copy = sg[i].length;
		if (copy_from_iter(
				page_address(sg_page(&sg[i])) + sg[i].offset,
				copy, from) != copy) {
			rc = -EFAULT;
			goto out;
		}
		bytes -= copy;

		++tls_ctx->pending_open_record_frags;

		if (!bytes)
			break;
	}

out:
	return rc;
}

int tls_sw_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	int ret = 0;
	int required_size;
	long timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	bool eor = !(msg->msg_flags & MSG_MORE);
	size_t try_to_copy, copied = 0;
	unsigned char record_type = TLS_RECORD_TYPE_DATA;
	int record_room;
	bool full_record;
	int orig_size;

	if (msg->msg_flags & ~(MSG_MORE | MSG_DONTWAIT | MSG_NOSIGNAL))
		return -ENOTSUPP;

	lock_sock(sk);

	if (tls_complete_pending_work(sk, tls_ctx, msg->msg_flags, &timeo))
		goto send_end;

	if (unlikely(msg->msg_controllen)) {
		ret = tls_proccess_cmsg(sk, msg, &record_type);
		if (ret)
			goto send_end;
	}

	while (msg_data_left(msg)) {
		if (sk->sk_err) {
			ret = sk->sk_err;
			goto send_end;
		}

		orig_size = ctx->sg_plaintext_size;
		full_record = false;
		try_to_copy = msg_data_left(msg);
		record_room = TLS_MAX_PAYLOAD_SIZE - ctx->sg_plaintext_size;
		if (try_to_copy >= record_room) {
			try_to_copy = record_room;
			full_record = true;
		}

		required_size = ctx->sg_plaintext_size + try_to_copy +
				tls_ctx->tx.overhead_size;

		if (!sk_stream_memory_free(sk))
			goto wait_for_sndbuf;
alloc_encrypted:
		ret = alloc_encrypted_sg(sk, required_size);
		if (ret) {
			if (ret != -ENOSPC)
				goto wait_for_memory;

			/* Adjust try_to_copy according to the amount that was
			 * actually allocated. The difference is due
			 * to max sg elements limit
			 */
			try_to_copy -= required_size - ctx->sg_encrypted_size;
			full_record = true;
		}

		if (full_record || eor) {
			ret = zerocopy_from_iter(
				sk, &msg->msg_iter,
				try_to_copy, &ctx->sg_plaintext_num_elem,
				&ctx->sg_plaintext_size,
				ctx->sg_plaintext_data,
				ARRAY_SIZE(ctx->sg_plaintext_data),
				true);
			if (ret)
				goto fallback_to_reg_send;

			copied += try_to_copy;
			ret = tls_push_record(sk, msg->msg_flags, record_type);
			if (!ret)
				continue;
			if (ret == -EAGAIN)
				goto send_end;

			copied -= try_to_copy;
fallback_to_reg_send:
			iov_iter_revert(&msg->msg_iter,
					ctx->sg_plaintext_size - orig_size);
			trim_sg(sk, ctx->sg_plaintext_data,
				&ctx->sg_plaintext_num_elem,
				&ctx->sg_plaintext_size,
				orig_size);
		}

		required_size = ctx->sg_plaintext_size + try_to_copy;
alloc_plaintext:
		ret = alloc_plaintext_sg(sk, required_size);
		if (ret) {
			if (ret != -ENOSPC)
				goto wait_for_memory;

			/* Adjust try_to_copy according to the amount that was
			 * actually allocated. The difference is due
			 * to max sg elements limit
			 */
			try_to_copy -= required_size - ctx->sg_plaintext_size;
			full_record = true;

			trim_sg(sk, ctx->sg_encrypted_data,
				&ctx->sg_encrypted_num_elem,
				&ctx->sg_encrypted_size,
				ctx->sg_plaintext_size +
				tls_ctx->tx.overhead_size);
		}

		ret = memcopy_from_iter(sk, &msg->msg_iter, try_to_copy);
		if (ret)
			goto trim_sgl;

		copied += try_to_copy;
		if (full_record || eor) {
push_record:
			ret = tls_push_record(sk, msg->msg_flags, record_type);
			if (ret) {
				if (ret == -ENOMEM)
					goto wait_for_memory;

				goto send_end;
			}
		}

		continue;

wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		ret = sk_stream_wait_memory(sk, &timeo);
		if (ret) {
trim_sgl:
			trim_both_sgl(sk, orig_size);
			goto send_end;
		}

		if (tls_is_pending_closed_record(tls_ctx))
			goto push_record;

		if (ctx->sg_encrypted_size < required_size)
			goto alloc_encrypted;

		goto alloc_plaintext;
	}

send_end:
	ret = sk_stream_error(sk, msg->msg_flags, ret);

	release_sock(sk);
	return copied ? copied : ret;
}

int tls_sw_sendpage(struct sock *sk, struct page *page,
		    int offset, size_t size, int flags)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	int ret = 0;
	long timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	bool eor;
	size_t orig_size = size;
	unsigned char record_type = TLS_RECORD_TYPE_DATA;
	struct scatterlist *sg;
	bool full_record;
	int record_room;

	if (flags & ~(MSG_MORE | MSG_DONTWAIT | MSG_NOSIGNAL |
		      MSG_SENDPAGE_NOTLAST))
		return -ENOTSUPP;

	/* No MSG_EOR from splice, only look at MSG_MORE */
	eor = !(flags & (MSG_MORE | MSG_SENDPAGE_NOTLAST));

	lock_sock(sk);

	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	if (tls_complete_pending_work(sk, tls_ctx, flags, &timeo))
		goto sendpage_end;

	/* Call the sk_stream functions to manage the sndbuf mem. */
	while (size > 0) {
		size_t copy, required_size;

		if (sk->sk_err) {
			ret = sk->sk_err;
			goto sendpage_end;
		}

		full_record = false;
		record_room = TLS_MAX_PAYLOAD_SIZE - ctx->sg_plaintext_size;
		copy = size;
		if (copy >= record_room) {
			copy = record_room;
			full_record = true;
		}
		required_size = ctx->sg_plaintext_size + copy +
			      tls_ctx->tx.overhead_size;

		if (!sk_stream_memory_free(sk))
			goto wait_for_sndbuf;
alloc_payload:
		ret = alloc_encrypted_sg(sk, required_size);
		if (ret) {
			if (ret != -ENOSPC)
				goto wait_for_memory;

			/* Adjust copy according to the amount that was
			 * actually allocated. The difference is due
			 * to max sg elements limit
			 */
			copy -= required_size - ctx->sg_plaintext_size;
			full_record = true;
		}

		get_page(page);
		sg = ctx->sg_plaintext_data + ctx->sg_plaintext_num_elem;
		sg_set_page(sg, page, copy, offset);
		sg_unmark_end(sg);

		ctx->sg_plaintext_num_elem++;

		sk_mem_charge(sk, copy);
		offset += copy;
		size -= copy;
		ctx->sg_plaintext_size += copy;
		tls_ctx->pending_open_record_frags = ctx->sg_plaintext_num_elem;

		if (full_record || eor ||
		    ctx->sg_plaintext_num_elem ==
		    ARRAY_SIZE(ctx->sg_plaintext_data)) {
push_record:
			ret = tls_push_record(sk, flags, record_type);
			if (ret) {
				if (ret == -ENOMEM)
					goto wait_for_memory;

				goto sendpage_end;
			}
		}
		continue;
wait_for_sndbuf:
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
		ret = sk_stream_wait_memory(sk, &timeo);
		if (ret) {
			trim_both_sgl(sk, ctx->sg_plaintext_size);
			goto sendpage_end;
		}

		if (tls_is_pending_closed_record(tls_ctx))
			goto push_record;

		goto alloc_payload;
	}

sendpage_end:
	if (orig_size > size)
		ret = orig_size - size;
	else
		ret = sk_stream_error(sk, flags, ret);

	release_sock(sk);
	return ret;
}

static struct sk_buff *tls_wait_data(struct sock *sk, int flags,
				     long timeo, int *err)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	struct sk_buff *skb;
	DEFINE_WAIT_FUNC(wait, woken_wake_function);

	while (!(skb = ctx->recv_pkt)) {
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

		sk_wait_data(sk, &timeo, NULL);

		add_wait_queue(sk_sleep(sk), &wait);
		sk_set_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		sk_wait_event(sk, &timeo, ctx->recv_pkt != skb, &wait);
		sk_clear_bit(SOCKWQ_ASYNC_WAITDATA, sk);
		remove_wait_queue(sk_sleep(sk), &wait);

		/* Handle signals */
		if (signal_pending(current)) {
			*err = sock_intr_errno(timeo);
			return NULL;
		}
	}

	return skb;
}

static int decrypt_skb(struct sock *sk, struct sk_buff *skb,
		struct scatterlist *sgout)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	int ret, nsg;
	size_t prepend, overhead;
	struct strp_rx_msg *rxm;
	char iv[TLS_CIPHER_AES_GCM_128_SALT_SIZE + tls_ctx->rx.iv_size];
	char type;

	memset(iv, 0, sizeof(iv));
	prepend = tls_ctx->rx.prepend_size;
	overhead = tls_ctx->rx.overhead_size;
	rxm = strp_rx_msg(skb);

	ret = skb_copy_bits(skb, rxm->offset, &type, 1);
	if (ret < 0)
		goto decryption_fail;
	ret = skb_copy_bits(skb, rxm->offset + TLS_HEADER_SIZE,
			iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
		tls_ctx->rx.iv_size);
	memcpy(iv, tls_ctx->rx.iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);

	if (ret < 0)
		goto decryption_fail;

	sg_init_table(ctx->sgin, ARRAY_SIZE(ctx->sgin));
	sg_set_buf(&ctx->sgin[0], ctx->aad_recv, sizeof(ctx->aad_recv));

	nsg = skb_to_sgvec(skb, &ctx->sgin[1], rxm->offset +
			prepend,
			rxm->full_len - prepend);

	/* The length of sg into decryption must not be over
	 * ALG_MAX_PAGES. The aad takes the first sg, so the payload

	 * must be less than ALG_MAX_PAGES - 1
	 */
	if (nsg > MAX_SKB_FRAGS - 1) {
		ret = -EBADMSG;
		goto decryption_fail;
	}

	tls_make_aad(1, ctx->aad_recv,
		     rxm->full_len - overhead,
		     tls_ctx->rx.rec_seq,
		     tls_ctx->rx.rec_seq_size,
		     type);

	/* Decrypt in place.  After this function call, the decrypted
	 * data will be in rxm->offset. We must therefore account for
	 * the fact that the lengths of skbuff_in and skbuff_out are
	 * different
	 */
	if (!sgout)
		sgout = ctx->sgin;

	ret = tls_do_decryption(sk,
				ctx->sgin,
				sgout,
				iv,
				rxm->full_len - overhead,
				skb,
		                sk->sk_allocation);

decryption_fail:
	return ret;
}

int tls_sw_read_sock(struct sock *sk, read_descriptor_t *desc,
			 sk_read_actor_t recv_actor) {
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	struct strp_rx_msg *rxm;
	struct sk_buff *skb = NULL;
	int err = 0;
	int used;
	int copied = 0;

	printk("tls_read_sock\n");

	while ((skb = tls_wait_data(sk, MSG_DONTWAIT, 0, &err)) != NULL) {
		rxm = strp_rx_msg(skb);
		printk("Got skb %p %p\n", skb, rxm);

		if (!tls_rx_msg(skb)->decrypted) {
			printk("decrypting\n");
			err = decrypt_skb(sk, skb, NULL);
			printk("err is %i\n", err);
			if (err == -EINPROGRESS) {
				// TODO must install callback
				err = 0;
				skb = NULL;
				goto recv_end;
			}
			if (err < 0) {
				tls_err_abort(sk);
				goto recv_end;
			}
		}
		printk("with data %i\n", rxm->full_len);
		used = recv_actor(desc, skb, 0, rxm->full_len);
		printk("Used %i\n", used);
		copied += used;

		if (used < rxm->full_len) {
			printk("didn't use full\n");
			rxm->full_len -= used;
			rxm->offset += used;
			break;
		}

		printk("Used full, free skb\n");
		ctx->recv_pkt = NULL;
		kfree_skb(skb);
		strp_unpause(&ctx->strp);
		if (!desc->count)
			break;
	}

recv_end:
	if (!skb)
		err = 0;
	printk("Returning from tls_read_sock %i\n", err ?: copied);
	return err ?: copied;
}

int tls_sw_peek_len(struct socket *sock)
{
	struct tls_context *tls_ctx = tls_get_ctx(sock->sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	struct strp_rx_msg *rxm;

	if (!ctx->recv_pkt) {
		printk("tls_peek_len 0\n");
		return 0;
	}

	rxm = strp_rx_msg(ctx->recv_pkt);
	printk("tls_peek_len %i\n", rxm->full_len);
	return rxm->full_len;
}

int tls_sw_recvmsg(struct sock *sk,
		   struct msghdr *msg,
		   size_t len,
		   int nonblock,
		   int flags,
		   int *addr_len)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	ssize_t copied = 0;
	int err = 0;
	long timeo;
	struct strp_rx_msg *rxm;
	int ret = 0;
	struct sk_buff *skb;

	flags |= nonblock;

	lock_sock(sk);

	err = -sk->sk_err;
	if (err)
		goto recv_end;

	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
	do {
		int chunk = 0;
		bool zc = false;

		skb = tls_wait_data(sk, flags, timeo, &err);
		if (!skb)
			goto recv_end;

		rxm = strp_rx_msg(skb);
		/* It is possible that the message is already
		 * decrypted if the last call only read part of the
		 * message
		 */
		if (!tls_rx_msg(skb)->decrypted) {
			int page_count = iov_iter_npages(
				&msg->msg_iter, MAX_SKB_FRAGS);
			int to_copy = rxm->full_len -
				tls_ctx->rx.overhead_size;
			if (to_copy <= len &&
			    page_count < MAX_SKB_FRAGS &&
			    likely(!(flags & MSG_PEEK)))  {
				struct scatterlist sgin[MAX_SKB_FRAGS + 1];
				char unused[21];
				int pages = 0;

				zc = true;
				sg_init_table(sgin, MAX_SKB_FRAGS + 1);
				sg_set_buf(&sgin[0], unused, 13);

				err = zerocopy_from_iter(
					sk, &msg->msg_iter, to_copy,
					&pages, &chunk, &sgin[1], MAX_SKB_FRAGS,
					false);
				if (err < 0)
					goto recv_end;

				err = decrypt_skb(sk, skb, sgin);
				for (; pages > 0; pages--)
					put_page(sg_page(&sgin[pages]));
				if (err < 0) {
					tls_err_abort(sk);
					goto recv_end;
				}
			} else {
				err = decrypt_skb(sk, skb, NULL);
				if (err < 0) {
					tls_err_abort(sk);
					goto recv_end;
				}
			}
			tls_rx_msg(skb)->decrypted = 1;
		}

		if (!zc) {
			chunk = min_t(unsigned int, rxm->full_len, len);
			err = skb_copy_datagram_msg(
				skb, rxm->offset, msg, chunk);
			if (err < 0)
				goto recv_end;
		}
		copied += chunk;
		len -= chunk;
		if (likely(!(flags & MSG_PEEK))) {
			ctx->recv_len -= chunk;
			if (chunk < rxm->full_len) {
				rxm->offset += chunk;
				rxm->full_len -= chunk;
			} else {
				/* Finished with message */
				ctx->recv_pkt = NULL;
				kfree_skb(skb);
				strp_unpause(&ctx->strp);
			}
		}
	} while (len);

recv_end:
	release_sock(sk);
	ret = copied ? : err;

	return ret;
}

ssize_t tls_sw_splice_read(struct socket *sock,  loff_t *ppos,
			       struct pipe_inode_info *pipe,
			       size_t len, unsigned int flags)
{
	struct sock *sk = sock->sk;
	ssize_t copied = 0;
	long timeo;
	struct strp_rx_msg *rxm;
	int ret = 0;
	struct sk_buff *skb;
	int chunk;
	int err = 0;

	lock_sock(sk);

	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);

again:
	skb = tls_wait_data(sk, flags, timeo, &err);
	if (!skb)
		goto splice_read_end;

	rxm = strp_rx_msg(skb);
	/* It is possible that the message is already decrypted if the
	 * last call only read part of the message
	 */
	if (!tls_rx_msg(skb)->decrypted) {
		err = decrypt_skb(sk, skb, NULL);
		if (err == -EINPROGRESS)
			goto again;

		if (err < 0) {
			tls_err_abort(sk);
			goto splice_read_end;
		}
		tls_rx_msg(skb)->decrypted = 1;
	}
	chunk = min_t(unsigned int, rxm->full_len, len);
	copied = skb_splice_bits(skb, sk, rxm->offset, pipe, chunk, flags);
	if (ret < 0)
		goto splice_read_end;

	rxm->offset += copied;
	rxm->full_len -= copied;

splice_read_end:
	release_sock(sk);
	ret = (copied) ? copied : err;
	return ret;
}

unsigned int tls_sw_poll(struct file *file, struct socket *sock,
			     struct poll_table_struct *wait)
{
	unsigned int ret;
	struct sock *sk = sock->sk;
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);

	/* Call POLL on the underlying socket, which will call
	 * sock_poll_wait on tcp socket. Used for POLLOUT and
	 * POLLHUP
	 */
	ret = ctx->sk_poll(file, sock, wait);

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
	if (ctx->recv_pkt)
		ret |= POLLIN | POLLRDNORM;

	return ret;
}

/* Returns the length of the unencrypted message, plus overhead Note
 * that this function also populates tsk->header which is later used
 * for decryption. In TLS we automatically bail if we see a non-TLS
 * message.
 */
static inline ssize_t tls_read_size(struct sock *sk, struct sk_buff *skb)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	struct strp_rx_msg *rxm;
	size_t data_len = 0;
	size_t datagram_len;
	size_t prepend;
	char first_byte;
	char header[tls_ctx->rx.prepend_size];
	int ret;

	prepend = tls_ctx->rx.prepend_size;

	rxm = strp_rx_msg(skb);

	ret = skb_copy_bits(skb, rxm->offset, &first_byte, 1);
	if (ret < 0)
		goto read_failure;

	/* Check the first byte to see if its a TLS record */
	if (first_byte != TLS_RECORD_TYPE_DATA)
		ctx->control = 1;
	else
		ctx->control = 0;

	/* We have a TLS record. Check that msglen is long enough to
	 * read the length of record.  We must not check this before
	 * checking the first byte, since that will cause unencrypted
	 * messages shorter than TLS_PREPEND_SIZE to not be read
	 */
	if (rxm->offset + prepend > skb->len) {
		ret = 0;
		goto read_failure;
	}

	/* Copy header to read size.  An optimization could be to
	 * zero-copy, but you'd have to be able to walk
	 * frag_lists. This function call takes care of that.
	 * Overhead is relatively small (13 bytes for TLS)
	 */
	ret = skb_copy_bits(skb, rxm->offset, header, prepend);

	if (ret < 0)
		goto read_failure;

	data_len = ((header[4] & 0xFF) | (header[3] << 8));
	data_len = data_len - tls_ctx->rx.tag_size - tls_ctx->rx.iv_size;
	datagram_len = data_len + tls_ctx->rx.overhead_size;

	if (data_len > TLS_MAX_PAYLOAD_SIZE) {
		ret = -E2BIG;
		goto read_failure;
	}
	if (ctx->control) // TODO support cmsg on receive path
		return -EBADMSG;

	return datagram_len;

read_failure:
	/* TLS couldn't handle this message. */
	if (ret == -EBADMSG)
		tls_err_abort(sk);

	return ret;
}

static int tls_parse_cb(struct strparser *strp, struct sk_buff *skb)
{
	return tls_read_size(strp->sk, skb);
}

static void tls_abort_cb(struct strparser *strp, int err)
{
	tls_err_abort(strp->sk);
}

static void tls_queue(struct strparser *strp, struct sk_buff *skb)
{
	struct tls_context *tls_ctx = tls_get_ctx(strp->sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);
	struct strp_rx_msg *rxm;

	rxm = strp_rx_msg(skb);

	tls_rx_msg(skb)->decrypted = 0;

	ctx->recv_len += rxm->full_len - tls_ctx->rx.overhead_size;
	ctx->recv_pkt = skb;
	strp_pause(strp);

	strp->sk->sk_state_change(strp->sk);
}

/* Called with lower socket held */
static void tls_data_ready(struct sock *sk)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);

	strp_data_ready(&ctx->strp);
}

void tls_sw_free_resources(struct sock *sk)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context *ctx = tls_sw_ctx(tls_ctx);

	if (ctx->aead_send)
		crypto_free_aead(ctx->aead_send);
	if (ctx->aead_recv) {
		if (ctx->recv_pkt) {
			kfree_skb(ctx->recv_pkt);
			ctx->recv_pkt = NULL;
		}
		crypto_free_aead(ctx->aead_recv);
		strp_stop(&ctx->strp);
		write_lock_bh(&sk->sk_callback_lock);
		sk->sk_data_ready = ctx->saved_data_ready;
		write_unlock_bh(&sk->sk_callback_lock);
		release_sock(sk);
		strp_done(&ctx->strp);
		lock_sock(sk);
	}

	tls_free_both_sg(sk);

	kfree(ctx);
}

int tls_set_sw_offload_tx(struct sock *sk, struct tls_context *ctx)
{
	char keyval[TLS_CIPHER_AES_GCM_128_KEY_SIZE];
	struct tls_crypto_info *crypto_info;
	struct tls12_crypto_info_aes_gcm_128 *gcm_128_info;
	struct tls_sw_context *sw_ctx;
	u16 nonce_size, tag_size, iv_size, rec_seq_size;
	char *iv, *rec_seq;
	int rc = 0;

	if (!ctx) {
		rc = -EINVAL;
		goto out;
	}

	if (ctx->priv_ctx) {
		rc = -EEXIST;
		goto out;
	}

	sw_ctx = kzalloc(sizeof(*sw_ctx), GFP_KERNEL);
	if (!sw_ctx) {
		rc = -ENOMEM;
		goto out;
	}

	ctx->priv_ctx = (struct tls_offload_context *)sw_ctx;
	ctx->free_resources = tls_sw_free_resources;

	crypto_info = &ctx->crypto_send;
	switch (crypto_info->cipher_type) {
	case TLS_CIPHER_AES_GCM_128: {
		nonce_size = TLS_CIPHER_AES_GCM_128_IV_SIZE;
		tag_size = TLS_CIPHER_AES_GCM_128_TAG_SIZE;
		iv_size = TLS_CIPHER_AES_GCM_128_IV_SIZE;
		iv = ((struct tls12_crypto_info_aes_gcm_128 *)crypto_info)->iv;
		rec_seq_size = TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE;
		rec_seq =
		 ((struct tls12_crypto_info_aes_gcm_128 *)crypto_info)->rec_seq;
		gcm_128_info =
			(struct tls12_crypto_info_aes_gcm_128 *)crypto_info;
		break;
	}
	default:
		rc = -EINVAL;
		goto out;
	}

	ctx->tx.prepend_size = TLS_HEADER_SIZE + nonce_size;
	ctx->tx.tag_size = tag_size;
	ctx->tx.overhead_size = ctx->tx.prepend_size + ctx->tx.tag_size;
	ctx->tx.iv_size = iv_size;
	ctx->tx.iv = kmalloc(iv_size + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
			  GFP_KERNEL);
	if (!ctx->tx.iv) {
		rc = -ENOMEM;
		goto out;
	}
	memcpy(ctx->tx.iv, gcm_128_info->salt, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	memcpy(ctx->tx.iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE, iv, iv_size);
	ctx->tx.rec_seq_size = rec_seq_size;
	ctx->tx.rec_seq = kmalloc(rec_seq_size, GFP_KERNEL);
	if (!ctx->tx.rec_seq) {
		rc = -ENOMEM;
		goto free_iv;
	}
	memcpy(ctx->tx.rec_seq, rec_seq, rec_seq_size);

	sg_init_table(sw_ctx->sg_encrypted_data,
		      ARRAY_SIZE(sw_ctx->sg_encrypted_data));
	sg_init_table(sw_ctx->sg_plaintext_data,
		      ARRAY_SIZE(sw_ctx->sg_plaintext_data));

	sg_init_table(sw_ctx->sg_aead_in, 2);
	sg_set_buf(&sw_ctx->sg_aead_in[0], sw_ctx->aad_space,
		   sizeof(sw_ctx->aad_space));
	sg_unmark_end(&sw_ctx->sg_aead_in[1]);
	sg_chain(sw_ctx->sg_aead_in, 2, sw_ctx->sg_plaintext_data);
	sg_init_table(sw_ctx->sg_aead_out, 2);
	sg_set_buf(&sw_ctx->sg_aead_out[0], sw_ctx->aad_space,
		   sizeof(sw_ctx->aad_space));
	sg_unmark_end(&sw_ctx->sg_aead_out[1]);
	sg_chain(sw_ctx->sg_aead_out, 2, sw_ctx->sg_encrypted_data);

	if (!sw_ctx->aead_send) {
		sw_ctx->aead_send = crypto_alloc_aead("gcm(aes)", 0, 0);
		if (IS_ERR(sw_ctx->aead_send)) {
			rc = PTR_ERR(sw_ctx->aead_send);
			sw_ctx->aead_send = NULL;
			goto free_rec_seq;
		}
	}

	ctx->push_pending_record = tls_sw_push_pending_record;

	memcpy(keyval, gcm_128_info->key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);

	rc = crypto_aead_setkey(sw_ctx->aead_send, keyval,
				TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	if (rc)
		goto free_aead;

	rc = crypto_aead_setauthsize(sw_ctx->aead_send, ctx->tx.tag_size);
	if (!rc)
		goto out;

free_aead:
	crypto_free_aead(sw_ctx->aead_send);
	sw_ctx->aead_send = NULL;
free_rec_seq:
	kfree(ctx->tx.rec_seq);
	ctx->tx.rec_seq = NULL;
free_iv:
	kfree(ctx->tx.iv);
	ctx->tx.iv = NULL;
out:
	return rc;
}

int tls_set_sw_offload_rx(struct sock *sk, struct tls_context *ctx)
{
	char keyval[TLS_CIPHER_AES_GCM_128_KEY_SIZE];
	struct tls12_crypto_info_aes_gcm_128 *gcm_128_info;
	u16 nonce_size, tag_size, iv_size, rec_seq_size;
	struct tls_crypto_info *crypto_info;
	struct tls_sw_context *sw_ctx = NULL;
	struct strp_callbacks cb;
	char *iv, *rec_seq;
	int rc = 0;

	if (!ctx) {
		rc = -EINVAL;
		goto out;
	}

	if (!ctx->priv_ctx) {
		sw_ctx = kzalloc(sizeof(*sw_ctx), GFP_KERNEL);
		if (!sw_ctx) {
			rc = -ENOMEM;
			goto out;
		}
	} else {
		sw_ctx = ctx->priv_ctx;
	}

	ctx->priv_ctx = (struct tls_offload_context *)sw_ctx;
	ctx->free_resources = tls_sw_free_resources;

	crypto_info = &ctx->crypto_recv;

	switch (crypto_info->cipher_type) {
	case TLS_CIPHER_AES_GCM_128: {
		nonce_size = TLS_CIPHER_AES_GCM_128_IV_SIZE;
		tag_size = TLS_CIPHER_AES_GCM_128_TAG_SIZE;
		iv_size = TLS_CIPHER_AES_GCM_128_IV_SIZE;
		iv = ((struct tls12_crypto_info_aes_gcm_128 *)crypto_info)->iv;
		rec_seq_size = TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE;
		rec_seq =
		 ((struct tls12_crypto_info_aes_gcm_128 *)crypto_info)->rec_seq;
		gcm_128_info =
			(struct tls12_crypto_info_aes_gcm_128 *)crypto_info;
		break;
	}
	default:
		rc = -EINVAL;
		goto out;
	}

	ctx->rx.prepend_size = TLS_HEADER_SIZE + nonce_size;
	ctx->rx.tag_size = tag_size;
	ctx->rx.overhead_size = ctx->rx.prepend_size + ctx->rx.tag_size;
	ctx->rx.iv_size = iv_size;
	ctx->rx.iv = kmalloc(iv_size + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
			  GFP_KERNEL);
	if (!ctx->rx.iv) {
		rc = -ENOMEM;
		goto out;
	}
	memcpy(ctx->rx.iv, gcm_128_info->salt,
	       TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	memcpy(ctx->rx.iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE, iv, iv_size);
	ctx->rx.rec_seq_size = rec_seq_size;
	ctx->rx.rec_seq = kmalloc(rec_seq_size, GFP_KERNEL);
	if (!ctx->rx.rec_seq) {
		rc = -ENOMEM;
		goto free_iv;
	}
	memcpy(ctx->rx.rec_seq, rec_seq, rec_seq_size);

	if (!sw_ctx->aead_recv) {
		sw_ctx->aead_recv = crypto_alloc_aead("gcm(aes)", 0, 0);
		if (IS_ERR(sw_ctx->aead_recv)) {
			rc = PTR_ERR(sw_ctx->aead_recv);
			sw_ctx->aead_recv = NULL;
			goto free_rec_seq;
		}
	}

	memcpy(keyval, gcm_128_info->key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);

	rc = crypto_aead_setkey(sw_ctx->aead_recv, keyval,
				TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	if (rc)
		goto free_aead;

	rc = crypto_aead_setauthsize(sw_ctx->aead_recv, ctx->rx.tag_size);
	if (rc)
		goto out;

	// Set up strparser
	cb.rcv_msg = tls_queue;
	cb.abort_parser = tls_abort_cb;
	cb.parse_msg = tls_parse_cb;
	cb.read_sock_done = NULL;
	cb.read_sock = sk->sk_socket->ops->read_sock;

	strp_init(&sw_ctx->strp, sk, &cb);

	write_lock_bh(&sk->sk_callback_lock);
	sw_ctx->saved_data_ready = sk->sk_data_ready;
	sk->sk_data_ready = tls_data_ready;
	write_unlock_bh(&sk->sk_callback_lock);

	sw_ctx->sk_poll = sk->sk_socket->ops->poll;
	sw_ctx->sk_read_sock = sk->sk_socket->ops->read_sock;

	strp_check_rcv(&sw_ctx->strp);

	goto out;
free_aead:
	crypto_free_aead(sw_ctx->aead_recv);
	sw_ctx->aead_recv = NULL;
free_rec_seq:
	kfree(ctx->rx.rec_seq);
	ctx->rx.rec_seq = NULL;
free_iv:
	kfree(ctx->rx.iv);
	ctx->rx.iv = NULL;
out:
	return rc;
}
