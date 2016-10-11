/*
 * af_tls: TLS/DTLS socket
 *
 * Copyright (C) 2016
 *
 * Original authors:
 *   Fridolin Pokorny <fpokorny@redhat.com>
 *   Nikos Mavrogiannopoulos <nmav@redhat.com>
 *   Dave Watson <davejwatson@fb.com>
 *   Lance Chao <lancerchao@fb.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#ifndef __NET_TLS_H_
#define __NET_TLS_H_

#include <linux/types.h>
#include <uapi/linux/tls.h>

/* Constants */
#define TLS_AES_GCM_128_IV_SIZE	((size_t)8)
#define TLS_AES_GCM_128_KEY_SIZE	((size_t)16)
#define TLS_AES_GCM_128_SALT_SIZE	((size_t)4)

/* Maximum data size carried in a TLS/DTLS record */
#define TLS_MAX_PAYLOAD_SIZE		((size_t)1 << 14)

#include <linux/types.h>
#ifndef CHAR_BIT
# define CHAR_BIT   8
#endif
#define MAX(a, b)			((a) > (b) ? (a) : (b))

#define TLS_RECORD_DATA		0x17

#define TLS_KEY_SIZE			TLS_AES_GCM_128_KEY_SIZE
#define TLS_SALT_SIZE			TLS_AES_GCM_128_SALT_SIZE
#define TLS_TAG_SIZE			16
#define TLS_IV_SIZE			TLS_AES_GCM_128_IV_SIZE
#define TLS_NONCE_SIZE			8

#define TLS_DATA_PAGES			(TLS_MAX_PAYLOAD_SIZE / PAGE_SIZE)
/* +1 for aad, +1 for tag, +1 for chaining */
#define TLS_SG_DATA_SIZE		(TLS_DATA_PAGES + 3)

#define TLS_AAD_SPACE_SIZE		21
#define TLS_AAD_SIZE			13

/* TLS
 */
#define TLS_TLS_HEADER_SIZE		5
#define TLS_TLS_PREPEND_SIZE		(TLS_TLS_HEADER_SIZE + TLS_NONCE_SIZE)
#define TLS_TLS_OVERHEAD		(TLS_TLS_PREPEND_SIZE + TLS_TAG_SIZE)

#define TLS_TLS_1_2_MAJOR		0x03
#define TLS_TLS_1_2_MINOR		0x03

/* nonce explicit offset in a record */
#define TLS_TLS_NONCE_OFFSET		TLS_TLS_HEADER_SIZE

#define TLS_PREPEND_SIZE(T)          (IS_TLS(T) ?			\
					(TLS_TLS_PREPEND_SIZE) :	\
					(TLS_DTLS_PREPEND_SIZE))

#define TLS_HEADER_SIZE(T)           (IS_TLS(T) ?			\
					(TLS_TLS_HEADER_SIZE) :	\
					(TLS_DTLS_HEADER_SIZE))

#define TLS_OVERHEAD(T)              (IS_TLS(T) ?		\
					(TLS_TLS_OVERHEAD) :	\
					(TLS_DTLS_OVERHEAD))

/* DTLS
 */
#define TLS_DTLS_HEADER_SIZE		13
#define TLS_DTLS_PREPEND_SIZE		(TLS_DTLS_HEADER_SIZE \
						+ TLS_NONCE_SIZE)
#define TLS_DTLS_OVERHEAD		(TLS_DTLS_PREPEND_SIZE \
						+ TLS_TAG_SIZE)

#define TLS_DTLS_1_2_MAJOR		0xFE
#define TLS_DTLS_1_2_MINOR		0xFD

/* we are handling epoch and seq num as one unit */
#define TLS_DTLS_SEQ_NUM_OFFSET	3
/* nonce explicit offset in a record */
#define TLS_DTLS_NONCE_OFFSET		TLS_DTLS_HEADER_SIZE

/* Ensure that bind(2) was called
 */
#define TLS_SETSOCKOPT_READY(T)	((T)->aead_send && (T)->aead_recv)
#define TLS_GETSOCKOPT_READY(T)	TLS_SETSOCKOPT_READY(T)

/* Ensure that we have needed key material
 */
#define TLS_SEND_READY(T)		((T)->key_send.keylen && \
						(T)->key_send.saltlen && \
						(T)->iv_send && \
						TLS_GETSOCKOPT_READY(T))
#define TLS_RECV_READY(T)		((T)->key_recv.keylen && \
						(T)->key_recv.saltlen && \
						(T)->iv_recv && \
						TLS_GETSOCKOPT_READY(T))

#define IS_TLS(T)			((T)->sk.sk_type == SOCK_STREAM)
#define IS_DTLS(T)			(!IS_TLS(T))

/* Distinguish bound socket type
 */
#define IS_INET46(S)			((S)->sk->sk_family == AF_INET || \
						(S)->sk->sk_family == AF_INET6)
#define IS_TCP(S)			(IS_INET46(S) && \
						(S)->sk->sk_type == SOCK_STREAM)
#define IS_UDP(S)			(IS_INET46(S) && \
						(S)->sk->sk_type == SOCK_DGRAM)

/* Real size of a record based on data carried
 */
#define TLS_RECORD_SIZE(T, S)		(IS_TLS(T) ? \
						(S + TLS_TLS_OVERHEAD) : \
						(S + TLS_DTLS_OVERHEAD))

/* Nonce explicit offset in a record
 */
#define TLS_NONCE_OFFSET(T)		(IS_TLS(T) ? \
						(TLS_TLS_NONCE_OFFSET) : \
						(TLS_DTLS_NONCE_OFFSET))

struct tls_key {
	char *key;
	size_t keylen;
	char salt[TLS_SALT_SIZE];
	size_t saltlen;
};

struct tls_sock {
	/* struct sock must be the very first member */
	struct sock sk;

	/* TCP/UDP socket we are bound to */
	struct socket *socket;

	int rx_stopped;
	int tx_stopped;

	int async_decrypt;
	int async_encrypt;

	/* Context for {set,get}sockopt() */
	unsigned char *iv_send;
	struct tls_key key_send;

	unsigned char *iv_recv;
	struct tls_key key_recv;

	struct crypto_aead *aead_send;
	struct crypto_aead *aead_recv;

	/* Sending context */
	struct scatterlist sg_tx_data[TLS_SG_DATA_SIZE];
	struct scatterlist sg_tx_data2[ALG_MAX_PAGES + 1];
	char aad_send[TLS_AAD_SPACE_SIZE];
	char tag_send[TLS_TAG_SIZE];
	struct page *pages_send;
	int send_offset;
	int send_len;
	int order_npages;
	struct scatterlist sgaad_send[2];
	struct scatterlist sgtag_send[2];
	struct work_struct send_work;

	/* Receive */
	struct scatterlist sgin[ALG_MAX_PAGES + 1];
	char aad_recv[TLS_AAD_SPACE_SIZE];
	char header_recv[MAX(TLS_TLS_PREPEND_SIZE, TLS_DTLS_PREPEND_SIZE)];
	char header_recv2[MAX(TLS_TLS_PREPEND_SIZE, TLS_DTLS_PREPEND_SIZE)];

	struct strparser strp;
	struct sk_buff_head rx_hold_queue;
	struct work_struct recv_work;
	void (*saved_sk_data_ready)(struct sock *sk);
	void (*saved_sk_write_space)(struct sock *sk);
	size_t recv_len;

	/* our cipher type and its crypto API representation (e.g. "gcm(aes)")
	 */
	unsigned int cipher_type;
	char *cipher_crypto;

	/* TLS/DTLS version for header */
	char version[2];

	/* DTLS window handling */
	struct {
		u64 bits;
		/* The end point (next expected packet) of the sliding
		   window without epoch */
		u64 next;
		bool have_recv;
	} dtls_window;

	int unsent;
};

#endif
