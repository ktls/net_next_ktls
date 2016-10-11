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

#ifndef TLS_KERNEL_H
#define TLS_KERNEL_H

#include <linux/types.h>

/* getsockopt() optnames */
#define TLS_SET_IV_RECV		        1
#define TLS_SET_KEY_RECV		2
#define TLS_SET_SALT_RECV		3
#define TLS_SET_IV_SEND		        4
#define TLS_SET_KEY_SEND		5
#define TLS_SET_SALT_SEND		6
#define TLS_SET_MTU			7
#define TLS_UNATTACH			8

/* setsockopt() optnames */
#define TLS_GET_IV_RECV		        11
#define TLS_GET_KEY_RECV		12
#define TLS_GET_SALT_RECV		13
#define TLS_GET_IV_SEND		        14
#define TLS_GET_KEY_SEND		15
#define TLS_GET_SALT_SEND		16
#define TLS_GET_MTU			17

/* Supported ciphers */
#define TLS_CIPHER_AES_GCM_128		51

#define TLS_VERSION_LATEST		0
#define TLS_VERSION_1_2		        1

struct sockaddr_tls {
	__u16   sa_cipher;
	__u16   sa_socket;
	__u16   sa_version;
};


#endif
