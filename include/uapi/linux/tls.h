
#ifndef _UAPI_LINUX_TLS_H
#define _UAPI_LINUX_TLS_H

#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/socket.h>
#include <linux/tcp.h>

/* Supported versions */
#define TLS_VERSION_MINOR(ver) ((ver) & 0xFF)
#define TLS_VERSION_MAJOR(ver) (((ver) >> 8) & 0xFF)

#define TLS_VERSION_NUMBER(id) ((((id##_VERSION_MAJOR) & 0xFF) << 8) |	\
					((id##_VERSION_MINOR) & 0xFF))

#define TLS_1_2_VERSION_MAJOR  0x3
#define TLS_1_2_VERSION_MINOR  0x3
#define TLS_1_2_VERSION                TLS_VERSION_NUMBER(TLS_1_2)

/* Supported ciphers */
#define TLS_CIPHER_AES_GCM_128                 51
#define TLS_CIPHER_AES_GCM_128_IV_SIZE         ((size_t)8)
#define TLS_CIPHER_AES_GCM_128_KEY_SIZE                ((size_t)16)
#define TLS_CIPHER_AES_GCM_128_SALT_SIZE       ((size_t)4)
#define TLS_CIPHER_AES_GCM_128_TAG_SIZE                ((size_t)16)

struct tls_ctrlmsg {
	unsigned char type;
	unsigned char data[0];
} __attribute__((packed));

enum tls_state {
	TLS_STATE_SW = 0x0,
	TLS_STATE_HW = 0x1,
};

struct tls_crypto_info {
	__u16 version;
	__u16 cipher_type;
	__u32 state;
};

struct tls_crypto_info_aes_gcm_128 {
	struct tls_crypto_info info;
	unsigned char iv[TLS_CIPHER_AES_GCM_128_IV_SIZE];
	unsigned char key[TLS_CIPHER_AES_GCM_128_KEY_SIZE];
	unsigned char salt[TLS_CIPHER_AES_GCM_128_SALT_SIZE];
};

#endif /* _UAPI_LINUX_TLS_H */
