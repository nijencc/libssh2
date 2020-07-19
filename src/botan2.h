#ifndef __LIBSSH2_BOTAN2_H
#define __LIBSSH2_BOTAN2_H
/* Copyright (C) 2021 Nils Jenniches
 *
 * Author: Nils Jenniches
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */
#include <botan/ffi.h>

/// Check availability of certain features
#ifdef BOTAN_HAS_RSA
# define LIBSSH2_RSA 1
#else
# define LIBSSH2_RSA 0
#endif

#ifdef BOTAN_HAS_DSA
# define LIBSSH2_DSA 1
#else
# define LIBSSH2_DSA 0
#endif

#ifdef BOTAN_HAS_ECDSA
# define LIBSSH2_ECDSA 1
#else
# define LIBSSH2_ECDSA 0
#endif

#ifdef BOTAN_HAS_ED25519
# define LIBSSH2_ED25519 1
#else
# define LIBSSH2_ED25519 0
#endif

#ifdef BOTAN_HAS_MD5
# define LIBSSH2_MD5 1
#else
# define LIBSSH2_MD5 0
#endif

#ifdef BOTAN_HAS_RIPEMD_160
# define LIBSSH2_HMAC_RIPEMD 1
#else
# define LIBSSH2_HMAC_RIPEMD 0
#endif

#if defined(BOTAN_HAS_HMAC) && \
    defined(BOTAN_HAS_SHA2_32)
# define LIBSSH2_HMAC_SHA256 1
#else
# define LIBSSH2_HMAC_SHA256 0
#endif

#if defined(BOTAN_HAS_HMAC) && \
    defined(BOTAN_HAS_SHA2_64)
# define LIBSSH2_HMAC_SHA512 1
#else
# define LIBSSH2_HMAC_SHA512 0
#endif

#ifdef BOTAN_HAS_AES
# ifdef BOTAN_HAS_CTR_BE
#  define LIBSSH2_AES_CTR 1
# else
#  define LIBSSH2_AES_CTR 0
# endif
# define LIBSSH2_AES 1
#else
# define LIBSSH2_AES_CTR 0
# define LIBSSH2_AES 0
#endif

#ifdef BOTAN_HAS_BLOWFISH
# define LIBSSH2_BLOWFISH 1
#else
# define LIBSSH2_BLOWFISH 0
#endif

#ifdef BOTAN_HAS_RC4
# define LIBSSH2_RC4 1
#else
# define LIBSSH2_RC4 0
#endif

#ifdef BOTAN_HAS_CAST
# define LIBSSH2_CAST 1
#else
# define LIBSSH2_CAST 0
#endif

#ifdef BOTAN_HAS_DES
# define LIBSSH2_3DES 1
#else
# define LIBSSH2_3DES 0
#endif


#define MD5_DIGEST_LENGTH 16
#define SHA_DIGEST_LENGTH 20
#define SHA256_DIGEST_LENGTH 32
#define SHA384_DIGEST_LENGTH 48
#define SHA512_DIGEST_LENGTH 64

#define EC_MAX_POINT_LEN ((528 * 2 / 8) + 1)


/*******************************************************************/
/*
 * Botan2 backend: Generic functions
 */

#define libssh2_crypto_init() \
    _libssh2_botan2_init()
#define libssh2_crypto_exit() \
    _libssh2_botan2_free()

#define _libssh2_random(buf, len) \
    _libssh2_botan2_random(buf, len)

#define libssh2_prepare_iovec(vec, len)  /* Empty. */


/*******************************************************************/
/*
 * Botan2 backend: HMAC functions
 */

#define libssh2_hmac_ctx botan_mac_t

#define libssh2_hmac_ctx_init(ctx)
#define libssh2_hmac_cleanup(pctx) \
    botan_mac_destroy(*pctx)
#define libssh2_hmac_update(ctx, data, datalen) \
    botan_mac_update(ctx, (unsigned char *) data, datalen)
#define libssh2_hmac_final(ctx, hash) \
    botan_mac_final(ctx, hash, NULL)

#define libssh2_hmac_sha1_init(pctx, key, keylen) \
    _libssh2_botan2_hmac_init(pctx, "HMAC(SHA-1)", key, keylen)
#define libssh2_hmac_md5_init(pctx, key, keylen) \
    _libssh2_botan2_hmac_init(pctx, "HMAC(MD5)", key, keylen)
#define libssh2_hmac_ripemd160_init(pctx, key, keylen) \
    _libssh2_botan2_hmac_init(pctx, "HMAC(RIPEMD-160)", key, keylen)
#define libssh2_hmac_sha256_init(pctx, key, keylen) \
    _libssh2_botan2_hmac_init(pctx, "HMAC(SHA-256)", key, keylen)
#define libssh2_hmac_sha384_init(pctx, key, keylen) \
    _libssh2_botan2_hmac_init(pctx, "HMAC(SHA-384)", key, keylen)
#define libssh2_hmac_sha512_init(pctx, key, keylen) \
    _libssh2_botan2_hmac_init(pctx, "HMAC(SHA-512)", key, keylen)


/*******************************************************************/
/*
 * Botan2 backend: SHA1 functions
 */

#define libssh2_sha1_ctx botan_hash_t

#define libssh2_sha1_init(pctx) \
    _libssh2_botan2_hash_init(pctx, "SHA-1")
#define libssh2_sha1_update(ctx, data, datalen) \
    botan_hash_update(ctx, (unsigned char *) data, datalen)
#define libssh2_sha1_final(ctx, hash) \
    _libssh2_botan2_hash_final(&ctx, hash)
#define libssh2_sha1(data, datalen, hash) \
    _libssh2_botan2_hash(data, datalen, "SHA-1", hash)

/*******************************************************************/
/*
 * Botan2 backend: SHA256 functions
 */

#define libssh2_sha256_ctx botan_hash_t

#define libssh2_sha256_init(pctx) \
    _libssh2_botan2_hash_init(pctx, "SHA-256")
#define libssh2_sha256_update(ctx, data, datalen) \
    botan_hash_update(ctx, (unsigned char *) data, datalen)
#define libssh2_sha256_final(ctx, hash) \
    _libssh2_botan2_hash_final(&ctx, hash)
#define libssh2_sha256(data, datalen, hash) \
    _libssh2_botan2_hash(data, datalen, "SHA-256", hash)


/*******************************************************************/
/*
 * Botan2 backend: SHA384 functions
 */

#define libssh2_sha384_ctx botan_hash_t

#define libssh2_sha384_init(pctx) \
    _libssh2_botan2_hash_init(pctx, "SHA-384")
#define libssh2_sha384_update(ctx, data, datalen) \
    botan_hash_update(ctx, (unsigned char *) data, datalen)
#define libssh2_sha384_final(ctx, hash) \
    _libssh2_botan2_hash_final(&ctx, hash)
#define libssh2_sha384(data, datalen, hash) \
    _libssh2_botan2_hash(data, datalen, "SHA-384", hash)


/*******************************************************************/
/*
 * Botan2 backend: SHA512 functions
 */

#define libssh2_sha512_ctx botan_hash_t

#define libssh2_sha512_init(pctx) \
    _libssh2_botan2_hash_init(pctx, "SHA-512")
#define libssh2_sha512_update(ctx, data, datalen) \
    botan_hash_update(ctx, (unsigned char *) data, datalen)
#define libssh2_sha512_final(ctx, hash) \
    _libssh2_botan2_hash_final(&ctx, hash)
#define libssh2_sha512(data, datalen, hash) \
    _libssh2_botan2_hash(data, datalen, "SHA-512", hash)


/*******************************************************************/
/*
 * Botan2 backend: MD5 functions
 */

#define libssh2_md5_ctx botan_hash_t

#define libssh2_md5_init(pctx) \
    _libssh2_botan2_hash_init(pctx, "MD5")
#define libssh2_md5_update(ctx, data, datalen) \
    botan_hash_update(ctx, (unsigned char *) data, datalen)
#define libssh2_md5_final(ctx, hash) \
    _libssh2_botan2_hash_final(&ctx, hash)
#define libssh2_md5(data, datalen, hash) \
    _libssh2_botan2_hash(data, datalen, "MD5", hash)

/*******************************************************************/
/*
 * Botan2 backend: Symmetric Cipher Functions
 */
#define _libssh2_cipher_ctx botan_cipher_t

#define _libssh2_cipher_type(algo)  const char* algo

#define _libssh2_cipher_aes256ctr "AES-256/CTR"
#define _libssh2_cipher_aes192ctr "AES-192/CTR"
#define _libssh2_cipher_aes128ctr "AES-128/CTR"
#define _libssh2_cipher_aes256    "AES-256/CBC"
#define _libssh2_cipher_aes192    "AES-192/CBC"
#define _libssh2_cipher_aes128    "AES-128/CBC"
#define _libssh2_cipher_blowfish  "BLOWFISH/CBC"
#define _libssh2_cipher_arcfour   "ARC4-128"
#define _libssh2_cipher_cast5     "CAST5"
#define _libssh2_cipher_3des      "3DES/CBC"


#define _libssh2_cipher_init(h, algo, iv, secret, encrypt) \
    _libssh2_botan2_cipher_init(h, algo, iv, secret, encrypt)

#define _libssh2_cipher_crypt(ctx, algo, encrypt, block, blocksize) \
    _libssh2_botan2_cipher_crypt(ctx, algo, encrypt, block, blocksize)

/*******************************************************************/
/*
 * Botan2 backend: RSA Functions
 */

struct _libssh2_botan2_rsa_ctx;
typedef struct _libssh2_botan2_rsa_ctx libssh2_rsa_ctx;

#define _libssh2_rsa_new(rsactx, e, e_len, n, n_len, \
                         d, d_len, p, p_len, q, q_len, \
                         e1, e1_len, e2, e2_len, c, c_len) \
    _libssh2_botan2_rsa_new(rsactx, e, e_len, n, n_len, \
                            d, d_len, p, p_len, q, q_len, \
                            e1, e1_len, e2, e2_len, c, c_len)

#define _libssh2_rsa_new_private(rsactx, s, filename, passphrase) \
    _libssh2_botan2_rsa_new_private(rsactx, s, filename, passphrase)

#define _libssh2_rsa_new_private_frommemory(rsactx, s, filedata, \
                                            filedata_len, passphrase) \
     _libssh2_botan2_rsa_new_private_frommemory(rsactx, s, filedata, \
                                               filedata_len, passphrase)

#define _libssh2_rsa_sha1_sign(s, rsactx, hash, hash_len, sig, sig_len) \
    _libssh2_botan2_rsa_sha1_sign(s, rsactx, hash, hash_len, sig, sig_len)

#define _libssh2_rsa_sha1_verify(rsactx, sig, sig_len, m, m_len) \
    _libssh2_botan2_rsa_sha1_verify(rsactx, sig, sig_len, m, m_len)

#define _libssh2_rsa_free(rsactx) \
    _libssh2_botan2_rsa_free(rsactx)


/*******************************************************************/
/*
 * Botan2 backend: forward declarations
 */
void
_libssh2_botan2_init(void);

void
_libssh2_botan2_free(void);

int
_libssh2_botan2_random(unsigned char * buf, int len);

void
_libssh2_botan2_hmac_init(botan_mac_t * ctx, const char * mac,
                          const unsigned char * key, size_t keylen);

int
_libssh2_botan2_hash_init(botan_hash_t * ctx, const char * algo);

void
_libssh2_botan2_hash_final(botan_hash_t * ctx, unsigned char * output);

int
_libssh2_botan2_hash(const unsigned char * data, size_t len,
                     const char * algo, unsigned char * output);


int
_libssh2_botan2_cipher_init(_libssh2_cipher_ctx * h, _libssh2_cipher_type(algo),
                            unsigned char * iv, unsigned char * secret,
                            int encrypt);

int
_libssh2_botan2_cipher_crypt(_libssh2_cipher_ctx * ctx,
                             _libssh2_cipher_type(algo), int encrypt,
                             unsigned char * block, size_t blocksize);

int
_libssh2_botan2_rsa_new(libssh2_rsa_ctx ** rsa,
                        const unsigned char * edata, unsigned long elen,
                        const unsigned char * ndata, unsigned long nlen,
                        const unsigned char * ddata, unsigned long dlen,
                        const unsigned char * pdata, unsigned long plen,
                        const unsigned char * qdata, unsigned long qlen,
                        const unsigned char * e1data, unsigned long e1len,
                        const unsigned char * e2data, unsigned long e2len,
                        const unsigned char * coeffdata,
                        unsigned long coefflen);

int
_libssh2_botan2_rsa_new_private(libssh2_rsa_ctx ** rsa,
                                LIBSSH2_SESSION * session,
                                const char * filename,
                                const unsigned char * passphrase);

int
_libssh2_botan2_rsa_new_private_frommemory(libssh2_rsa_ctx ** rsa,
                                           LIBSSH2_SESSION * session,
                                           const char * data, size_t datalen,
                                           const unsigned char * passphrase);

int
_libssh2_botan2_rsa_sha1_sign(LIBSSH2_SESSION * session,
                              libssh2_rsa_ctx * rsactx,
                              const unsigned char * hash, size_t hashlen,
                              unsigned char ** signature,
                              size_t * signaturelen);

int
_libssh2_botan2_rsa_sha1_verify(libssh2_rsa_ctx * rsa,
                                const unsigned char * sig, unsigned long siglen,
                                const unsigned char * m, unsigned long mlen);

void
_libssh2_botan2_rsa_free(libssh2_rsa_ctx * rsactx);

#endif // __LIBSSH2_BOTAN2_H
