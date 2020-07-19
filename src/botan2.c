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
#include "libssh2_priv.h"

#ifdef LIBSSH2_BOTAN2 /* compile only, if we build with botan2 */

#include "misc.h"

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include <alloca.h>
#include <stdint.h>
#include <stdio.h>

/*******************************************************************/
/*
 * Botan2 backend: Misc defines
 */

#define LIBSSH2_BOTAN2_RNG_TYPE "user-threadsafe" // AutoSeeded_RNG

#ifdef BOTAN_HAS_EMSA_PKCS1
#   define LIBSSH2_BOTAN2_EMSA(hash) \
                "EMSA3(" hash ")"
#elif defined(BOTAN_HAS_EMSA_PSSR)
#   define LIBSSH2_BOTAN2_EMSA(hash) \
                "EMSA4(" hash ")"
#endif

/*
 * Macros for compile-time version checks
 *
 * Compare using BOTAN_VERSION_CODE_FOR, as in
 *  # if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,8,0)
 *  #    error "Botan version too old"
 *  # endif
 */
#ifndef BOTAN_VERSION_CODE_FOR
# define BOTAN_VERSION_CODE_FOR(a,b,c) \
          ((a << 16) | (b << 8) | (c))
# ifdef BOTAN_VERSION_CODE
#   undef BOTAN_VERSION_CODE
# endif
#endif
#ifndef BOTAN_VERSION_CODE
# define BOTAN_VERSION_CODE \
          BOTAN_VERSION_CODE_FOR(BOTAN_VERSION_MAJOR, \
                                 BOTAN_VERSION_MINOR, \
                                 BOTAN_VERSION_PATCH)
#endif

#define botan2_calloc calloc
#define botan2_free free

struct _libssh2_botan2_rsa_ctx
{
    botan_privkey_t privkey;
    botan_pubkey_t pubkey;
};


/*******************************************************************/
/*
 * Botan2 backend: Global const defines
 */

static const char enc_privkey_header[] =  "-----BEGIN ENCRYPTED PRIVATE KEY-----";
static const char enc_privkey_footer[] = "-----END ENCRYPTED PRIVATE KEY-----";

static const char privkey_header[] = "-----BEGIN PRIVATE KEY-----";
static const char privkey_footer[] = "-----END PRIVATE KEY-----";

static const char rsa_privkey_header[] = "-----BEGIN RSA PRIVATE KEY-----";
static const char rsa_privkey_footer[] = "-----END RSA PRIVATE KEY-----";


/*******************************************************************/
/*
 * Botan2 backend: Global context handles
 */

static botan_rng_t _libssh2_botan2_rng;

/*******************************************************************/
/*
 * Botan2 backend: Static helpers
 */

static int
_init_mp_from_bin(botan_mp_t * mp, const uint8_t vec[], size_t veclen)
{
    int ret;

    ret = botan_mp_init(mp);
    if (ret != BOTAN_FFI_SUCCESS) {
        return ret;
    }

    ret = botan_mp_from_bin(*mp, vec, veclen);
    if (ret != BOTAN_FFI_SUCCESS) {
        (void)botan_mp_destroy(*mp);
    }

    return ret;
}

static int
_rsa_load_keys(botan_privkey_t * privkey, botan_pubkey_t * pubkey,
               const uint8_t edata[], size_t elen,
               const uint8_t ndata[], size_t nlen,
               const uint8_t pdata[], size_t plen,
               const uint8_t qdata[], size_t qlen)
{
    int ret;
    botan_mp_t e, n, p, q;

    ret = _init_mp_from_bin(&e, edata, elen);
    if (ret == BOTAN_FFI_SUCCESS) {
      ret = _init_mp_from_bin(&n, ndata, nlen);
    }
    if (ret == BOTAN_FFI_SUCCESS) {
      ret = _init_mp_from_bin(&p, pdata, plen);
    }
    if (ret == BOTAN_FFI_SUCCESS) {
      ret = _init_mp_from_bin(&q, qdata, qlen);
    }
    if (ret == BOTAN_FFI_SUCCESS) {
      ret = botan_privkey_load_rsa(privkey, p, q, e);
    }
    if (ret == BOTAN_FFI_SUCCESS) {
      ret = botan_pubkey_load_rsa(pubkey, n, e);
    }

    (void)botan_mp_destroy(q);
    (void)botan_mp_destroy(p);
    (void)botan_mp_destroy(n);
    (void)botan_mp_destroy(e);

    return ret;
}

static int
_try_pem_load(LIBSSH2_SESSION *session,
              FILE * fp, const uint8_t * passphrase,
              const char * header, const char * footer,
              uint8_t ** data, size_t * datalen)
{
    int next;
    int ret;

    if (data == NULL) {
        return -1;
    }

    *data = NULL;
    *datalen = 0;
    (void)fseek(fp, 0L, SEEK_SET);
    for (;;) {
        ret = _libssh2_pem_parse(session, header, footer, passphrase, fp,
                                 data, (unsigned int *) datalen);
        if(ret == 0) { /* We did it, we found a PEM encoded block! */
            return 0;
        }

        if (data != NULL) { /* Do cleanup, after not finding a PEM block. */
            LIBSSH2_FREE(session, data);
            data = NULL;
        }

        next = getc(fp);
        if (next == EOF) { /* Move forward and check again for a PEM block? */
            break;
        }
        (void)ungetc(next, fp);
    }
    return -1;
}

static int
_is_rsa_key(botan_privkey_t privkey)
{
    int ret;
    botan_mp_t p;
    if (botan_mp_init(&p) != BOTAN_FFI_SUCCESS) {
        return FALSE;
    }
    /* Fetch RSA specific key to check used algo indirectly*/
    ret = botan_privkey_get_field(p, privkey, "p");
    (void)botan_mp_destroy(p);
    return (ret == BOTAN_FFI_SUCCESS ? TRUE : FALSE);
}

static int
_load_rsa_privkey_from_file(LIBSSH2_SESSION * session, const char * filename,
                            const uint8_t * passphrase, botan_privkey_t * out)
{
    int ret;
    long int filesize;

    FILE * fp = fopen(filename, "r");
    uint8_t * data = NULL;
    size_t datalen = 0;
    const char * password = (const char *) passphrase;

    if (fp == NULL) {
        return -1;
    }

    /* Try with "ENCRYPTED PRIVATE KEY" PEM armor.
       --> PKCS#8 EncryptedPrivateKeyInfo */
    ret = _try_pem_load(session, fp, passphrase, enc_privkey_header,
                        enc_privkey_footer, &data, &datalen);

    /* Try with "PRIVATE KEY" PEM armor.
       --> PKCS#8 PrivateKeyInfo or EncryptedPrivateKeyInfo */
    if (ret != 0) {
        ret = _try_pem_load(session, fp, passphrase, privkey_header,
                            privkey_footer, &data, &datalen);
    }

    /* Found a PEM armor containing PKCS#8 data. */
    if (ret == 0) {
        ret = botan_privkey_load(out, NULL, data, datalen, password);
        ret = (ret == BOTAN_FFI_SUCCESS ? 0 : -1);
    }

    /* Try with "RSA PRIVATE KEY" PEM armor.
       --> PKCS#1 RSAPrivateKey */
    if (ret != 0) {
        ret = _try_pem_load(session, fp, passphrase, rsa_privkey_header,
                            rsa_privkey_footer, &data, &datalen);
        /* Found a PEM armor containing PKCS#1 data. */
        if (ret == 0) {
            ret = botan_privkey_load_rsa_pkcs1(out, data, datalen);
            ret = (ret == BOTAN_FFI_SUCCESS ? 0 : -1);
        }
    }
    (void)fclose(fp);

    if (ret != 0) {
        /* Try DER encoding. */
        fp = fopen(filename, "r");
        (void)fseek(fp, 0L, SEEK_END);
        filesize = ftell(fp);

        if (filesize <= 32768) { /* Limit to a reasonable size. */
            datalen = filesize;
            data = (unsigned char *) alloca(datalen);
            if (data != NULL) { /* Avoid SIGSEGV in case stack was full. */
                fseek(fp, 0L, SEEK_SET);
                fread(data, datalen, 1, fp);

                /* Try as PKCS#8 DER data.
                   --> PKCS#8 PrivateKeyInfo or EncryptedPrivateKeyInfo */
                ret = botan_privkey_load(out, NULL, data, datalen, password);
                /* Try as PKCS#1 DER data.
                   --> PKCS#1 RSAPrivateKey */
                if (ret != BOTAN_FFI_SUCCESS) {
                    ret = botan_privkey_load_rsa_pkcs1(out, data, datalen);
                    ret = (ret == BOTAN_FFI_SUCCESS ? 0 : -1);
                }
            }
        }
        (void)fclose(fp);
    }

    if (ret != 0 || _is_rsa_key(*out) == FALSE) {
        return -1;
    }
    return 0;
}

static int
_load_rsa_privkey_from_memory(LIBSSH2_SESSION * session, const char * filedata,
                            size_t filedatalen, const uint8_t * passphrase,
                            botan_privkey_t * out)
{
    int ret;

    uint8_t * data = NULL;
    size_t datalen = 0;
    const char * password = (const char *) passphrase;

    /* Try with "ENCRYPTED PRIVATE KEY" PEM armor.
       --> PKCS#8 EncryptedPrivateKeyInfo */
    ret = _libssh2_pem_parse_memory(session, enc_privkey_header,
                                    enc_privkey_footer, filedata, filedatalen,
                                    &data, (unsigned int *) &datalen);

    /* Try with "PRIVATE KEY" PEM armor.
       --> PKCS#8 PrivateKeyInfo or EncryptedPrivateKeyInfo */
    if (ret != 0) {
        ret = _libssh2_pem_parse_memory(session, privkey_header, privkey_footer,
                                        filedata, filedatalen, &data,
                                        (unsigned int *) &datalen);
    }

    /* Found a PEM armor containing PKCS#8 data. */
    if (ret == 0) {
        ret = botan_privkey_load(out, NULL, data, datalen, password);
        ret = (ret == BOTAN_FFI_SUCCESS ? 0 : -1);
    }

    /* Try with "RSA PRIVATE KEY" PEM armor.
       --> PKCS#1 RSAPrivateKey */
    if (ret != 0) {
        ret = _libssh2_pem_parse_memory(session, rsa_privkey_header,
                                        rsa_privkey_footer, filedata,
                                        filedatalen, &data,
                                        (unsigned int *) &datalen);
        /* Found a PEM armor containing PKCS#1 data. */
        if (ret == 0) {
            ret = botan_privkey_load_rsa_pkcs1(out, data, datalen);
            ret = (ret == BOTAN_FFI_SUCCESS ? 0 : -1);
        }
    }

    if (ret != 0) {
        data = (uint8_t *)filedata;
        datalen = filedatalen;
        /* Try as PKCS#8 DER data.
           --> PKCS#8 PrivateKeyInfo or EncryptedPrivateKeyInfo */
        ret = botan_privkey_load(out, NULL, data, datalen, password);
        /* Try as PKCS#1 DER data.
           --> PKCS#1 RSAPrivateKey */
        if (ret != BOTAN_FFI_SUCCESS) {
            ret = botan_privkey_load_rsa_pkcs1(out, data, datalen);
            ret = (ret == BOTAN_FFI_SUCCESS ? 0 : -1);
        }
    }

    if (ret != 0 || _is_rsa_key(*out) == FALSE) {
        return -1;
    }
    return 0;
}

static const LIBSSH2_CRYPT_METHOD*
_get_cipher_method_by_algo(const char * algo)
{
    static const LIBSSH2_CRYPT_METHOD ** methods_list;
    methods_list = libssh2_crypt_methods();

    size_t algo_len;
    algo_len = strlen(algo);

    if (methods_list != NULL) {
        while(*methods_list != NULL) {
            if (strlen((*methods_list)->algo) == algo_len &&
                strncmp((*methods_list)->algo, algo, algo_len) == 0) {
                return *methods_list;
            }
            methods_list++;
        }
    }
    return NULL;
}


/*******************************************************************/
/*
 * Botan2 backend: Generic functions
 */

void
_libssh2_botan2_init(void)
{
    int ret;
    ret = botan_rng_init(&_libssh2_botan2_rng, LIBSSH2_BOTAN2_RNG_TYPE);
    if(ret != BOTAN_FFI_SUCCESS) {
        (void)botan_rng_destroy(_libssh2_botan2_rng);
    }
}

void
_libssh2_botan2_free(void)
{
    (void)botan_rng_destroy(_libssh2_botan2_rng);
}

int
_libssh2_botan2_random(unsigned char * buf, int len)
{
    int ret = botan_rng_get(_libssh2_botan2_rng, buf, len);
    return ret == BOTAN_FFI_SUCCESS ? 0 : -1;
}

void
_libssh2_botan2_hmac_init(botan_mac_t * ctx, const char * mac,
                          const uint8_t * key, size_t keylen)
{
    int ret;

    ret = botan_mac_init(ctx, mac, 0);
    if (ret != BOTAN_FFI_SUCCESS) {
        return;
    }

    ret = botan_mac_set_key(*ctx, key, keylen);
    if (ret != BOTAN_FFI_SUCCESS) {
        (void)botan_mac_destroy(*ctx);
        *ctx = NULL;
    }
}


int
_libssh2_botan2_hash_init(botan_hash_t * ctx, const char * algo)
{
    int ret;

    if (ctx == NULL) {
        return 0;
    }

    ret = botan_hash_init(ctx, algo, 0);
    return ret == BOTAN_FFI_SUCCESS ? 1 : 0;
}

void
_libssh2_botan2_hash_final(botan_hash_t * ctx, unsigned char * output)
{
    if (ctx != NULL && *ctx != NULL)
    {
        (void)botan_hash_final(*ctx, output);
        (void)botan_hash_destroy(*ctx);
    }
}

int
_libssh2_botan2_hash(const unsigned char * data, size_t len,
                     const char * algo, unsigned char * output)
{
    botan_hash_t ctx;
    int ret;

    ret = botan_hash_init(&ctx, algo, 0);
    if (ret != BOTAN_FFI_SUCCESS) {
        return -1;
    }

    ret = botan_hash_update(ctx, data, len);
    if (ret != BOTAN_FFI_SUCCESS) {
        (void)botan_hash_destroy(ctx);
        return -1;
    }

    ret = botan_hash_final(ctx, output);
    (void)botan_hash_destroy(ctx);
    return ret == BOTAN_FFI_SUCCESS ? 0 : -1;
}

int
_libssh2_botan2_cipher_init(_libssh2_cipher_ctx * h, _libssh2_cipher_type(algo),
                            unsigned char * iv, unsigned char * secret,
                            int encrypt)
{
    int ret;
    int flags;
    _libssh2_cipher_ctx ctx;
    const LIBSSH2_CRYPT_METHOD * method;

    flags = encrypt == TRUE
        ? BOTAN_CIPHER_INIT_FLAG_ENCRYPT : BOTAN_CIPHER_INIT_FLAG_DECRYPT;
    ret = botan_cipher_init(&ctx, algo, flags);
    if (ret != BOTAN_FFI_SUCCESS) {
        return -1;
    }

    method = _get_cipher_method_by_algo(algo);
    if (method == NULL) {
        botan_cipher_destroy(ctx);
        return -1;
    }

    ret = botan_cipher_set_key(ctx, secret, method->secret_len);
    if (ret == BOTAN_FFI_SUCCESS && encrypt == TRUE) {
        ret = botan_cipher_start(ctx, iv, method->iv_len);
    }

    if (ret != BOTAN_FFI_SUCCESS) {
        botan_cipher_destroy(ctx);
        return -1;
    }

    *h = ctx;
    return 0;
}

int
_libssh2_botan2_cipher_crypt(_libssh2_cipher_ctx * ctx,
                             _libssh2_cipher_type(algo), int encrypt,
                             unsigned char * block, size_t blocksize)
{
    unsigned char * buf;
    size_t bufsize;
    int ret;
    if (ctx == NULL || *ctx == NULL) {
        return -1;
    }

    ret = botan_cipher_output_length(*ctx, blocksize, &bufsize);
    if (ret == BOTAN_FFI_SUCCESS && blocksize >= bufsize) {
      botan_
    }

    ret = _check_botan_cipher_config(ctx, algo, encrypt);
    if (ret == BOTAN_FFI_SUCCESS)
}

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
                        unsigned long coefflen)
{
    int ret;
    libssh2_rsa_ctx * ctx;

    ctx = (libssh2_rsa_ctx*) botan2_calloc(1, sizeof(libssh2_rsa_ctx));
    if (ctx == NULL) {
        return -1;
    }

    // Botan2 calculates private exp d, e1, e2 and coeff internally.
    (void)ddata;
    (void)dlen;
    (void)e1data;
    (void)e1len;
    (void)e2data;
    (void)e2len;
    (void)coeffdata;
    (void)coefflen;

    ret = _rsa_load_keys(&(ctx->privkey), &(ctx->pubkey),
                           edata, elen, ndata, nlen,
                           pdata, plen, qdata, qlen);
    if (ret != BOTAN_FFI_SUCCESS) {
        _libssh2_botan2_rsa_free(ctx);
        return -1;
    }
    *rsa = ctx;
    return 0;
}

int
_libssh2_botan2_rsa_new_private(libssh2_rsa_ctx ** rsa,
                                LIBSSH2_SESSION * session,
                                const char * filename,
                                const unsigned char * passphrase)
{
    int ret;
    if (session == NULL) {
        return -1;
    }

    _libssh2_init_if_needed();
    *rsa = (libssh2_rsa_ctx *) LIBSSH2_ALLOC(session, sizeof(libssh2_rsa_ctx));
    if (*rsa == NULL) {
        return -1;
    }

    ret = _load_rsa_privkey_from_file(session, filename, passphrase,
                                      &((*rsa)->privkey));
    if (ret != 0) {
        _libssh2_botan2_rsa_free(*rsa);
        LIBSSH2_FREE(session, *rsa);
        *rsa = NULL;
        return -1;
    }
    return 0;
}

int
_libssh2_botan2_rsa_new_private_frommemory(libssh2_rsa_ctx ** rsa,
                                           LIBSSH2_SESSION * session,
                                           const char * data, size_t datalen,
                                           const unsigned char * passphrase)
{
    int ret;
    if (session == NULL) {
        return -1;
    }

    _libssh2_init_if_needed();
    *rsa = (libssh2_rsa_ctx *) LIBSSH2_ALLOC(session, sizeof(libssh2_rsa_ctx));
    if (*rsa == NULL) {
        return -1;
    }

    ret = _load_rsa_privkey_from_memory(session, data, datalen, passphrase,
                                        &((*rsa)->privkey));
    if (ret != 0) {
        _libssh2_botan2_rsa_free(*rsa);
        LIBSSH2_FREE(session, *rsa);
        *rsa = NULL;
        return -1;
    }
    return 0;
}

int
_libssh2_botan2_rsa_sha1_sign(LIBSSH2_SESSION * session,
                              libssh2_rsa_ctx * rsactx,
                              const unsigned char * hash, size_t hashlen,
                              unsigned char ** signature,
                              size_t * signaturelen)
{
    botan_pk_op_sign_t op;
    int ret;
    botan_rng_t rng;
    unsigned char *sig;
    size_t siglen;

    if (rsactx == NULL || signaturelen == NULL ||
        signature == NULL || *signature != NULL) {
        return -1;
    }

    ret = botan_pk_op_sign_create(&op, rsactx->privkey,
                                  LIBSSH2_BOTAN2_EMSA("SHA-1"), 0);
    if (ret != BOTAN_FFI_SUCCESS) {
        return -1;
    }

    ret  = botan_pk_op_sign_update(op, hash, hashlen);
    if (ret == BOTAN_FFI_SUCCESS) {
        ret = botan_pk_op_sign_output_length(op, &siglen);
        if (ret == BOTAN_FFI_SUCCESS) {
            sig = LIBSSH2_ALLOC(session, siglen);
            if(sig == NULL) {
                (void)botan_pk_op_sign_destroy(op);
                return -1;
            }

            *signaturelen = 0;
            ret = botan_rng_init(&rng, LIBSSH2_BOTAN2_RNG_TYPE);
            if(ret == BOTAN_FFI_SUCCESS) {
                ret = botan_pk_op_sign_finish(op, rng, sig, signaturelen);
            }

            if (ret == BOTAN_FFI_SUCCESS && siglen == *signaturelen) {
                *signature = sig;
            }
            else {
                LIBSSH2_FREE(session, sig);
                *signaturelen = 0;
                *signature = NULL;
            }
        }
    }

    (void)botan_pk_op_sign_destroy(op);
    (void)botan_rng_destroy(rng);
    return (ret == BOTAN_FFI_SUCCESS) ? 0 : -1;
}

int
_libssh2_botan2_rsa_sha1_verify(libssh2_rsa_ctx * rsa,
                                const unsigned char * sig, unsigned long siglen,
                                const unsigned char * m, unsigned long mlen)
{
    botan_pk_op_verify_t op;
    int ret;

    if (rsa == NULL) {
        return -1;
    }

    ret = botan_pk_op_verify_create(&op, rsa->pubkey,
                                    LIBSSH2_BOTAN2_EMSA("SHA-1"), 0);
    if (ret != BOTAN_FFI_SUCCESS) {
        return -1;
    }

    ret  = botan_pk_op_verify_update(op, m, mlen);
    if (ret == BOTAN_FFI_SUCCESS) {
        ret = botan_pk_op_verify_finish(op, sig, siglen);
    }

    (void)botan_pk_op_verify_destroy(op);
    return (ret == BOTAN_FFI_SUCCESS) ? 0 : -1;
}

void
_libssh2_botan2_rsa_free(libssh2_rsa_ctx * rsactx)
{
    if (rsactx == NULL) {
        return;
    }
    (void)botan_pubkey_destroy(rsactx->pubkey);
    (void)botan_privkey_destroy(rsactx->privkey);
    botan2_free(rsactx);
}

#endif
