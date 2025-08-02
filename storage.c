/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#include "storage.h"
#include "signserver-pkcs11.h"

#include <string.h>
#include <openssl/evp.h>

struct storage *storage_new(unsigned char *data, size_t len)
{
    struct storage *s = malloc(len + sizeof *s);
    if (s) {
        s->len = len;
        if (data)
            memcpy(s->data, data, len);
    }
    return s;
}

struct storage *storage_i2d(int(*i2d)(const void*, unsigned char **),
                            const void *data)
{
    struct storage *s;
    unsigned char *p;

    int size = i2d(data, NULL);
    if (size < 0) {
        OSSL_ERR("i2d function failed");
        return NULL;
    }
    s = malloc(size + sizeof *s);
    if (!s)
        return NULL;
    s->len = size;
    p = s->data;
    i2d(data, &p);
    return s;
}

struct storage *storage_BN(BIGNUM *bn)
{
    struct storage *s = storage_new(NULL, BN_num_bytes(bn));
    if (s)
        BN_bn2bin(bn, s->data);
    BN_free(bn);
    return s;
}

struct storage *storage_PKEY(const EVP_PKEY *pkey, const char *param)
{
    BIGNUM *bn = NULL;
    if (EVP_PKEY_get_bn_param(pkey, param, &bn) > 0) {
        struct storage *s = storage_BN(bn);
        return s;
    }
    OSSL_ERR(param);
    return NULL;
}
