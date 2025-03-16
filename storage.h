/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _STORAGE_H
#define _STORAGE_H 1

#include <stddef.h>
#include <stdlib.h>
#include <openssl/bn.h>

struct storage {
    size_t len;
    unsigned char data[1];
};

struct storage *storage_new(unsigned char *data, size_t len);
static inline void storage_free(struct storage *s)
{
    if (s)
        free(s);
}
struct storage *storage_i2d(int(*i2d)(const void*, unsigned char **),
                            const void *data);
#define storage_I2D(i2d, data) storage_i2d(\
    (int (*)(const void *, unsigned char **))(i2d), (const void *)(data))

struct storage *storage_BN(BIGNUM *bn);
struct storage *storage_PKEY(EVP_PKEY *pkey, const char *param);

#endif
