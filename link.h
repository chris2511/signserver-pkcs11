/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _LINK_H
#define _LINK_H 1

#include "keyutil-pkcs11.h"
#include "object.h"
#include "storage.h"
#include <openssl/evp.h>

/* Objects with the same public key (privs, pubs, x509)
 * link here */
struct link {
    struct link *next;
    unsigned long pkcs11_id;
    unsigned char id[2];
    char *name;
    EVP_PKEY *pkey;
    struct storage *pub_der;
    struct storage *modulus;
    struct storage *pub_exp;
};

struct link *link_new(const char *name);
void link_free(struct link *link);
ck_rv_t link_collect_attributes(struct link *link, struct attr *attr);
void link_add_pkey(struct link *link, EVP_PKEY *pkey);

#endif
