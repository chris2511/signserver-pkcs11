/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#include "link.h"
#include <stdlib.h>
#include <string.h>

//#include <openssl/evp.h>
#include <openssl/core_names.h>

static unsigned long pkcs11_id = 1000;

struct link *link_new(const char *name)
{
    struct link *link = calloc(1, sizeof *link);
    if (link) {
        link->pkcs11_id = pkcs11_id++;
        link->id[0] = link->pkcs11_id >> 8;
        link->id[1] = link->pkcs11_id & 0xff;
        link->name = strdup(name);
        DBG("New Link P11_ID:%lu Name:%s", link->pkcs11_id, link->name);
        if (!link->name) {
            free(link);
            link = NULL;}
    }
    return link;
}

void link_free(struct link *link)
{
    DBG("Free Link P11_ID:%lu Name:%s", link->pkcs11_id, link->name);
    if (link->pkey)
        EVP_PKEY_free(link->pkey);
    storage_free(link->pub_der);
    storage_free(link->modulus);
    storage_free(link->pub_exp);

    free(link->name);
    free(link);
}

ck_rv_t link_collect_attributes(struct link *link, struct attr *attr)
{
    if (!link || !attr)
        return CKR_OK;
    if (link->modulus)
        ATTR_ADD_STORAGE(attr, CKA_MODULUS, link->modulus);
    if (link->pub_exp)
        ATTR_ADD_STORAGE(attr, CKA_PUBLIC_EXPONENT, link->pub_exp);
    ATTR_ADD(attr, CKA_ID, link->id, sizeof link->id, 0);
    return CKR_OK;
}

void link_add_pkey(struct link *link, EVP_PKEY *pkey)
{
    link->pkey = pkey;
    link->pub_der = storage_I2D(i2d_PublicKey, pkey);
    
    link->modulus = storage_PKEY(pkey, OSSL_PKEY_PARAM_RSA_N);
    link->pub_exp = storage_PKEY(pkey, OSSL_PKEY_PARAM_RSA_E);
}
