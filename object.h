/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _OBJECT_H
#define _OBJECT_H 1

#include "signserver-pkcs11.h"
#include "attr.h"
#include <openssl/bio.h>

#define OBJ_ID_OFFSET 0x25ad7 

enum object_type {
    OBJECT_TYPE_PUBLIC_KEY,
    OBJECT_TYPE_PRIVATE_KEY,
    OBJECT_TYPE_CERTIFICATE,
    OBJECT_TYPE_MAX,
};

struct object {
    ck_object_handle_t object_id;
    enum object_type type;
    int keytype; // EVP_PKEY_base_id
    struct attr attributes;
    unsigned long mechanism;
    BIO *bio;
    BUF_MEM *bm;
};

struct slot;

ck_rv_t object_new(struct object *obj, enum object_type type, X509 *cert);
void object_free(struct object *obj);
int object_match_attributes(struct object *obj, struct ck_attribute *templ, unsigned long n);
const char *object_type_to_desc(enum object_type type);

#endif
