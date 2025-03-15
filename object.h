/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _OBJECT_H
#define _OBJECT_H 1

#include "keyutil-pkcs11.h"
#include "attr.h"
#include "key.h"
#include "x509.h"

enum object_type {
    OBJECT_TYPE_PUBLIC_KEY,
    OBJECT_TYPE_PRIVATE_KEY,
    OBJECT_TYPE_CERTIFICATE,
};

struct object {
    struct object *next;
    key_serial_t object_id;
    enum object_type type;
    char *name;
    struct attr attributes;
    struct link *link;
    union {
        struct key key;
        struct x509 x509;
    };
};

struct object *object_new(key_serial_t key_id, char *desc);
void object_free(struct object *obj);
int object_match_attributes(struct object *obj, struct ck_attribute *templ, unsigned long n);
const char *forward_to_colon(struct object *obj);
ck_rv_t object_link(struct object *obj, struct link *link);

#endif
