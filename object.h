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
#include "key.h"
#include "x509.h"

enum object_type {
    OBJECT_TYPE_PUBLIC_KEY,
    OBJECT_TYPE_PRIVATE_KEY,
    OBJECT_TYPE_CERTIFICATE,
};

struct object {
    struct object *next;
    ck_object_handle_t object_id;
    enum object_type type;
    char *name;
    struct attr attributes;
    union {
        struct key key;
        struct x509 x509;
    };
};

struct object *object_new(key_serial_t key_id, char *desc);
void object_free(struct object *obj);
int object_match_attributes(struct object *obj, struct ck_attribute *templ, unsigned long n);
const char *forward_to_colon(struct object *obj);

#endif
