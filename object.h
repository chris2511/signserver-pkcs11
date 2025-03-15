/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _OBJECT_H
#define _OBJECT_H 1

#include "keyutil-pkcs11.h"

enum object_type {
    OBJECT_TYPE_PUBLIC_KEY,
    OBJECT_TYPE_PRIVATE_KEY,
    OBJECT_TYPE_CERTIFICATE,
};

struct object {
    struct object *next;
    struct object *prev;
    key_serial_t object_id;
    enum object_type type;
    char *name;
    unsigned long n_attributes;
    struct ck_attribute attributes[MAX_ATTRIBUTES];
};

int object_init(struct object *obj, key_serial_t key_id, char *desc, int desc_len);
void object_free(struct object *obj);
//ck_rv_t object_collect_attributes(struct object *obj);
int object_match_attributes(struct object *obj, struct ck_attribute *templ, unsigned long n);

#endif
