/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _KEY_H
#define _KEY_H 1

#include "keyutil-pkcs11.h"
#include <stddef.h>

struct object;

struct key {
    struct keyctl_pkey_query query;
    struct ck_mechanism mechanism;
    unsigned char *data;
    unsigned long data_len;
};

extern const ck_mechanism_type_t rsa_mechs[];
extern const unsigned long n_mechs;

struct object *key_init(struct object *obj);
void key_free(struct object *obj);
int key_mechanism_dup(struct object *obj, struct ck_mechanism *src);
ck_rv_t key_sign(struct object *obj,
    unsigned char *signature, unsigned long *signature_len);
ck_rv_t key_data_add(struct object *obj,
    unsigned char *data, unsigned long data_len);

#endif
