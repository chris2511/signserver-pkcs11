/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _KEY_H
#define _KEY_H 1

#include "keyutil-pkcs11.h"

struct key {
    key_serial_t key;
    char *name;
    struct keyctl_pkey_query query;
    struct ck_mechanism mechanism;
    unsigned long n_attributes;
    void *data;
    unsigned long data_len;
    struct ck_attribute attributes[MAX_ATTRIBUTES];
};

extern const ck_mechanism_type_t rsa_mechs[];
extern const unsigned long n_mechs;

int key_init(struct key *key, key_serial_t key_id, char *desc, int desc_len);
void key_free(struct key *key);
int key_mechanism_dup(struct key *dst, struct ck_mechanism *src);
ck_rv_t key_collect_attributes(struct key *key);
ck_rv_t key_sign(struct key *key,
    unsigned char *signature, unsigned long *signature_len);
ck_rv_t key_data_add(struct key *key,
    unsigned char *data, unsigned long data_len);

#endif
