/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _KEY_H
#define _KEY_H 1

#include <stddef.h>

#include "signserver-pkcs11.h"
#include "object.h"

#include <openssl/bio.h>

struct signature_op {
    struct object *obj;
    unsigned long mechanism;
    BIO *bio;
    BUF_MEM *bm;
};

ck_rv_t signature_op_init(struct signature_op *sig);
ck_rv_t signature_op_update(struct signature_op *sig,
        unsigned char *part, unsigned long part_len);
ck_rv_t signature_op_final(struct signature_op *sig, struct slot *slot,
        unsigned char *signature, unsigned long *signature_len);
void signature_op_free(struct signature_op *op);

ck_rv_t key_get_mechanism(struct object *obj,
        ck_mechanism_type_t *mechanism_list, unsigned long *count);
ck_rv_t key_collect_key_attributes(struct object *obj, const EVP_PKEY *key);

#endif
