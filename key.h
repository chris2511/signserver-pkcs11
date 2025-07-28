/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _KEY_H
#define _KEY_H 1

#include "signserver-pkcs11.h"
#include "object.h"

#include <stddef.h>

ck_rv_t key_sign_init(struct object *dst, struct ck_mechanism *src);
ck_rv_t key_sign_update(struct object *obj,
        unsigned char *part, unsigned long part_len);
ck_rv_t key_sign_final(struct object *obj, struct slot *slot,
        unsigned char *signature, unsigned long *signature_len);
ck_rv_t key_get_mechanism(struct object *obj,
        ck_mechanism_type_t *mechanism_list, unsigned long *count);
ck_rv_t key_collect_key_attributes(struct object *obj, const EVP_PKEY *key);

#endif
