/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _ATTR_H
#define _ATTR_H 1

#include "keyutil-pkcs11.h"

struct attr {
    unsigned long count;
    unsigned long alloced;
    struct ck_attribute *attributes;
};

#define ATTR_ADD(attr, type, val, len) do { \
    ck_rv_t r = attr_add((attr), (type), (void*)(val), (len)); \
    if (r != CKR_OK) \
        return r; \
} while (0)

#define ATTR_ADD_ULONG(attr, type, _val) do { \
    unsigned long val = (_val); \
    ATTR_ADD((attr), (type), &val, sizeof val); \
} while (0)

#define ATTR_ADD_BOOL(attr, type, _val) do { \
    unsigned char val = (_val); \
    ATTR_ADD((attr), (type), &val, sizeof val); \
} while (0)

int attr_init(struct attr *attr);
void attr_free(struct attr *attr);
ck_rv_t attr_add(struct attr *attr, ck_attribute_type_t type,
                 void *value, unsigned long value_len);
int attr_match_template(struct attr *attr,
        struct ck_attribute *templ, unsigned long count);
int attr_fill_template(struct attr *attr,
        struct ck_attribute *templ, unsigned long count);
#endif
