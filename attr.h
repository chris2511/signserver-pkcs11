/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _ATTR_H
#define _ATTR_H 1

#include "storage.h"
#include "signserver-pkcs11.h"

extern unsigned char attr_True, attr_False;

struct attr {
    unsigned long alloced_bitfield;
    unsigned long count;
    unsigned long alloced;
    struct ck_attribute *attributes;
};

#define ATTR_ADD(attr, type, val, len, dup) do { \
    ck_rv_t r = attr_add((attr), (type), (void*)(val), (len), (dup)); \
    if (r != CKR_OK) \
        return r; \
} while (0)

#define ATTR_ADD_ULONG(attr, type, _val) do { \
    unsigned long val = (_val); \
    ATTR_ADD((attr), (type), &val, sizeof val, 1); \
} while (0)

#define ATTR_ADD_BOOL(attr, type, _val) do { \
    unsigned char *val = (_val) ? &attr_True : &attr_False; \
    ATTR_ADD((attr), (type), val, sizeof *val, 0); \
} while (0)

#define ATTR_ADD_STORAGE(attr, type, _val) do { \
    if (!(_val)) return CKR_ARGUMENTS_BAD; \
    ATTR_ADD((attr), (type), (_val)->data, (_val)->len, 1); \
    storage_free(_val); \
} while (0)

int attr_init(struct attr *attr);
void attr_free(struct attr *attr);
ck_rv_t attr_add(struct attr *attr, ck_attribute_type_t type,
                 void *value, size_t value_len, int dup);
int attr_match_template(const struct attr *attr,
        struct ck_attribute *templ, unsigned long count);
ck_rv_t attr_fill_template(const struct attr *attr,
        struct ck_attribute *templ, unsigned long count);

#endif
