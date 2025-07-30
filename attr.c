/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#include "attr.h"

#include <stdlib.h>
#include <string.h>

unsigned char attr_True = 1, attr_False =0;

int attr_init(struct attr *attr)
{
    attr->count = 0;
    attr->alloced = 8;
    attr->attributes = calloc(attr->alloced, sizeof(struct ck_attribute));
    return attr->attributes ? 1 : 0;
}

void attr_free(struct attr *attr)
{
    for (unsigned long i = 0; i < attr->count; i++) {
        if (attr->attributes[i].value && (attr->alloced_bitfield & (1 << i)))
            free(attr->attributes[i].value);
    }
    free(attr->attributes);
    memset(attr, 0, sizeof *attr);
}

ck_rv_t attr_add(struct attr *attr, ck_attribute_type_t type,
                 void *value, size_t value_len, int dup)
{
    if (attr->count >= attr->alloced) {
        attr->alloced *= 2;
        attr->attributes = realloc(attr->attributes,
                                   attr->alloced * sizeof(struct ck_attribute));
        if (!attr->attributes)
            return CKR_HOST_MEMORY;
    }
//    DBG("Add Attribute[%lu] %lu %lu", attr->count, type, value_len);
    struct ck_attribute *a = attr->attributes + attr->count;
    a->type = type;
    if (attr->count >= sizeof(attr->alloced_bitfield) * 8)
        return CKR_ARGUMENTS_BAD;
    if (dup) {
        a->value = malloc(value_len);
        if (!a->value)
            return CKR_HOST_MEMORY;
        memcpy(a->value, value, value_len);
        attr->alloced_bitfield |= 1 << attr->count;
    } else {
        a->value = value;
    }
    a->value_len = (unsigned long)value_len;
    attr->count++;
    return CKR_OK;
}

/* Returns 0 if an attribute did not match,
 * 1 if all matched, 
 * 2 if some attributes are unknown
 */
int attr_match_template(struct attr *attr,
        struct ck_attribute *templ, unsigned long count)
{
    int unknown = 0;
    unsigned long i, j;
    for (i = 0; i < count; i++) {
        struct ck_attribute *tmpl_attr = templ + i;
        DBG("Check TMPL Attribute[%lu] Type:%lu Len:%lu", i, tmpl_attr->type, tmpl_attr->value_len);
        for (j = 0; j < attr->count; j++) {
            struct ck_attribute *obj_attr = attr->attributes + j;
            if (tmpl_attr->type == obj_attr->type) {
                DBG("Check Attribute[%lu:%lu] Type:%lu Len:%lu", i, j, tmpl_attr->type, tmpl_attr->value_len);
                if (tmpl_attr->value_len != obj_attr->value_len)
                    return 0;
                if (memcmp(tmpl_attr->value, obj_attr->value, tmpl_attr->value_len) != 0)
                    return 0;
                DBG("Object found Type:%lu Len:%lu", tmpl_attr->type, tmpl_attr->value_len);
                break;
            }
        }
        if (j == attr->count)
            unknown = 1;
    }
    DBG("Attributes matched %lu out of %lu", i, count);
    return unknown ? 2 : 1;
}

int attr_fill_template(struct attr *attr,
        struct ck_attribute *templ, unsigned long count)
{
    unsigned long filled = 0;
    for (unsigned long i = 0; i < count; i++) {
        DBG("Attribute 0x%lx %lu", templ[i].type, templ[i].value_len);
        unsigned long new_len = CK_UNAVAILABLE_INFORMATION;
        for (unsigned long j = 0; j < attr->count; j++) {
//            DBG("Object Attribute[%lu] %lu %lu", j, attr->attributes[j].type,
//                            attr->attributes[j].value_len);
            if (attr->attributes[j].type != templ[i].type)
                continue;
            filled++;
            if (!templ[i].value) {
                new_len = attr->attributes[j].value_len;
            } else {
                if (templ[i].value_len >= attr->attributes[j].value_len) {
                    new_len = attr->attributes[j].value_len;
                    memcpy(templ[i].value, attr->attributes[j].value, new_len);
                }
            }
            break;
        }
        if (new_len == CK_UNAVAILABLE_INFORMATION) {
            DBG("Attribute 0x%lx not found", templ[i].type);
            continue;
        }
        templ[i].value_len = new_len;
    }
    DBG("Attributes Filled %lu out of %lu", filled, count);
    return filled;
}
