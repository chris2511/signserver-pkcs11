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
    DBG2("Add Attribute[%lu] %lu %lu", attr->count, type, value_len);
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

static const struct ck_attribute *attr_find(const struct attr *attr,
    const struct ck_attribute *templ)
{
    for (unsigned long i = 0; i < attr->count; i++) {
        if (attr->attributes[i].type == templ->type) {
            DBG2("Found my attribute[%lu/%lu] Type:0x%lx Len:%lu", i, attr->count,
                 attr->attributes[i].type, attr->attributes[i].value_len);
            return &attr->attributes[i];
        }
    }
    DBG2("Attribute 0x%lx not found", templ->type);
    return NULL;
}

/* Returns 0 if an attribute did not match,
 * 1 if all matched,
 * 2 if some attributes are unknown
 */
int attr_match_template(const struct attr *attr,
        struct ck_attribute *templ, unsigned long count)
{
    int unknown = 0;
    unsigned long i;
    for (i = 0; i < count; i++) {
        const struct ck_attribute *tmpl_attr = templ + i;
        DBG("Search Template attribute[%lu/%lu] Type:0x%lx Len:%lu", i, count, tmpl_attr->type, tmpl_attr->value_len);
        const struct ck_attribute *obj_attr = attr_find(attr, tmpl_attr);
        if (!obj_attr) {
            unknown++;
        } else {
            if (tmpl_attr->value_len != obj_attr->value_len ||
                memcmp(tmpl_attr->value, obj_attr->value, tmpl_attr->value_len) != 0)
            {
                DBG("Attribute %lu different to ours", i);
                return 0;
            }
            DBG2("Attribute %lu matches ours", i);
        }
    }
    DBG("All our attributes matched %lu out of %lu", count - unknown, count);
    return unknown ? 2 : 1;
}

ck_rv_t attr_fill_template(const struct attr *attr,
        struct ck_attribute *templ, unsigned long count)
{
    unsigned long found = 0, too_small = 0;
    for (unsigned long i = 0; i < count; i++) {
        struct ck_attribute *tmpl_attr = templ + i;

        DBG("Search Template attribute[%lu/%lu] Type:0x%lx Len:%lu",
            i, count, tmpl_attr->type, tmpl_attr->value_len);
        unsigned long new_len = CK_UNAVAILABLE_INFORMATION;
        const struct ck_attribute *obj_attr = attr_find(attr, tmpl_attr);
        if (obj_attr) {
            found++;
            // Follows the spec: attr->value && attr->value_len < new_len
            //     -> CK_UNAVAILABLE_INFORMATION & ret = CKR_BUFFER_TOO_SMALL
            if (!tmpl_attr->value) {
                new_len = obj_attr->value_len;
            } else if (tmpl_attr->value_len < obj_attr->value_len) {
                too_small++;
            } else {
                new_len = obj_attr->value_len;
                memcpy(tmpl_attr->value, obj_attr->value, new_len);
            }
        }
        tmpl_attr->value_len = new_len;
    }
    DBG("Attributes found/too_small %lu/%lu out of %lu", found, too_small, count);
    return found < count ? CKR_ATTRIBUTE_TYPE_INVALID :
                           too_small > 0 ? CKR_BUFFER_TOO_SMALL : CKR_OK;
}
