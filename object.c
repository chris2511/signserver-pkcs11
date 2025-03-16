/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#include "object.h"
#include "key.h"
#include "attr.h"
#include "link.h"
#include "x509.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <sys/param.h>

void object_free(struct object *obj)
{
    if (obj->name)
        free(obj->name);
    attr_free(&obj->attributes);

    free(obj);
}

static ck_rv_t object_collect_attributes(struct object *obj)
{
    const char *name = forward_to_colon(obj);
    struct attr *attr = &obj->attributes;
    ATTR_ADD(attr, CKA_LABEL, (char*)name, strlen(name), 0);
    ATTR_ADD_BOOL(attr, CKA_ALWAYS_AUTHENTICATE, 0);
    return CKR_OK;
}

static void link_object(struct object *obj, struct link *link)
{
    obj->link = link;
}

static struct object *_object_init(key_serial_t object_id, char *desc)
{
    DBG("New Object %d %s", object_id, desc);
    struct object *obj = calloc(1, sizeof *obj);
    if (obj) {
        obj->object_id = object_id;
        obj->do_link = link_object;
        struct attr *attr = &obj->attributes;
        obj->name = dup_keyname(desc);
        if (obj->name) {
            if (attr_init(attr)) {
                if (object_collect_attributes(obj) == CKR_OK)
                    return obj;
            }
        }
    }
    attr_free(&obj->attributes);
    free(obj->name);
    free(obj);
    return NULL;
}

struct object *object_new(key_serial_t object_id, char *desc)
{
    if (strncmp(desc, "asymmetric;", 11u) == 0) {
        return key_init(_object_init(object_id, desc));
    }
    if (strncmp(desc, "user;", 5u) == 0) {
        struct object *obj = _object_init(object_id, desc);
        if (obj && strncmp(obj->name, "x509:", 5u) == 0) {
            return x509_init(obj);
        }
        object_free(obj);
    }
    return NULL;
}

const char *forward_to_colon(struct object *obj)
{
    const char *name = strchr(obj->name, ':');
    return name ? name +1 : obj->name;
}