/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#include "x509.h"
#include "object.h"
#include "attr.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <sys/param.h>

#include <openssl/x509.h>

static struct x509 *object2x509(struct object *obj)
{
    return &obj->x509;
}

void x509_free(struct object *obj)
{
    struct x509 *x509 = object2x509(obj);
    if (x509->certificate)
        X509_free(x509->certificate);

    object_free(obj);
}

static ck_rv_t x509_collect_attributes(struct object *obj)
{
    struct x509 *x509 = object2x509(obj);
    struct attr *attr = &obj->attributes;

    X509_NAME *name = X509_get_subject_name(x509->certificate);
    if (name) {
        unsigned char *subject, *p;
        int len = i2d_X509_NAME(name, NULL); 
        subject = p = OPENSSL_malloc(len);
        i2d_X509_NAME(name, &p);
        ATTR_ADD(attr, CKA_SUBJECT, subject, (size_t)len);
        free(subject);
        X509_NAME_free(name);
    }
    return CKR_OK;
}

struct object *x509_init(struct object *obj)
{
    if (!obj)
        return NULL;
    struct x509 *x509 = object2x509(obj);
    obj->type = OBJECT_TYPE_CERTIFICATE;

    DBG("Collect Attributes for '%s'", obj->name);
    unsigned char *buffer;
    const unsigned char *p;
    long r = keyctl_read_alloc(obj->object_id, (void**)&buffer);
    if (r == -1) {
        fprintf(stderr, "keyctl_read_alloc() %ld - %s\n", r, strerror(errno));
        object_free(obj);
        return NULL;
    }
    p = buffer;
    x509->certificate = d2i_X509(NULL, &p, r);
    free(buffer);
    if (!x509->certificate) {
        fprintf(stderr, "d2i_X509() failed\n");
        x509_free(obj);
        return NULL;
    }   
    if (x509_collect_attributes(obj) != CKR_OK) {
        x509_free(obj);
        return NULL;
    }
    return obj;
}
