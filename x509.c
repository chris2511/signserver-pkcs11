/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#include "x509.h"
#include "object.h"
#include "attr.h"
#include "link.h"

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
    storage_free(x509->cert_der);
    storage_free(x509->name_der);
    object_free(obj);
}

static ck_rv_t x509_collect_attributes(struct object *obj)
{
    struct x509 *x509 = object2x509(obj);
    struct attr *attr = &obj->attributes;

    ATTR_ADD_ULONG(attr, CKA_CLASS, CKO_CERTIFICATE);
    ATTR_ADD_ULONG(attr, CKA_CERTIFICATE_TYPE, CKC_X_509);
    ATTR_ADD_STORAGE(attr, CKA_VALUE, x509->cert_der);
    ATTR_ADD_STORAGE(attr, CKA_SUBJECT, x509->name_der);

    return CKR_OK;
}

static void x509_link_object(struct object *obj, struct link *link)
{
    obj->link = link;
    struct x509 *x509 = object2x509(obj);
    EVP_PKEY *pkey = X509_get_pubkey(x509->certificate);
    if (pkey)
        link_add_pkey(link, pkey);
}

struct object *x509_init(struct object *obj)
{
    if (!obj)
        return NULL;
    struct x509 *x509 = object2x509(obj);
    obj->type = OBJECT_TYPE_CERTIFICATE;
    obj->do_link = x509_link_object;

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
    if (p-buffer != r) {
        fprintf(stderr, "Object:%s: %zu octets ignored\n",
                obj->name, r-(p-buffer));
    }
    free(buffer);
    if (x509->certificate) {
        X509_NAME *name = X509_get_subject_name(x509->certificate);
        x509->cert_der = storage_I2D(i2d_X509, x509->certificate);
        x509->name_der = storage_I2D(i2d_X509_NAME, name);
    }
    if (!x509->certificate || !x509->cert_der || !x509->name_der) {
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
