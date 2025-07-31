/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#include "object.h"
#include "signature.h"
#include "attr.h"
#include "slot.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <sys/param.h>

#include <openssl/x509.h>
#include <openssl/err.h>

void object_free(struct object *obj)
{
    attr_free(&obj->attributes);
}

const char *object_type_to_desc(enum object_type type)
{
    switch (type) {
        case OBJECT_TYPE_PUBLIC_KEY:
            return "public_key";
        case OBJECT_TYPE_PRIVATE_KEY:
            return "private_key";
        case OBJECT_TYPE_CERTIFICATE:
            return "certificate";
        default:
            return NULL;
    }
}

static ck_rv_t object_collect_attributes(struct object *obj)
{
    struct attr *attr = &obj->attributes;
    //ATTR_ADD_ULONG(attr, CKA_ID, 0);
    ATTR_ADD_BOOL(attr, CKA_ALWAYS_AUTHENTICATE, 0);
    ATTR_ADD_BOOL(attr, CKA_TOKEN, 1);
    return CKR_OK;
}

static ck_rv_t object_init(struct object *obj)
{
    struct attr *attr = &obj->attributes;
    if (!attr_init(attr))
        return CKR_HOST_MEMORY;

    int r = object_collect_attributes(obj);
    if (r != CKR_OK) {
        attr_free(attr);
        return r;
    }
    return CKR_OK;
}

int object_match_attributes(const struct object *obj, struct ck_attribute *templ, unsigned long n)
{
    DBG("Check Object %lu:%s", obj->object_id, object_type_to_desc(obj->type));
    if (!obj || !templ || n == 0)
        return 0;
    int ret = attr_match_template(&obj->attributes, templ, n);
    if (ret == 2) {
        DBG("Object %lu has unknown attributes", obj->object_id);
    }
    return ret;
}

static ck_rv_t x509_collect_attributes(struct object *obj, const X509 *cert)
{
    struct storage *store;

    struct attr *attr = &obj->attributes;
    ATTR_ADD_ULONG(attr, CKA_CLASS, CKO_CERTIFICATE);
    ATTR_ADD_ULONG(attr, CKA_CERTIFICATE_TYPE, CKC_X_509);
    ATTR_ADD_BOOL(attr, CKA_EXTRACTABLE, 1);
    ATTR_ADD_BOOL(attr, CKA_NEVER_EXTRACTABLE, 0);
    ATTR_ADD_BOOL(attr, CKA_COPYABLE, 1);
    store = storage_I2D(i2d_X509, cert);
    ATTR_ADD_STORAGE(attr, CKA_VALUE, store);
    store = storage_I2D(i2d_X509_NAME, X509_get_subject_name(cert));
    ATTR_ADD_STORAGE(attr, CKA_SUBJECT, store);

    return CKR_OK;
}

ck_rv_t object_new(struct object *obj, enum object_type type, X509 *cert)
{
    obj->type = type;
    obj->object_id = (ck_object_handle_t)type +OBJ_ID_OFFSET;
    object_init(obj);

    struct attr *attr = &obj->attributes;
    const EVP_PKEY *key = X509_get_pubkey(cert);

    if (!key) {
        char errbuf[256];
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof errbuf);
        DBG("Cannot get public key from certificate '%s'\n", errbuf);
        return CKR_HOST_MEMORY;
    }
    obj->keytype = EVP_PKEY_base_id(key);

    switch (type) {
        case OBJECT_TYPE_PUBLIC_KEY:
            key_collect_key_attributes(obj, key);
            ATTR_ADD_ULONG(attr, CKA_CLASS, CKO_PUBLIC_KEY);
            ATTR_ADD_BOOL(attr, CKA_ENCRYPT, 1);
            ATTR_ADD_BOOL(attr, CKA_VERIFY, 1);
            ATTR_ADD_BOOL(attr, CKA_EXTRACTABLE, 1);
            ATTR_ADD_BOOL(attr, CKA_COPYABLE, 1);
            break;
        case OBJECT_TYPE_PRIVATE_KEY:
            key_collect_key_attributes(obj, key);
            ATTR_ADD_ULONG(attr, CKA_CLASS, CKO_PRIVATE_KEY);
            ATTR_ADD_BOOL(attr, CKA_DECRYPT, 1);
            ATTR_ADD_BOOL(attr, CKA_SIGN, 1);
            ATTR_ADD_BOOL(attr, CKA_NEVER_EXTRACTABLE, 1);
            ATTR_ADD_BOOL(attr, CKA_COPYABLE, 0);
            break;
        case OBJECT_TYPE_CERTIFICATE:
            x509_collect_attributes(obj, cert);
            break;
        default:
            return CKR_GENERAL_ERROR;
    }
    switch (obj->keytype) {
        case EVP_PKEY_RSA:
            ATTR_ADD_ULONG(attr, CKA_KEY_TYPE, CKK_RSA);
            break;
        case EVP_PKEY_EC:
            ATTR_ADD_ULONG(attr, CKA_KEY_TYPE, CKK_EC);
            break;
    }
    return CKR_OK;
}
