/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#include "key.h"
#include "object.h"
#include "attr.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <sys/param.h>

const ck_mechanism_type_t rsa_mechs[] = {
        CKM_RSA_PKCS,
    //    CKM_RSA_X_509,
    //     CKM_RSA_PKCS_OAEP,
    //     CKM_RSA_PKCS_PSS,
        CKM_SHA1_RSA_PKCS,
        CKM_SHA256_RSA_PKCS,
        CKM_SHA384_RSA_PKCS,
        CKM_SHA512_RSA_PKCS,
    //     CKM_SHA1_RSA_PKCS_PSS,
    //     CKM_SHA256_RSA_PKCS_PSS,
    //     CKM_SHA384_RSA_PKCS_PSS,
    //     CKM_SHA512_RSA_PKCS_PSS,
};
const unsigned long n_mechs = sizeof rsa_mechs / sizeof rsa_mechs[0];

static const char *enc_by_id(int id)
    {
        switch (id) {
        case CKM_RSA_PKCS:
        case CKM_SHA1_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS:
            return "enc=pkcs1";
        }
        return "";
}

static struct key *object2key(struct object *obj)
{
    return &obj->key;
}

int key_mechanism_dup(struct object *dst, struct ck_mechanism *src)
{
    struct key *key = object2key(dst);
    memcpy(&key->mechanism, src, sizeof *src);
    key->mechanism.parameter = malloc(src->parameter_len);
    if (!key->mechanism.parameter)
        return -1;
    memcpy(key->mechanism.parameter, src->parameter, src->parameter_len);
    return 0;
}

void key_free(struct object *obj)
{
    struct key *key = object2key(obj);
    if (key->data)
        free(key->data);
    if (key->mechanism.parameter)
        free(key->mechanism.parameter);
    object_free(obj);
}

static ck_rv_t key_collect_attributes(struct object *obj)
{
    struct key *key = object2key(obj);
    struct attr *attr = &obj->attributes;

    /* Educated guess */
    if (key->query.key_size > 1024) {
        ATTR_ADD_ULONG(attr, CKA_KEY_TYPE, CKK_RSA);
        ATTR_ADD_ULONG(attr, CKA_MODULUS_BITS, key->query.key_size);
        ATTR_ADD(attr, CKA_ALLOWED_MECHANISMS, rsa_mechs, sizeof rsa_mechs, 0);
    }

    unsigned long supported_ops = key->query.supported_ops;
    if (supported_ops & (KEYCTL_SUPPORTS_DECRYPT | KEYCTL_SUPPORTS_SIGN)) {
        obj->type = OBJECT_TYPE_PRIVATE_KEY;
        ATTR_ADD_ULONG(attr, CKA_CLASS, CKO_PRIVATE_KEY);
        if (supported_ops & KEYCTL_SUPPORTS_DECRYPT)
            ATTR_ADD_BOOL(attr, CKA_DECRYPT, 1);
        if (supported_ops & KEYCTL_SUPPORTS_SIGN)
            ATTR_ADD_BOOL(attr, CKA_SIGN, 1);

    } else if (supported_ops & (KEYCTL_SUPPORTS_ENCRYPT | KEYCTL_SUPPORTS_VERIFY)) {
        obj->type = OBJECT_TYPE_PUBLIC_KEY;
        ATTR_ADD_ULONG(attr, CKA_CLASS, CKO_PUBLIC_KEY);
        if (supported_ops & KEYCTL_SUPPORTS_ENCRYPT)
            ATTR_ADD_BOOL(attr, CKA_ENCRYPT, 1);
        if (supported_ops & KEYCTL_SUPPORTS_VERIFY)
            ATTR_ADD_BOOL(attr, CKA_VERIFY, 1);
    }
    return CKR_OK;
}

struct object *key_init(struct object *obj)
{
    if (!obj)
        return NULL;

    struct key *key = object2key(obj);

    DBG("Collect Attributes for '%s'", obj->name);
    int r = keyctl_pkey_query(obj->object_id, "", &key->query);
    if (r == -1) {
        fprintf(stderr, "keyctl_pkey_query %d - %s\n", r, strerror(errno));
        object_free(obj);
        return NULL;
    }
    DBG("QUERY %u %u %u %u", key->query.max_data_size,
        key->query.max_dec_size, key->query.max_enc_size,
        key->query.max_sig_size);
    if (key_collect_attributes(obj) != CKR_OK) {
        object_free(obj);
        return NULL;
    }
    return obj;
}

ck_rv_t key_sign(struct object *obj,
    unsigned char *signature, unsigned long *signature_len)
{
    struct key *key = object2key(obj);
    size_t sig_len = MIN(key->query.max_sig_size, *signature_len);
    long ret = keyctl_pkey_sign(obj->object_id, enc_by_id(key->mechanism.mechanism),
        key->data, key->data_len, signature, sig_len);
    if (ret < 0) {
        fprintf(stderr, "SIGN Error %ld - %s key:%d(%s) in:%lu out:%zu\n", ret,
                strerror(errno), obj->object_id, obj->name, key->data_len, sig_len);
        return CKR_GENERAL_ERROR;
    }

    *signature_len = ret;
    DBG("SIGN OK %ld key:%d(%s) in:%lu out:%lu", ret,
            obj->object_id, obj->name, key->data_len, sig_len);
    
    return CKR_OK;
}

ck_rv_t key_data_add(struct object *obj,
    unsigned char *data, unsigned long data_len)
{
    struct key *key = object2key(obj);
    key->data = realloc(key->data, key->data_len + data_len);
    if (!key->data)
        return CKR_HOST_MEMORY;
    memcpy(key->data + key->data_len, data, data_len);

    DBG("PART %ld + %ld - MECH: %lu", key->data_len, data_len, key->mechanism.mechanism);
    key->data_len += data_len;
    return CKR_OK;
}
