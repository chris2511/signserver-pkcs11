/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#include "key.h"

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

int key_mechanism_dup(struct key *dst, struct ck_mechanism *src)
{
    memcpy(&dst->mechanism, src, sizeof *src);
    dst->mechanism.parameter = malloc(src->parameter_len);
    if (!dst->mechanism.parameter)
        return -1;
    memcpy(dst->mechanism.parameter, src->parameter, src->parameter_len);
    return 0;
}

void key_free(struct key *key)
{
    for (unsigned long i = 0; i < key->n_attributes; i++) {
        if (key->attributes[i].value)
            free(key->attributes[i].value);
    }
    if (key->name)
        free(key->name);
}

int key_init(struct key *key, key_serial_t key_id, char *desc, int desc_len)
{
    (void)desc_len;
    if (strncmp(desc, "asymmetric;", 11u) != 0)
        return 0;
    char *name = strrchr(desc, ';');
    if (!name)
        return 0;
    
    memset(key, 0, sizeof *key);
    key->key = key_id;
    key->name = strdup(name + 1);
    key_collect_attributes(key);
    return 1;
}

#define INIT_ATTR(attr, _type, _len) { \
    attr.type = _type; \
    attr.value = malloc(_len); \
    if (!attr.value) \
        return CKR_HOST_MEMORY; \
    attr.value_len = _len; \
}
#define INIT_ATTR_ULONG(attr, _type, val) { \
    INIT_ATTR(attr, _type, sizeof(unsigned long)) \
    *((unsigned long *)attr.value) = val; \
}
#define INIT_ATTR_BOOL(attr, _type, val) { \
    INIT_ATTR(attr, _type, sizeof(unsigned char)) \
    *((unsigned char *)attr.value) = val; \
}

ck_rv_t key_collect_attributes(struct key *key)
{
    unsigned long n = 0;
    struct ck_attribute *templ = key->attributes;

    INIT_ATTR(templ[n], CKA_LABEL, strlen(key->name));
    memcpy(templ[n].value, key->name, templ[n].value_len);
    n++;

    int r = keyctl_pkey_query(key->key, "", &key->query);
    if (r == -1) {
        fprintf(stderr, "keyctl_pkey_query %d - %s\n", r, strerror(errno));
        return CKR_SLOT_ID_INVALID;
    }
    DBG("QUERY %u %u %u %u", key->query.max_data_size,
        key->query.max_dec_size, key->query.max_enc_size,
        key->query.max_sig_size);
    if (key->query.key_size > 1024) {
        INIT_ATTR_ULONG(templ[n], CKA_KEY_TYPE, CKK_RSA);
        n++;
        INIT_ATTR_ULONG(templ[n], CKA_MODULUS_BITS, key->query.key_size);
        n++;
    }
    INIT_ATTR(templ[n], CKA_ALLOWED_MECHANISMS, sizeof rsa_mechs);
    memcpy(templ[n].value, rsa_mechs, templ[n].value_len);
    n++;
    INIT_ATTR_BOOL(templ[n], CKA_ALWAYS_AUTHENTICATE, 0);
    n++;

    unsigned long supported_ops = key->query.supported_ops;
    if (supported_ops & (KEYCTL_SUPPORTS_DECRYPT | KEYCTL_SUPPORTS_SIGN)) {
        INIT_ATTR_ULONG(templ[n], CKA_CLASS, CKO_PRIVATE_KEY);
        n++;
        if (supported_ops & KEYCTL_SUPPORTS_DECRYPT) {
            INIT_ATTR_BOOL(templ[n], CKA_DECRYPT, 1);
            n++;
        }
        if (supported_ops & KEYCTL_SUPPORTS_SIGN) {
            INIT_ATTR_BOOL(templ[n], CKA_SIGN, 1);
            n++;
        }

    } else if (supported_ops & (KEYCTL_SUPPORTS_ENCRYPT | KEYCTL_SUPPORTS_VERIFY)) {
        INIT_ATTR_ULONG(templ[n], CKA_CLASS, CKO_PUBLIC_KEY);
        n++;
        if (supported_ops & KEYCTL_SUPPORTS_ENCRYPT) {
            INIT_ATTR_BOOL(templ[n], CKA_ENCRYPT, 1);
            n++;
        }
        if (supported_ops & KEYCTL_SUPPORTS_VERIFY) {
            INIT_ATTR_BOOL(templ[n], CKA_VERIFY, 1);
            n++;
        }
    }
    key->n_attributes = n;
    DBG("Attributes for '%s' Count:%lu 0x%lx Keysize: %u",
         key->name, n, supported_ops, key->query.key_size);
    return CKR_OK;
}

ck_rv_t key_sign(struct key *key,
    unsigned char *signature, unsigned long *signature_len)
{
    size_t sig_len = MIN(key->query.max_sig_size, *signature_len);
    long ret = keyctl_pkey_sign(key->key, enc_by_id(key->mechanism.mechanism),
        key->data, key->data_len, signature, sig_len);
    if (ret < 0) {
        fprintf(stderr, "SIGN Error %ld - %s key:%d(%s) in:%lu out:%zu\n", ret,
                strerror(errno), key->key, key->name, key->data_len, sig_len);
        return CKR_GENERAL_ERROR;
    }

    *signature_len = ret;
    DBG("SIGN OK %ld key:%d(%s) in:%lu out:%lu", ret,
            key->key, key->name, key->data_len, sig_len);
    
    return CKR_OK;
}

ck_rv_t key_data_add(struct key *key,
    unsigned char *data, unsigned long data_len)
{
    key->data = realloc(key->data, key->data_len + data_len);
    if (!key->data)
        return CKR_HOST_MEMORY;
    memcpy(key->data + key->data_len, data, data_len);
    key->data_len += data_len;

    DBG("PART '%s' %ld", data, data_len);
    return CKR_OK;
}

/* Returns 0 if an attribute did not match,
 * 1 if all matched, 
 * 2 if some attributes are unknown
 */
int key_match_attributes(struct key *key, struct ck_attribute *templ, unsigned long n)
{
    int unknown = 0;
    unsigned long i, j;
    for (i = 0; i < n; i++) {
        struct ck_attribute *attr = templ + i;
        for (j = 0; j < key->n_attributes; j++) {
            struct ck_attribute *key_attr = key->attributes + j;
            if (attr->type == key_attr->type) {
                if (attr->value_len != key_attr->value_len)
                    return 0;
                if (memcmp(attr->value, key_attr->value, attr->value_len) != 0)
                    return 0;
                break;
            }
        }
        if (j == key->n_attributes)
            unknown = 1;
    }
    return unknown ? 2 : 1;
}
