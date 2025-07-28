/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#include "object.h"
#include "key.h"
#include "attr.h"
#include "x509.h"
#include "slot.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <sys/param.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>

void object_free(struct object *obj)
{
    for (unsigned long i=0; i < sizeof obj->store / sizeof obj->store[0]; i++) {
        if (obj->store[i])
            storage_free(obj->store[i]);
        obj->store[i] = NULL;
    }
    if (obj->bio) {
        BIO_free_all(obj->bio);
        obj->bio = NULL;
    }
    if (obj->bm) {
        BUF_MEM_free(obj->bm);
        obj->bm = NULL;
    }
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

int object_match_attributes(struct object *obj, struct ck_attribute *templ, unsigned long n)
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

static int mechanism_to_hashnid(ck_mechanism_type_t mech)
{
    switch (mech) {
        case CKM_ECDSA_SHA1:
        case CKM_SHA1_RSA_PKCS:
        case CKM_SHA1_RSA_PKCS_PSS:
            return NID_sha1;
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS_PSS:
            return NID_sha256;
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS_PSS:
            return NID_sha384;
        case CKM_SHA512_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS_PSS:
            return NID_sha512;
        case CKM_ECDSA:
        case CKM_RSA_PKCS:
        case CKM_RSA_PKCS_PSS:
            return NID_undef;
        default:
            DBG("Unsupported mechanism %lu", mech);
            return NID_undef;
    }
}

static const char* mechanism_to_signserver_algo(ck_mechanism_type_t mech)
{
    switch (mech) {
        case CKM_RSA_PKCS:
        case CKM_SHA1_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS:
            return "NONEwithRSA";
        case CKM_RSA_PKCS_PSS:
        case CKM_SHA1_RSA_PKCS_PSS:
        case CKM_SHA256_RSA_PKCS_PSS:
        case CKM_SHA384_RSA_PKCS_PSS:
        case CKM_SHA512_RSA_PKCS_PSS:
            return "NONEwithRSAandMGF1";
        case CKM_ECDSA:
        case CKM_ECDSA_SHA1:
            return "NONEwithECDSA";
        default:
            return "";
    }
}

static int mechanism_is_pkcsv15(ck_mechanism_type_t mech)
{
    switch (mech) {
        case CKM_RSA_PKCS:
        case CKM_SHA1_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS:
            return 1;
        default:
            return 0;
    }
}

ck_rv_t obj_sign_init(struct object *obj, struct ck_mechanism *mech)
{
    if (!obj || !mech)
        return CKR_ARGUMENTS_BAD;
    obj->mechanism = mech->mechanism;
    int nid = mechanism_to_hashnid(obj->mechanism);

    obj->bio = BIO_new(BIO_s_mem());
    obj->bm = BUF_MEM_new();

    if (!obj->bio || !obj->bm) {
        DBG("Failed to create BIO for mechanism %lu", mech->mechanism);
        return CKR_HOST_MEMORY;
    }
    BIO_set_mem_buf(obj->bio, obj->bm, BIO_NOCLOSE);
    if (nid != NID_undef) {
        BIO *digest = BIO_new(BIO_f_md());
        if (!digest) {
            DBG("Failed to create BIO for digest %d", nid);
            return CKR_HOST_MEMORY;
        }
        BIO_set_md(digest, EVP_get_digestbynid(nid));
        obj->bio = BIO_push(digest, obj->bio);
    }

    return CKR_OK;
}

ck_rv_t obj_sign_update(struct object *obj,
        unsigned char *part, unsigned long part_len)
{
    return BIO_write(obj->bio, part, part_len) >= 0 ?
        CKR_OK : CKR_FUNCTION_FAILED;
}

ck_rv_t obj_sign_final(struct object *obj, struct slot *slot,
        unsigned char *signature, unsigned long *signature_len)
{
    BIO_flush(obj->bio);
    BIO_free_all(obj->bio);
    obj->bio = NULL;
    const unsigned char *data = (unsigned char *)obj->bm->data;
    int len = obj->bm->length;
    X509_SIG *sig = NULL;
    int hashnid = mechanism_to_hashnid(obj->mechanism);

    if (mechanism_is_pkcsv15(obj->mechanism)) {
        DBG("Unpacking PKCS#1 v1.5 envelope %lu", obj->object_id);
        sig = d2i_X509_SIG(NULL, &data, obj->bm->length);
        if (!sig) {
            DBG("Failed to unpack PKCS#1 v1.5 envelope");
            return CKR_FUNCTION_FAILED;
        }
        const ASN1_OCTET_STRING *digest;
        const X509_ALGOR *algor;
        X509_SIG_get0(sig, &algor, &digest);
        data = digest->data;
        len = digest->length;
        hashnid = OBJ_obj2nid(algor->algorithm);
    }
    DBG("Finalizing signature for object %lu", obj->object_id);
    FILE *fp =fopen("DATA", "w");
    if (!fp) {
        DBG("Cannot open DATA file for writing: %s", strerror(errno));
        if (sig)
            X509_SIG_free(sig);
        return CKR_FUNCTION_FAILED;
    }
    fwrite(data, 1, len, fp);
    fclose(fp);
    if (sig)
        X509_SIG_free(sig);

    char cmd[1024];
    snprintf(cmd, sizeof cmd, "curl -v -k --cert-type P12 --cert '%s:%s'"
        " -F workerName='%s'"
        " -F data=@DATA"
        " -F REQUEST_METADATA.CLIENTSIDE_HASHDIGESTALGORITHM=%s"
        " -F REQUEST_METADATA.USE_CLIENTSUPPLIED_HASH=true"
        " -F REQUEST_METADATA.SIGNATUREALGORITHM=%s"
        " '%s/signserver/process'",
        slot->auth_cert, slot->auth_pass,
        slot->worker,
        OBJ_nid2sn(hashnid),
        mechanism_to_signserver_algo(obj->mechanism),
        slot->url);

    DBG("Executing command: '%s'", cmd);

    fp = popen(cmd, "r");
    if (!fp) {
        DBG("Cannot execute command '%s': %s", cmd, strerror(errno));
        return CKR_FUNCTION_FAILED;
    }
    char buf[1024];
    size_t readlen = fread(buf, 1, sizeof buf, fp);
    pclose(fp);
    if (readlen == 0) {
        DBG("No data read from command '%s'", cmd);
        return CKR_FUNCTION_FAILED;
    }
    memcpy(signature, buf, readlen);
    *signature_len = readlen;
    ///////////////// SIGNATURE LOGIC HERE /////////////////
    return CKR_OK;
}

const ck_mechanism_type_t rsa_mechs[] = {
        CKM_RSA_PKCS,
        CKM_RSA_PKCS_PSS,
        CKM_SHA1_RSA_PKCS,
        CKM_SHA256_RSA_PKCS,
        CKM_SHA384_RSA_PKCS,
        CKM_SHA512_RSA_PKCS,
        CKM_SHA1_RSA_PKCS_PSS,
        CKM_SHA256_RSA_PKCS_PSS,
        CKM_SHA384_RSA_PKCS_PSS,
        CKM_SHA512_RSA_PKCS_PSS,
};
const unsigned long n_mechs = sizeof rsa_mechs / sizeof rsa_mechs[0];

static ck_rv_t key_collect_key_attributes(struct object *obj, const EVP_PKEY *key)
{
    struct attr *attr = &obj->attributes;
    const OSSL_PARAM *pa = EVP_PKEY_gettable_params(key);
    DBG("Key: %lu", obj->object_id);
    while (pa && pa->key) {
//        DBG("Param: %s Type: %d", pa->key, pa->data_type);
        pa++;
    }

    if (EVP_PKEY_get_base_id(key) == EVP_PKEY_RSA) {
        ATTR_ADD_ULONG(attr, CKA_KEY_TYPE, CKK_RSA);
        ATTR_ADD_ULONG(attr, CKA_MODULUS_BITS, EVP_PKEY_bits(key));
        ATTR_ADD(attr, CKA_ALLOWED_MECHANISMS, rsa_mechs, sizeof rsa_mechs, 0);
        obj->store[0] = storage_PKEY(key, OSSL_PKEY_PARAM_RSA_N);
        ATTR_ADD_STORAGE(attr, CKA_MODULUS, obj->store[0]);
        obj->store[1] = storage_PKEY(key, OSSL_PKEY_PARAM_RSA_E);
        ATTR_ADD_STORAGE(attr, CKA_PUBLIC_EXPONENT, obj->store[1]);
    }
    if (EVP_PKEY_get_base_id(key) == EVP_PKEY_EC) {
        unsigned char buf[1024], *ptr = buf;
        size_t len = sizeof buf;
        ATTR_ADD_ULONG(attr, CKA_KEY_TYPE, CKK_EC);
        EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_EC_GENERATOR,
                                        buf, len, &len);
        if (len == 0 || len > sizeof buf) {
            DBG("Cannot get EC generator size: %zu", len);
            return CKR_HOST_MEMORY;
        }
        ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
        ASN1_STRING_set(os, buf, len);
        int ret = i2d_ASN1_OCTET_STRING(os, &ptr);
        ASN1_OCTET_STRING_free(os);
        if (ret < 0) {
            DBG("Cannot convert EC generator to DER");
            return CKR_GENERAL_ERROR;
        }
        obj->store[0] = storage_new(buf, ret);
        ATTR_ADD_STORAGE(attr, CKA_EC_POINT, obj->store[0]);
        #if 0
        const EC_GROUP *group = EVP_PKEY_get0_EC_KEY(key)->group;
        if (group) {
            int curve_nid = EC_GROUP_get_curve_name(group);
            ATTR_ADD_ULONG(attr, CKA_EC_PARAMS, curve_nid);
            obj->store[0] = storage_new((unsigned char *)&curve_nid, sizeof(curve_nid));
            ATTR_ADD_STORAGE(attr, CKA_EC_PARAMS, obj->store[0]);
        }
            #endif
    }
    return CKR_OK;
}

static ck_rv_t x509_collect_attributes(struct object *obj, const X509 *cert)
{
    struct attr *attr = &obj->attributes;
    ATTR_ADD_ULONG(attr, CKA_CLASS, CKO_CERTIFICATE);
    ATTR_ADD_ULONG(attr, CKA_CERTIFICATE_TYPE, CKC_X_509);
    ATTR_ADD_BOOL(attr, CKA_EXTRACTABLE, 1);
    ATTR_ADD_BOOL(attr, CKA_NEVER_EXTRACTABLE, 0);
    obj->store[0] = storage_I2D(i2d_X509, cert);
    ATTR_ADD_STORAGE(attr, CKA_VALUE, obj->store[0]);
    obj->store[1] = storage_I2D(i2d_X509_NAME, X509_get_subject_name(cert));
    ATTR_ADD_STORAGE(attr, CKA_SUBJECT,  obj->store[1]);

    return CKR_OK;
}

ck_rv_t object_new(struct object *obj, enum object_type type, X509 *cert)
{
    obj->type = type;
    obj->object_id = (ck_object_handle_t)type;
    object_init(obj);

    struct attr *attr = &obj->attributes;
    const EVP_PKEY *key = X509_get_pubkey(cert);
    if (!key) {
        DBG("Cannot get public key from certificate\n");
        return CKR_HOST_MEMORY;
    }

    switch (type) {
        case OBJECT_TYPE_PUBLIC_KEY:
            key_collect_key_attributes(obj, key);
            ATTR_ADD_ULONG(attr, CKA_CLASS, CKO_PUBLIC_KEY);
            ATTR_ADD_BOOL(attr, CKA_ENCRYPT, 1);
            ATTR_ADD_BOOL(attr, CKA_VERIFY, 1);
            ATTR_ADD_BOOL(attr, CKA_EXTRACTABLE, 1);
            break;
        case OBJECT_TYPE_PRIVATE_KEY:
            key_collect_key_attributes(obj, key);
            ATTR_ADD_ULONG(attr, CKA_CLASS, CKO_PRIVATE_KEY);
            ATTR_ADD_BOOL(attr, CKA_DECRYPT, 1);
            ATTR_ADD_BOOL(attr, CKA_SIGN, 1);
            ATTR_ADD_BOOL(attr, CKA_NEVER_EXTRACTABLE, 1);
            break;
        case OBJECT_TYPE_CERTIFICATE:
            x509_collect_attributes(obj, cert);
            break;
        default:
            return CKR_GENERAL_ERROR;
    }

    return CKR_OK;
}
