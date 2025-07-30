/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#include "signature.h"
#include "attr.h"
#include "slot.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>

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

static int estimate_hash_nid(int hashlen)
{
    switch (hashlen) {
        case SHA_DIGEST_LENGTH: return NID_sha1; break;
        case SHA256_DIGEST_LENGTH: return NID_sha256; break;
        case SHA384_DIGEST_LENGTH: return NID_sha384; break;
        case SHA512_DIGEST_LENGTH: return NID_sha512; break;
    }
    return NID_undef;
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

void signature_op_free(struct signature_op *op)
{
    if (op->bio)
        BIO_free_all(op->bio);
    if (op->bm)
        BUF_MEM_free(op->bm);
    memset(op, 0, sizeof *op);
}

ck_rv_t signature_op_init(struct signature_op *sig)
{
    if (!sig)
        return CKR_ARGUMENTS_BAD;
    int nid = mechanism_to_hashnid(sig->mechanism);

    sig->bio = BIO_new(BIO_s_mem());
    sig->bm = BUF_MEM_new();

    if (!sig->bio || !sig->bm) {
        DBG("Failed to create BIO for mechanism %lu", sig->mechanism);
        return CKR_HOST_MEMORY;
    }
    BIO_set_mem_buf(sig->bio, sig->bm, BIO_NOCLOSE);
    if (nid != NID_undef) {
        BIO *digest = BIO_new(BIO_f_md());
        if (!digest) {
            DBG("Failed to create BIO for digest %d", nid);
            return CKR_HOST_MEMORY;
        }
        BIO_set_md(digest, EVP_get_digestbynid(nid));
        sig->bio = BIO_push(digest, sig->bio);
    }
    return CKR_OK;
}

ck_rv_t signature_op_update(struct signature_op *sig,
        unsigned char *part, unsigned long part_len)
{
    if (!sig || !sig->bio || !part || part_len == 0) {
        DBG("Invalid arguments for key_sign_update");
        return CKR_ARGUMENTS_BAD;
    }
    return BIO_write(sig->bio, part, part_len) >= 0 ?
        CKR_OK : CKR_FUNCTION_FAILED;
}

static int unpack_pkcs15_signature(struct signature_op *sig)
{
    DBG("Unpacking PKCS#1 v1.5 envelope %lu", sig->obj->object_id);
    const unsigned char *p = (unsigned char *)sig->bm->data;
    X509_SIG *xsig = d2i_X509_SIG(NULL, &p, sig->bm->length);
    if (!xsig) {
        DBG("Failed to unpack PKCS#1 v1.5 envelope");
        return NID_undef;
    }
    BIO_free_all(sig->bio);
    sig->bio = NULL;
    const ASN1_OCTET_STRING *digest;
    const X509_ALGOR *algor;
    X509_SIG_get0(xsig, &algor, &digest);

    //  sig->bm is large enough, check anyway
    if (sig->bm->length < (size_t)digest->length) {
        DBG("Failed to grow BUF_MEM for PKCS#1 v1.5 envelope");
        X509_SIG_free(xsig);
        return NID_undef;
    }
    // Write the digest to the BIO
    memcpy(sig->bm->data, digest->data, digest->length);
    sig->bm->length = digest->length;

    // extract hashnid before freeing xsig
    int hashnid = OBJ_obj2nid(algor->algorithm);
    X509_SIG_free(xsig);
    return hashnid;
}

ck_rv_t signature_op_final(struct signature_op *sig, struct slot *slot,
        unsigned char *signature, unsigned long *signature_len)
{
    BIO_flush(sig->bio);
    int hashnid = mechanism_to_hashnid(sig->mechanism);
    if (mechanism_is_pkcsv15(sig->mechanism))
        hashnid = unpack_pkcs15_signature(sig);

    if (hashnid == NID_undef) {
        DBG("No hash algorithm for mechanism %lu - guessing", sig->mechanism);
        hashnid = estimate_hash_nid(sig->bm->length);
    }
    DBG("Finalizing signature for object %lu", sig->obj->object_id);
    FILE *fp =fopen("DATA", "w");
    if (!fp) {
        DBG("Cannot open DATA file for writing: %s", strerror(errno));
        return CKR_FUNCTION_FAILED;
    }
    fwrite(sig->bm->data, 1, sig->bm->length, fp);
    fclose(fp);

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
        mechanism_to_signserver_algo(sig->mechanism),
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
const unsigned long n_rsa_mechs = sizeof rsa_mechs / sizeof rsa_mechs[0];

const ck_mechanism_type_t ec_mechs[] = {
        CKM_ECDSA,
        CKM_ECDSA_SHA1,
};
const unsigned long n_ec_mechs = sizeof ec_mechs / sizeof ec_mechs[0];

ck_rv_t key_get_mechanism(struct object *obj,
        ck_mechanism_type_t *mechanism_list, unsigned long *count)
{
    unsigned long n_mechs;
    const ck_mechanism_type_t *mechs;

    switch (obj->keytype) {
        case EVP_PKEY_RSA:
            mechs = rsa_mechs;
            n_mechs = n_rsa_mechs;
            break;
        case EVP_PKEY_EC:
            mechs = ec_mechs;
            n_mechs = n_ec_mechs;
            break;
        default:
            DBG("Unsupported key type %d", obj->keytype);
            return CKR_KEY_TYPE_INCONSISTENT;
    }
    if (mechanism_list) {
        if (*count < n_mechs) {
            *count = n_mechs;
            return CKR_BUFFER_TOO_SMALL;
        }
        memcpy(mechanism_list, mechs, n_mechs * sizeof(ck_mechanism_type_t));
    }
    *count = n_mechs;
    return CKR_OK;
}

ck_rv_t key_collect_key_attributes(struct object *obj, const EVP_PKEY *key)
{
    struct attr *attr = &obj->attributes;
    DBG("Key: %lu", obj->object_id);
    struct storage *store;
    if (EVP_PKEY_get_base_id(key) == EVP_PKEY_RSA) {
        ATTR_ADD_ULONG(attr, CKA_KEY_TYPE, CKK_RSA);
        ATTR_ADD_ULONG(attr, CKA_MODULUS_BITS, EVP_PKEY_bits(key));
        ATTR_ADD(attr, CKA_ALLOWED_MECHANISMS, rsa_mechs, sizeof rsa_mechs, 0);
        store = storage_PKEY(key, OSSL_PKEY_PARAM_RSA_N);
        ATTR_ADD_STORAGE(attr, CKA_MODULUS, store);
        store = storage_PKEY(key, OSSL_PKEY_PARAM_RSA_E);
        ATTR_ADD_STORAGE(attr, CKA_PUBLIC_EXPONENT, store);
    }
    if (EVP_PKEY_get_base_id(key) == EVP_PKEY_EC) {
        ATTR_ADD_ULONG(attr, CKA_KEY_TYPE, CKK_EC);
        ATTR_ADD(attr, CKA_ALLOWED_MECHANISMS, ec_mechs, sizeof ec_mechs, 0);

#if 0
        const OSSL_PARAM *pa = EVP_PKEY_gettable_params(key);
    while (pa && pa->key) {
        DBG("Param: %s Type: %d", pa->key, pa->data_type);
       pa++;
    }
#endif
        unsigned char buf[1024], *ptr = buf;
        size_t len = sizeof buf;
        char grpname[256];
        if (EVP_PKEY_get_group_name(key, grpname, sizeof grpname, NULL) > 0) {
            DBG("EC group name: %s", grpname);
            int nid = OBJ_txt2nid(grpname);
            EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
            if (group) {
                len = i2d_ECPKParameters(group, &ptr);
                if (len > 0) {
                    ATTR_ADD(attr, CKA_EC_PARAMS, buf, len, 1);
                } else {
                    DBG("Failed to convert EC parameters to DER");
                }
                EC_GROUP_free(group);
            }
        }
        EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_EC_GENERATOR,
                                        buf, sizeof buf, &len);
        DBG("EC generator length: %zu", len);
        if (len == 0 || len > sizeof buf) {
            DBG("Cannot get EC generator size: %zu", len);
            return CKR_HOST_MEMORY;
        }
        ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
        ASN1_STRING_set(os, buf, len);
        ptr = buf +len;
        int ret = i2d_ASN1_OCTET_STRING(os, &ptr);
        ASN1_OCTET_STRING_free(os);
        if (ret < 0) {
            DBG("Cannot convert EC generator to DER");
            return CKR_GENERAL_ERROR;
        }
        ATTR_ADD(attr, CKA_EC_POINT, buf +len, ret, 1);
    }
    return CKR_OK;
}
