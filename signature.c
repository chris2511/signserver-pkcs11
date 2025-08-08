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
        case CKM_ECDSA_SHA256:
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS_PSS:
            return NID_sha256;
        case CKM_ECDSA_SHA384:
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS_PSS:
            return NID_sha384;
        case CKM_ECDSA_SHA512:
        case CKM_SHA512_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS_PSS:
            return NID_sha512;
        case CKM_ECDSA:
        case CKM_RSA_PKCS:
        case CKM_RSA_PKCS_PSS:
            return NID_undef;
        default:
            ERR("Unsupported mechanism %lu", mech);
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

static int mechanism_is_pkcsv15(ck_mechanism_type_t mech)
{
    return mech == CKM_RSA_PKCS;
}

void signature_op_free(struct signature_op *op)
{
    if (op->bio)
        BIO_free_all(op->bio);
    memset(op, 0, sizeof *op);
}

ck_rv_t signature_op_init(struct signature_op *sig)
{
    if (!sig)
        return CKR_ARGUMENTS_BAD;
    int nid = mechanism_to_hashnid(sig->mechanism);
    DBG("Object %lu with mechanism 0x%lx -> Nid: %d (%s)",
        sig->obj->object_id, sig->mechanism, nid, OBJ_nid2sn(nid));

    if (nid != NID_undef) {
        // The BIO_f_md() needs a BIO to write to, so we use a null BIO
        BIO *null = BIO_new(BIO_s_null());
        sig->bio = BIO_push(BIO_new(BIO_f_md()), null);
        if (sig->bio) {
            if (!BIO_set_md(sig->bio, EVP_get_digestbynid(nid)))
                return CKR_GENERAL_ERROR;
        }
        DBG("Using digest %d (%s) for mechanism %lu",
            nid, OBJ_nid2sn(nid), sig->mechanism);
    } else {
        sig->bio = BIO_new(BIO_s_mem());
    }
    if (!sig->bio) {
        ERR("Failed to create MEM BIO");
        return CKR_HOST_MEMORY;
    }
    return CKR_OK;
}

ck_rv_t signature_op_update(struct signature_op *sig,
        unsigned char *part, unsigned long part_len)
{
    DBG("Update signature for object %lu with %lu bytes",
        sig->obj->object_id, part_len);
    if (!sig || !sig->bio || !part || part_len == 0) {
        ERR("Invalid arguments for key_sign_update");
        return CKR_ARGUMENTS_BAD;
    }
    return BIO_write(sig->bio, part, part_len) >= 0 ?
        CKR_OK : CKR_FUNCTION_FAILED;
}

static int unpack_pkcs15_signature(struct signature_op *sig)
{
    DBG("Unpacking PKCS#1 v1.5 envelope %lu", sig->obj->object_id);
    const unsigned char *data;
    long len = BIO_get_mem_data(sig->bio, &data);

    X509_SIG *xsig = d2i_X509_SIG(NULL, &data, len);
    if (!xsig) {
        ERR("Failed to unpack PKCS#1 v1.5 envelope");
        return NID_undef;
    }
    BIO_reset(sig->bio);
    const ASN1_OCTET_STRING *digest;
    const X509_ALGOR *algor;
    X509_SIG_get0(xsig, &algor, &digest);
    BIO_write(sig->bio, digest->data, digest->length);

    // extract hashnid before freeing xsig
    int hashnid = OBJ_obj2nid(algor->algorithm);
    X509_SIG_free(xsig);
    return hashnid;
}

static int padding_from_mechanism(ck_mechanism_type_t mech)
{
    switch (mech) {
        case CKM_RSA_PKCS:
        case CKM_SHA1_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS:
            return RSA_PKCS1_PADDING;
        case CKM_RSA_PKCS_PSS:
        case CKM_SHA1_RSA_PKCS_PSS:
        case CKM_SHA256_RSA_PKCS_PSS:
        case CKM_SHA384_RSA_PKCS_PSS:
        case CKM_SHA512_RSA_PKCS_PSS:
            return RSA_PKCS1_PSS_PADDING;
        default:
            return -1;
    }
}

static ck_rv_t swsign(struct signature_op *sig, const struct slot *slot, int hashnid,
    unsigned char *md, unsigned long md_len,
    unsigned char *signature, unsigned long *signature_len)
{
    DBG("Using private key for slot '%s' to sign", slot->name);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(slot->private, NULL);
    if (!ctx) {
        OSSL_ERR("Failed to create EVP_PKEY_CTX");
        return CKR_HOST_MEMORY;
    }
    if (EVP_PKEY_sign_init(ctx) <= 0){
        ERR("Failed to initialize signing operation");
        EVP_PKEY_CTX_free(ctx);
        return CKR_GENERAL_ERROR;
    }
    int padding = padding_from_mechanism(sig->mechanism);
    if (padding > 0) {
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
            OSSL_ERR("Failed to set RSA padding");
            EVP_PKEY_CTX_free(ctx);
            return CKR_GENERAL_ERROR;
        }
    }
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_get_digestbynid(hashnid)) <= 0){
        ERR("Failed to set signature MD %d (%s)", hashnid, OBJ_nid2sn(hashnid));
        EVP_PKEY_CTX_free(ctx);
        return CKR_GENERAL_ERROR;
    }
    if (EVP_PKEY_sign(ctx, signature, signature_len, md, md_len) <= 0) {
        OSSL_ERR("EVP_PKEY_sign failed");
        EVP_PKEY_CTX_free(ctx);
        return CKR_FUNCTION_FAILED;
    }
    EVP_PKEY_CTX_free(ctx);
    INFO("Signature created with hashnid %d (%s) and %lu bytes",
        hashnid, OBJ_nid2sn(hashnid), *signature_len);
    return CKR_OK;
}

ck_rv_t signature_op_final(struct signature_op *sig, const struct slot *slot,
        unsigned char *signature, unsigned long *signature_len)
{
    BIO_flush(sig->bio);
    int hashnid = mechanism_is_pkcsv15(sig->mechanism) ?
        unpack_pkcs15_signature(sig) : mechanism_to_hashnid(sig->mechanism);

    DBG("Object %lu with mechanism 0x%lx -> Nid: %d (%s)",
        sig->obj->object_id, sig->mechanism, hashnid, OBJ_nid2sn(hashnid));

    int md_len;
    unsigned char md[EVP_MAX_MD_SIZE];
    switch (BIO_method_type(sig->bio)) {
    case BIO_TYPE_MEM:
        md_len = BIO_read(sig->bio, md, sizeof md);
        DBG("Read %d bytes from MEM BIO", md_len);
        break;
    case BIO_TYPE_MD:
        md_len = BIO_gets(sig->bio, (char*)md, sizeof md);
        DBG("Read %d bytes from MD BIO", md_len);
        break;
    default:
        ERR("Unsupported BIO type %d", BIO_method_type(sig->bio));
        return CKR_GENERAL_ERROR;
    }
    if (md_len <= 0) {
        OSSL_ERR("BIO_gets/read failed");
        return CKR_FUNCTION_FAILED;
    }
    if (hashnid == NID_undef) {
        INFO("No hash algorithm for mechanism %lu - guessing", sig->mechanism);
        hashnid = estimate_hash_nid(md_len);
    }
    DBG("Calling plainsign with hashnid %d (%s) and %u bytes",
        hashnid, OBJ_nid2sn(hashnid), md_len);

    ck_rv_t ret = slot->private ?
        swsign(sig, slot, hashnid, md, md_len, signature, signature_len) :
        plainsign(sig, slot, hashnid, md, md_len, signature, signature_len);

    if (slot->objects[0].keytype == EVP_PKEY_EC) {
        const unsigned char *ptr = signature;
        // Need to convert the ECDSA_SIG to concatenated r+s format
        // signature was large enough to hold the ECDSA_SIG,
        // it will bear the smaller r+s
        ECDSA_SIG *sig_ec = d2i_ECDSA_SIG(NULL, &ptr, *signature_len);
        if (!sig_ec) {
            OSSL_ERR("Failed to unpack ECDSA signature");
            return CKR_FUNCTION_FAILED;
        }
        int r_len = BN_num_bytes(ECDSA_SIG_get0_r(sig_ec));
        int s_len = BN_num_bytes(ECDSA_SIG_get0_s(sig_ec));
        // r and s must always be the same size. Pad the smaller one.
        int maxlen = r_len < s_len ? s_len : r_len;
        if (*signature_len < maxlen *2U) {
            ERR("Invalid Signature len: %lu (%d,%d) for key '%s'",
                *signature_len, r_len, s_len, slot->name);
            ECDSA_SIG_free(sig_ec);
            return CKR_FUNCTION_FAILED;
        }
        *signature_len = 2 * maxlen;
        memset(signature, 0, *signature_len);
        /* right align the numbers in their half */
        BN_bn2bin(ECDSA_SIG_get0_r(sig_ec), signature + (maxlen - r_len));
        BN_bn2bin(ECDSA_SIG_get0_s(sig_ec), signature + (2 * maxlen - s_len));
        ECDSA_SIG_free(sig_ec);
    }
    return ret;
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
        CKM_ECDSA_SHA256,
        CKM_ECDSA_SHA384,
        CKM_ECDSA_SHA512,
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
            ERR("Unsupported key type %d", obj->keytype);
            return CKR_KEY_TYPE_INCONSISTENT;
    }
    if (mechanism_list) {
        if (*count < n_mechs) {
            ERR("Buffer too small for %lu mechanisms %lu", n_mechs, *count);
            *count = n_mechs;
            return CKR_BUFFER_TOO_SMALL;
        }
        memcpy(mechanism_list, mechs, n_mechs * sizeof(ck_mechanism_type_t));
    }
    *count = n_mechs;
    return CKR_OK;
}

static ck_rv_t get_der_groupname(const EVP_PKEY *key,
    unsigned char *der, size_t *derlen)
{
    char grpname[256];
    if (EVP_PKEY_get_group_name(key, grpname, sizeof grpname, NULL) <= 0){
        OSSL_ERR("Failed to get EC group name");
        return CKR_GENERAL_ERROR;
    }
    DBG("EC group name: %s", grpname);
    EC_GROUP *group = EC_GROUP_new_by_curve_name(OBJ_txt2nid(grpname));
    if (!group) {
        OSSL_ERR("Failed to create EC_GROUP from name");
        return CKR_GENERAL_ERROR;
    }

    if ((size_t)i2d_ECPKParameters(group, NULL) < *derlen)
        *derlen = i2d_ECPKParameters(group, &der);
    else
        *derlen= 0;

    EC_GROUP_free(group);
    return *derlen > 0 ? CKR_OK : CKR_GENERAL_ERROR;
}

ck_rv_t get_der_ec_point(const EVP_PKEY *key, unsigned char *der, size_t *derlen)
{
    size_t len;
    unsigned char buf[256];
    EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                    buf, sizeof buf, &len);
    DBG("EC generator length: %zu", len);

    if (len > sizeof buf)
        return CKR_HOST_MEMORY;

    ASN1_OCTET_STRING *point = ASN1_OCTET_STRING_new();
    if (!point)
        return CKR_HOST_MEMORY;
    ASN1_STRING_set(point, buf, len);

    if ((size_t)i2d_ASN1_OCTET_STRING(point, NULL) < *derlen)
        *derlen = i2d_ASN1_OCTET_STRING(point, &der);
    else
        *derlen = 0;
    ASN1_OCTET_STRING_free(point);
    return *derlen > 0 ? CKR_OK : CKR_GENERAL_ERROR;
}

ck_rv_t key_collect_key_attributes(struct object *obj, const EVP_PKEY *key)
{
    struct attr *attr = &obj->attributes;
    DBG("Key: %lu", obj->object_id);
    struct storage *store;
    if (obj->keytype == EVP_PKEY_RSA) {
        ATTR_ADD_ULONG(attr, CKA_KEY_TYPE, CKK_RSA);
        ATTR_ADD_ULONG(attr, CKA_MODULUS_BITS, EVP_PKEY_bits(key));
        ATTR_ADD(attr, CKA_ALLOWED_MECHANISMS, rsa_mechs, sizeof rsa_mechs, 0);
        store = storage_PKEY(key, OSSL_PKEY_PARAM_RSA_N);
        ATTR_ADD_STORAGE(attr, CKA_MODULUS, store);
        store = storage_PKEY(key, OSSL_PKEY_PARAM_RSA_E);
        ATTR_ADD_STORAGE(attr, CKA_PUBLIC_EXPONENT, store);
        return CKR_OK;
    }
    if (obj->keytype == EVP_PKEY_EC) {
        ATTR_ADD_ULONG(attr, CKA_KEY_TYPE, CKK_EC);
        ATTR_ADD(attr, CKA_ALLOWED_MECHANISMS, ec_mechs, sizeof ec_mechs, 0);

        unsigned char der[256];
        size_t len = sizeof der;
        ck_rv_t rv = get_der_groupname(key, der, &len);
        if (rv == CKR_OK) {
            ATTR_ADD(attr, CKA_EC_PARAMS, der, len, 1);
            len = sizeof der;
            rv = get_der_ec_point(key, der, &len);
        }
        if (rv == CKR_OK)
            ATTR_ADD(attr, CKA_EC_POINT, der, len, 1);
        return rv;
    }
    return CKR_GENERAL_ERROR;
}
