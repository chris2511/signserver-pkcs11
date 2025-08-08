/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "signserver-pkcs11.h"
#include "session.h"

#include <curl/curl.h>
#include <curl/easy.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>

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
        case CKM_ECDSA_SHA256:
        case CKM_ECDSA_SHA384:
        case CKM_ECDSA_SHA512:
            return "NONEwithECDSA";
        default:
            return "";
    }
}

/*
 * Extremely simple, dumb, but sufficient JSON parser: find base64 value by key
 * Assumptions:
 * - Theres is no other key that starts with the same string
 * - The value is a base64 encoded string
 */
static ck_rv_t extract_json(BIO *bio, const char *key,
    unsigned char *binary, unsigned long *len)
{
    char *json;
    BIO_write(bio, "", 1); // Null terminate
    BIO_get_mem_data(bio, &json);
    size_t key_len = strlen(key);

    const char *start = json, *end = NULL;
    do {
        start = strstr(start, key);
        if (!start) break;
        if (start <= json || start[-1] != '"' || start[key_len] != '"')
            continue;
        start = strchr(start + key_len +1, ':'); // find : after key
        if (start) start = strchr(start + 1, '"'); // find " after key
        if (start) end = strchr(++start, '"');
        if (end) break;
    } while (!end);
    if (!start || !end) {
        ERR("Key '%s' not found in JSON response", key);
        return CKR_FUNCTION_FAILED;
    }
    int b64len = end - start;
    DBG("Extracted JSON value for key '%s' %d: %.*s", key, b64len, b64len, start);

    // OpenSSL needs at most 2 more bytes than actually required, because it always
    // adds the padding null byte to the decoded value and we need to calculate the
    // correct length of the base64 value ourselves, depending on the trailinbg '='
    // the incoming buffer may be just too small for the 2 bytes.
    unsigned char *buf = malloc(b64len /4 *3 +1);
    if (!buf) {
        ERR("Failed to allocate memory for base64 value");
        return CKR_HOST_MEMORY;
    }
    int l = EVP_DecodeBlock(buf, (const unsigned char *)start, b64len);
    if (end[-1] == '=') l--;
    if (end[-2] == '=') l--;

    if (*len < (unsigned long)l) {
        ERR("Invalid Signature len: %lu (%d,%d) for key '%s'", *len, l, b64len, key);
        free(buf);
        return CKR_BUFFER_TOO_SMALL;
    }
    memcpy(binary, buf, l);
    *len = l;
    free(buf);
    return CKR_OK;
}

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    DBG2("write_cb: received %zu bytes %zu %zu", total, size, nmemb);
    BIO *bio = (BIO *)userdata;
    if (BIO_write(bio, ptr, total) != (int)total)
        return 0;
    return total;
}

static ck_rv_t run_curl_ossl_ctx(struct signature_op *sig, const struct slot *slot, int hashnid,
    unsigned char *md, unsigned long md_len, BIO *bio)
{
    DBG("Requesting signature for object %lu", sig->obj->object_id);

    if (md_len > EVP_MAX_MD_SIZE) {
        ERR("Message digest length %lu exceeds maximum %d", md_len, EVP_MAX_MD_SIZE);
        return CKR_HOST_MEMORY;
    }
    char url[1024];
    int len = snprintf(url, sizeof url,
        "%s/signserver/rest/v1/workers/%s/process?=", slot->url, slot->worker);
    if (len < 0 || len >= (int)sizeof url) {
        ERR("URL length %d exceeds maximum %zu", len, sizeof url);
        return CKR_ARGUMENTS_BAD;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        ERR("curl_easy_init failed");
        return CKR_FUNCTION_FAILED;
    }
    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    char request_json[4096];
    unsigned char b64[EVP_MAX_MD_SIZE *4 / 3 + 4];
    EVP_EncodeBlock(b64, md, md_len);

    snprintf(request_json, sizeof request_json, "{"
      "\"metaData\": {"
        "\"CLIENTSIDE_HASHDIGESTALGORITHM\": \"%s\","
        "\"SIGNATUREALGORITHM\": \"%s\","
        "\"USE_CLIENTSUPPLIED_HASH\": true"
      "},"
      "\"encoding\": \"BASE64\","
      "\"data\": \"%s\""
    "}",
    OBJ_nid2sn(hashnid), mechanism_to_signserver_algo(sig->mechanism), b64);

    DBG2("Request JSON: '%s'", request_json);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_json);

    // Enable verbose output for debugging
    if (debug_level > 2)
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, slot->verify_peer);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, slot->verify_peer);

    // Client-Zertifikat (P12) und Passwort
    curl_easy_setopt(curl, CURLOPT_SSLCERT, slot->auth_cert);
    curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "P12");
    curl_easy_setopt(curl, CURLOPT_KEYPASSWD, slot->auth_pass);

    curl_easy_setopt(curl, CURLOPT_WRITEDATA, bio);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        ERR("curl_easy_perform() failed: %s", curl_easy_strerror(res));
        return CKR_FUNCTION_FAILED;
    }
    INFO("HTTP response code of '%s': %ld", url, http_code);
    // Dump bio to stderr if http response != 200
    if (((debug_level > 0 && http_code != 200)) || debug_level > 2) {
        char *data;
        long len = BIO_get_mem_data(bio, &data);
        if (len > 0) {
            if (http_code != 200) {
                ERR("HTTP error %ld: %.*s", http_code, (int)len, data);
            } else {
                DBG("HTTP response %ld: %.*s", http_code, (int)len, data);
            }
        } else {
            ERR("No response data received.");
        }
    }
    return http_code == 200 ? CKR_OK : CKR_FUNCTION_FAILED;
}

static ck_rv_t run_curl(struct signature_op *sig, const struct slot *slot, int hashnid,
    unsigned char *md, unsigned long md_len, BIO *bio)
{
    OSSL_LIB_CTX *octx, *nctx = OSSL_LIB_CTX_new();

    octx = nctx ? OSSL_LIB_CTX_set0_default(nctx) : NULL;

    ck_rv_t r = run_curl_ossl_ctx(sig, slot, hashnid, md, md_len, bio);

    if (nctx) {
        OSSL_LIB_CTX_set0_default(octx);
        OSSL_LIB_CTX_free(nctx);
    }
    return r;
}

ck_rv_t plainsign(struct signature_op *sig, const struct slot *slot, int hashnid,
    unsigned char *md, unsigned long md_len,
    unsigned char *signature, unsigned long *signature_len)
{
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        OSSL_ERR("BIO_new(BIO_s_mem()) failed");
        return CKR_FUNCTION_FAILED;
    }
    ck_rv_t rv = run_curl(sig, slot, hashnid, md, md_len, bio);
    if (rv != CKR_OK) {
        BIO_free(bio);
        return rv;
    }
    rv = extract_json(bio, "data", signature, signature_len);
    BIO_free(bio);
    return rv;
}
