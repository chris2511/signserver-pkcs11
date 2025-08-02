#include <curl/curl.h>
#include <curl/easy.h>

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
#include <openssl/bio.h>
#include <openssl/buffer.h>

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

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    BIO *bio = (BIO *)userdata;
    if (BIO_write(bio, ptr, total) != (int)total)
        return 0;
    return total;
}

ck_rv_t plainsign(struct signature_op *sig, const struct slot *slot, int hashnid,
    unsigned char *signature, unsigned long *signature_len)
{
    DBG("Requesting signature for object %lu", sig->obj->object_id);

    CURL *curl = curl_easy_init();
    if (!curl) {
        DBG("curl_easy_init failed");
        return CKR_FUNCTION_FAILED;
    }

    CURLcode res;
    curl_mime *mime = curl_mime_init(curl);
    curl_mimepart *part;

    // workerName
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "workerName");
    curl_mime_data(part, slot->worker, CURL_ZERO_TERMINATED);

    // data (direkt aus Speicher, explizit als application/octet-stream)
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "data");
    curl_mime_data(part, (const char*)sig->bm->data, sig->bm->length);
    curl_mime_type(part, "application/octet-stream");
    curl_mime_filename(part, "file");

    // REQUEST_METADATA.CLIENTSIDE_HASHDIGESTALGORITHM
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "REQUEST_METADATA.CLIENTSIDE_HASHDIGESTALGORITHM");
    curl_mime_data(part, OBJ_nid2sn(hashnid), CURL_ZERO_TERMINATED);

    // REQUEST_METADATA.USE_CLIENTSUPPLIED_HASH
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "REQUEST_METADATA.USE_CLIENTSUPPLIED_HASH");
    curl_mime_data(part, "true", CURL_ZERO_TERMINATED);

    // REQUEST_METADATA.SIGNATUREALGORITHM
    part = curl_mime_addpart(mime);
    curl_mime_name(part, "REQUEST_METADATA.SIGNATUREALGORITHM");
    curl_mime_data(part, mechanism_to_signserver_algo(sig->mechanism), CURL_ZERO_TERMINATED);

    char url[1024];
    snprintf(url, sizeof url, "%s/signserver/process", slot->url);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    // Enable verbose output for debugging
    if (dbg > 0)
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    // Client-Zertifikat (P12) und Passwort
    curl_easy_setopt(curl, CURLOPT_SSLCERT, slot->auth_cert);
    curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "P12");
    curl_easy_setopt(curl, CURLOPT_KEYPASSWD, slot->auth_pass);


    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        DBG("BIO_new(BIO_s_mem()) failed");
        curl_mime_free(mime);
        curl_easy_cleanup(curl);
        return CKR_FUNCTION_FAILED;
    }
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, bio);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);

    res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);

    // Dump bio to stderr if http response != 200
    if (dbg > 0 && http_code != 200) {
        char *data;
        long len = BIO_get_mem_data(bio, &data);
        fprintf(stderr, "HTTP response code: %ld\n", http_code);
        if (len > 0) {
            fprintf(stderr, "Response from server:\n%.*s\n", (int)len, data);
        } else {
            fprintf(stderr, "No response data received.\n");
        }
    }
    if (res != CURLE_OK) {
        DBG("curl_easy_perform() failed: %s", curl_easy_strerror(res));
        BIO_free(bio);
        return CKR_FUNCTION_FAILED;
    }

    BUF_MEM *bptr = NULL;
    BIO_get_mem_ptr(bio, &bptr);
    if (!bptr || bptr->length == 0) {
        DBG("No data received from server");
        BIO_free(bio);
        return CKR_FUNCTION_FAILED;
    }
    size_t copylen = bptr->length > *signature_len ? *signature_len : bptr->length;
    memcpy(signature, bptr->data, copylen);
    *signature_len = copylen;
    BIO_free(bio);
    return CKR_OK;
}
