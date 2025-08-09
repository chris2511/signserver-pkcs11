/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#include "slot.h"
#include "link.h"
#include "object.h"
#include "signature.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openssl/pem.h>
#include <openssl/err.h>

void slot_free(struct slot *slot)
{
    for (int i = 0; i < OBJECT_TYPE_MAX; i++)
        object_free(slot->objects +i);
    if (slot->certificate)
        X509_free(slot->certificate);
    if (slot->private)
        EVP_PKEY_free(slot->private);
    memset(slot, 0, sizeof(struct slot));
}

const char *slot_get_ini_entry(const struct slot *slot,
    const char *key, const char *def)
{
    char section[MAX_SECTION_NAME + 64];
    snprintf(section, sizeof section, "%s:%s", slot->name, key);
    DBG("INI entry key: '%s'", section);
    return iniparser_getstring(slot->ini, section, def);
}

static int slot_init(struct slot *slot)
{
    DBG("Scanning section %d: '%s'", slot->section_idx, slot->name);
    slot->auth_cert = slot_get_ini_entry(slot, "AuthCert", NULL);
    slot->auth_pass = slot_get_ini_entry(slot, "AuthPass", "");
    slot->worker = slot_get_ini_entry(slot, "WorkerName", "");
    slot->url = slot_get_ini_entry(slot, "url", NULL);
    slot->cka_id = slot_get_ini_entry(slot, "cka_id", NULL);
    const char *verify_peer_str = slot_get_ini_entry(slot, "VerifyPeer", "True");
    slot->verify_peer = strcasecmp(verify_peer_str, "True") == 0 ||
                        strcasecmp(verify_peer_str, "1") == 0 ||
                        strcasecmp(verify_peer_str, "yes") == 0 ||
                        strcasecmp(verify_peer_str, "on") == 0;

    const char *certfile = slot_get_ini_entry(slot, "Certificate", NULL);
    if (certfile) {
        DBG("Certificate file for slot '%s': '%s'", slot->name, certfile);
        FILE *fp = fopen(certfile, "r");
        if (!fp) {
            ERR("Cannot open certificate file '%s': %s", certfile, strerror(errno));
            return CKR_FUNCTION_FAILED;
        }
        slot->certificate = PEM_read_X509(fp, NULL, NULL, NULL);
        rewind(fp);
        slot->private = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
        fclose(fp);
    } else {
        slot->certificate = retrieve_certificate(slot);
    }
    if (!slot->certificate) {
        ERR("No certificate available for slot '%s'", slot->name);
        return CKR_FUNCTION_FAILED;
    }
    if (slot->private)
        INFO("Private software key loaded for slot '%s'", slot->name);

    const EVP_PKEY *key = X509_get0_pubkey(slot->certificate);
    if (!key) {
        OSSL_ERR("Cannot get public key from certificate");
        return CKR_FUNCTION_FAILED;
    }
    slot->keytype = EVP_PKEY_base_id(key);
    return CKR_OK;
}

static int slot_init_objects(struct slot *slot)
{
    ck_rv_t ret = CKR_OK;

    for (int i = 0; i < OBJECT_TYPE_MAX; i++) {
        ret = object_new(slot, slot->objects + i, (enum object_type)i );
        struct attr *attr = &slot->objects[i].attributes;
        if (ret != CKR_OK) {
            ERR("Failed to create object %d for slot '%s': %lu", i, slot->name, ret);
            break;
        }
        ATTR_ADD(attr, CKA_LABEL, slot->name, strlen(slot->name), 0);
        BIGNUM *id_hex = NULL;
        if (slot->cka_id) {
            if ((size_t)BN_hex2bn(&id_hex, slot->cka_id) != strlen(slot->cka_id)) {
                ERR("Failed to convert CKA_ID '%s' to BIGNUM", slot->cka_id);
                BN_free(id_hex);
                return CKR_ARGUMENTS_BAD;
            }
        } else {
            id_hex = BN_new();
            if (!id_hex) {
                ERR("Failed to allocate BIGNUM for slot ID");
                return CKR_HOST_MEMORY;
            }
            BN_set_word(id_hex, slot->id +0x1000000);
        }
        struct storage *id_store = storage_BN(id_hex); // free()s id_hex
        if (id_store)
            ATTR_ADD_STORAGE(attr, CKA_ID, id_store); // free()s id_store

        DBG("Object %d for slot '%s' initialized", i, slot->name);
    }
    return ret;
}

ck_rv_t slot_scan(dictionary *ini, const char *filename,
            struct slot *slots, ck_slot_id_t *n_slots)
{
    *n_slots = 0;
    int sections = iniparser_getnsec(ini);
    for (int i = 0; i < sections; i++) {
        struct slot *slot = slots + (*n_slots);
        if (*n_slots >= MAX_SLOTS) {
            ERR("Too much Slot sections in '%s'. Max %d\n",
                filename, MAX_SLOTS);
            return CKR_HOST_MEMORY;
        }
        slot->name = iniparser_getsecname(ini, i);
        slot->section_idx = i;
        slot->id = *n_slots;
        slot->ini = ini;

        if (strcasecmp(slot_get_ini_entry(slot, "SignServer", ""), "true")) {
            INFO("Skipping section '%s' as it is not a SignServer slot",
                slot->name);
            continue;
        }
        if (strlen(slot->name) > MAX_SECTION_NAME) {
            ERR("Section name too long: '%s'", slot->name);
            return CKR_HOST_MEMORY;
        }
        if (slot_init(slot) != CKR_OK) {
            ERR("Failed to initialize slot '%s'", slot->name);
            continue;
        }
        if (slot_init_objects(slot) != CKR_OK) {
            ERR("Failed to initialize objects for slot '%s'", slot->name);
            continue;
        }
        *n_slots += 1;
    }
    return CKR_OK;
}
