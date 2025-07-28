/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */
 
#include "slot.h" 
#include "link.h" 
#include "object.h" 

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
    memset(slot, 0, sizeof(struct slot));
    if (slot->pin) {
        storage_free(slot->pin);
        slot->pin = NULL;
    }
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
    const char *certfile = slot_get_ini_entry(slot, "Certificate", NULL);
    if (!certfile) {
        DBG("No certificate file specified for slot '%s'", slot->name);
        return CKR_FUNCTION_FAILED;
    }
    DBG("Certificate file for slot '%s': '%s'", slot->name, certfile);
    FILE *fp = fopen(certfile, "r");
    if (!fp) {
        DBG("Cannot open certificate file '%s': %s", certfile, strerror(errno));
        return CKR_FUNCTION_FAILED;
    }
    slot->certificate = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!slot->certificate) {
        char errbuf[256];
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof errbuf);
        DBG("Cannot read certificate from '%s': %s", certfile, errbuf);
        return CKR_FUNCTION_FAILED;
    }
    slot->auth_cert = slot_get_ini_entry(slot, "AuthCert", NULL);
    slot->auth_pass = slot_get_ini_entry(slot, "AuthPass", "");
    slot->worker = slot_get_ini_entry(slot, "WorkerName", "PlainSigner");
    slot->url = slot_get_ini_entry(slot, "url", NULL);
    slot->label = slot_get_ini_entry(slot, "Label", NULL);

    return CKR_OK;
}

static int slot_init_objects(struct slot *slot)
{
    for (int i = 0; i < OBJECT_TYPE_MAX; i++) {
        ck_rv_t ret = object_new(slot->objects + i,
            (enum object_type)i, slot->certificate);
        if (ret != CKR_OK) {
            DBG("Failed to create object %d for slot '%s': %lu", i, slot->name, ret);
            return ret;
        }
        ATTR_ADD(&slot->objects[i].attributes, CKA_LABEL, slot->label, strlen(slot->label), 0);
        ATTR_ADD_ULONG(&slot->objects[i].attributes, CKA_ID, 0x4711);
    }
    return CKR_OK;
}

ck_rv_t slot_scan(dictionary *ini, const char *filename,
            struct slot *slots, ck_slot_id_t *n_slots)
{
    *n_slots = 0;
    int sections = iniparser_getnsec(ini);
    for (int i = 0; i < sections; i++) {
        struct slot *slot = slots + (*n_slots);
        if (*n_slots >= MAX_SLOTS) {
            DBG("Too much Slot sections in '%s'. Max %d\n",
                filename, MAX_SLOTS);
            return CKR_HOST_MEMORY;
        }
        slot->name = iniparser_getsecname(ini, i);
        slot->section_idx = i;
        slot->id = *n_slots;
        slot->ini = ini;

        if (strcasecmp(slot_get_ini_entry(slot, "SignServer", ""), "true")) {
            DBG("Skipping section '%s' as it is not a SignServer slot",
                slot->name);
            continue;
        }
        if (strlen(slot->name) > MAX_SECTION_NAME) {
            DBG("Section name too long: '%s'", slot->name);
            return CKR_HOST_MEMORY;
        }
        if (slot_init(slot) != CKR_OK) {
            DBG("Failed to initialize slot '%s'", slot->name);
            continue;
        }
        if (slot_init_objects(slot) != CKR_OK) {
            DBG("Failed to initialize objects for slot '%s'", slot->name);
            continue;
        }
        *n_slots += 1;
    }
    return CKR_OK;
}
