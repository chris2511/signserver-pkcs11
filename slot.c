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
    struct object *obj, *next;
    for (obj = slot->objects; obj; obj = next) {
        next = obj->next;
        object_free(obj);
    }
    memset(slot, 0, sizeof(struct slot));
}

#define SLOT_ID_OFFSET 9593
ck_rv_t slot_scan(dictionary *ini, const char *filename,
            struct slot *slots, ck_slot_id_t *n_slots)
{
    *n_slots = 0;
    int sections = iniparser_getnsec(ini);
    if (sections < 1 || sections > MAX_SLOTS) {
        DBG("Invalid number of sections (%d) in '%s' expected 1 - %d\n",
            sections, filename, MAX_SLOTS);
        return CKR_HOST_MEMORY;
    }
    for (int i = 0; i < sections; i++) {
        struct slot *slot = slots + (*n_slots);
        char key[MAX_SECTION_NAME +64];
        slot->name = iniparser_getsecname(ini, i);
        size_t len = strlen(slot->name);
        if (len > MAX_SECTION_NAME) {
            DBG("Section name too long: '%s'", slot->name);
            return CKR_HOST_MEMORY;
        }
        DBG("Scanning section %d: '%s'", i, slot->name);
        memcpy(key, slot->name, len);
        key[len++] = ':';
        slot->name = iniparser_getsecname(ini, i);
        slot->section_idx = i;
        slot->id = *n_slots;
        memcpy(key + len, "Certificate", sizeof "Certificate");
        DBG("Certificate key: '%s'", key);
        const char *certfile = iniparser_getstring(ini, key, NULL);
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
        memcpy(key + len, "AuthCert", sizeof "AuthCert");
        slot->auth_cert = iniparser_getstring(ini, key, NULL);
        memcpy(key + len, "AuthPass", sizeof "AuthPass");
        slot->auth_pass = iniparser_getstring(ini, key, "");
        memcpy(key + len, "WorkerName", sizeof "WorkerName");
        slot->worker = iniparser_getstring(ini, key, "PlainSigner");
        memcpy(key + len, "url", sizeof "url");
        slot->url = iniparser_getstring(ini, key, NULL);

        *n_slots += 1;
    }
    return CKR_OK;
}
