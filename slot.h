/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _SLOT_H
#define _SLOT_H 1

#include "iniparser.h"
#include "object.h"
#include <openssl/x509.h>

struct slot {
    ck_slot_id_t id;
    const char *name;
    int section_idx;
    dictionary *ini;
    /* Key management */
    X509 *certificate;
    const char *auth_cert;
    const char *auth_pass;
    const char *worker;
    const char *url;
    const char *label;
    struct storage *pin;
    struct object objects[OBJECT_TYPE_MAX];
    
};

void slot_free(struct slot *slot);
ck_rv_t slot_scan(dictionary *ini, const char *filename, struct slot *slots, ck_slot_id_t *n_slots);
const char *slot_get_ini_entry(const struct slot *slot, const char *key, const char *def);

#endif
