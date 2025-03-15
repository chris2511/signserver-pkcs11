/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _SLOT_H
#define _SLOT_H 1

#include "keyutil-pkcs11.h"
#include "object.h"
#include "link.h"

struct slot {
    ck_slot_id_t id;
    char *name;
    /* Keyring */
    key_serial_t keyring;
    /* Key management */
    unsigned long n_objects;
    struct object *objects;
    struct link *links;
};

void slot_free(struct slot *slot);
ck_rv_t slot_scan(int key_spec_keyring, struct slot *slots, ck_slot_id_t *n_slots);
void slot_link_objects(struct slot *slot);

#endif
