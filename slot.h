/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _SLOT_H
#define _SLOT_H 1

#include "keyutil-pkcs11.h"
#include "key.h"

struct slot {
    ck_slot_id_t id;
    char *name;
    /* Keyring */
    key_serial_t keyring;
    /* Key management */
    unsigned long n_keys;
    struct key *keys;
};

ck_rv_t slot_load_keys(struct slot *slot);
void slot_free(struct slot *slot);
ck_rv_t slot_scan(int key_spec_keyring, struct slot *slots, ck_slot_id_t *n_slots);

#endif
