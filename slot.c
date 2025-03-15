/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */
 
#include "slot.h" 
#include <stdlib.h>
#include <string.h>

void slot_free(struct slot *slot)
{
    if (slot->keys)
        free(slot->keys);
    if (slot->name)
        free(slot->name);
    memset(slot, 0, sizeof(struct slot));
}

static int key_scanner_cb(key_serial_t parent, key_serial_t key,
                          char *desc, int desc_len, void *data)
{
    struct slot *slot = data;
    DBG("Slot %lu(%d) KEY %d %s", slot->id, slot->keyring , key, desc);
    int ret = 0;
    if (slot->n_keys < MAX_KEYS && parent != 0) {
        ret = key_init(slot->keys + slot->n_keys, key, desc, desc_len);
        if (ret > 0)
            slot->n_keys++ ;
        DBG("Key(%d) init = %d %lu", key, ret, slot->n_keys);
    }
    return ret;
}

ck_rv_t slot_load_keys(struct slot *slot)
{
    if (slot->keys)
        return CKR_OK;
    slot->keys = calloc(MAX_KEYS, sizeof(struct key));
    if (!slot->keys)
        return CKR_HOST_MEMORY;
    long r = recursive_key_scan(slot->keyring, key_scanner_cb, slot);
    DBG("Slot: %lu(%d) Found %ld keys", slot->id, slot->keyring, r);
    return CKR_OK;
}

struct keyring_data {
    struct slot *slot;
    ck_slot_id_t n_slots;
};
 
static int keyring_scanner_cb(key_serial_t parent, key_serial_t key,
                              char *desc, int desc_len, void *data)
{
    (void)desc_len;
    struct keyring_data *kd = data;
    struct slot *slot = kd->slot + kd->n_slots;
    DBG("KEYRING %d %s", key, desc);
    if (parent == 0 || strncmp(desc, "keyring;", 8u) != 0)
        return 0;
    if (kd->n_slots >= MAX_SLOTS)
        return 0;
    DBG("Slot (%lu) Found KEYRING %d %s", kd->n_slots, key, desc);
    slot->keyring = key;
    slot->id = kd->n_slots;
    slot->name = dup_keyname(desc);
    slot_load_keys(slot);
    kd->n_slots++;

    return 1;
}

ck_rv_t slot_scan(int key_spec_keyring, struct slot *slots, ck_slot_id_t *n_slots)
{
    struct keyring_data kd = { slots, *n_slots };
    long r = recursive_key_scan(key_spec_keyring, keyring_scanner_cb, &kd);
    DBG("Found %ld keyrings", r);
    *n_slots = kd.n_slots;
    return r < 0 ? CKR_GENERAL_ERROR : CKR_OK;
}
