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
