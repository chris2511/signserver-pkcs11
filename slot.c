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

void slot_free(struct slot *slot)
{
    struct object *obj, *next;
    for (obj = slot->objects; obj; obj = next) {
        next = obj->next;
        object_free(obj);
    }
    struct link *link, *lnext;
    for (link = slot->links; link; link = lnext) {
        lnext = link->next;
        link_free(link);
    }
    if (slot->name)
        free(slot->name);

    memset(slot, 0, sizeof(struct slot));
}

static int key_scanner_cb(key_serial_t parent, key_serial_t object_id,
                          char *desc, int desc_len, void *data)
{
    (void)desc_len;
    struct slot *slot = data;
    DBG("Slot %lu(%d) KEY %d %s", slot->id, slot->keyring , object_id, desc);

    if (parent == 0)
        return 0;
    
    struct object *obj = object_new(object_id, desc);
    if (!obj)
        return 0;

    obj->next = slot->objects;
    slot->objects = obj;
    slot->n_objects++;
    DBG("Object[%lu](%d)",slot->n_objects, object_id);
    return 1;
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

    recursive_key_scan(slot->keyring, key_scanner_cb, slot);
    DBG("Slot: %lu(%d) Found %ld keys", slot->id, slot->keyring, slot->n_objects);
    kd->n_slots++;
    slot_link_objects(slot);
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

void slot_link_objects(struct slot *slot)
{
    struct object *obj;
    for (obj = slot->objects; obj; obj = obj->next) {
        struct link *link;
        const char *name = forward_to_colon(obj);
        DBG("Linking %s", name);
        for (link = slot->links; link; link = link->next) {
            if (strcmp(link->name, name) == 0)
                break;
        }
        if (!link) {
            link = link_new(name);
            if (link) {
                link->next = slot->links;
                slot->links = link;
            }
        }
        obj->do_link(obj, link);
    }
    for (obj = slot->objects; obj; obj = obj->next) {
        DBG("Collect Attributes for Kernel:%d '%s' type:%d Link:'%s'",
            obj->object_id, obj->name, obj->type,
            obj->link ? obj->link->name : "NONE");
        link_collect_attributes(obj->link, &obj->attributes);
    }
}
