/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */
 
#include "session.h"
#include "object.h" 
#include "storage.h" 
#include <string.h>

const struct object *session_object_by_serial(struct session *sess, ck_object_handle_t obj_id)
{
    for (int i = 0; i < OBJECT_TYPE_MAX; i++) {
        if (sess->slot->objects[i].object_id == obj_id)
            return sess->slot->objects + i;
    }
    DBG("Invalid object ID: %lu", obj_id);
    return NULL;
}

void session_free(struct session *sess)
{
    storage_free(sess->pin);
    signature_op_free(&sess->signature);
    memset(sess, 0, sizeof *sess);
}
