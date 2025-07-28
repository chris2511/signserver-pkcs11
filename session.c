/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */
 
#include "session.h"
#include "object.h" 
#include <string.h>

struct object *session_object_by_serial(struct session *sess, ck_object_handle_t obj_id)
{
    if (obj_id >= OBJECT_TYPE_MAX) {
        DBG("Invalid object ID: %lu", obj_id);
        return NULL;
    }
    return sess->slot->objects + obj_id;
}

void session_free(struct session *sess)
{
    memset(sess, 0, sizeof(struct session));
}
