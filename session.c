/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */
 
#include "session.h" 
#include <string.h>

struct object *session_object_by_serial(struct session *sess, key_serial_t obj_id)
{
    struct object *obj;
    if (sess->curr_obj && sess->curr_obj->object_id == obj_id)
        return sess->curr_obj;
    for (obj = sess->slot->objects; obj; obj = obj->next) {
        if (obj->object_id == obj_id) {
            sess->curr_obj = obj;
            return obj;
        }
    }
    return NULL;
}

void session_free(struct session *sess)
{
    memset(sess, 0, sizeof(struct session));
}
