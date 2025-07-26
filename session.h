/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _SESSION_H
#define _SESSION_H 1

#include "iniparser/iniparser.h"
#include "signserver-pkcs11.h"
#include "slot.h"

struct session {
    struct slot *slot;
    /* Operation (find, sign ..) in progress */
    unsigned long curr_op;
    struct object *curr_obj;
    /* FindObjects*() data */
    unsigned long find_pos;
    unsigned long n_found;
    struct object **found_objects;

};

static inline struct object *session_curr_obj(struct session *sess)
{
    return sess->curr_obj;
}

struct object *session_object_by_serial(struct session *sess, ck_object_handle_t obj_id);
void session_free(struct session *sess);
#endif
