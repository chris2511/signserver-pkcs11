/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _SESSION_H
#define _SESSION_H 1

#include "signserver-pkcs11.h"
#include "signature.h"
#include "slot.h"

#include "iniparser.h"

struct session {
    struct slot *slot;
    /* Operation (find, sign ..) in progress */
    unsigned long curr_op;
    const struct object *curr_obj;
    /* FindObjects*() data */
    unsigned long find_pos;
    unsigned long n_found;
    struct signature_op signature;
    const struct object *found_objects[OBJECT_TYPE_MAX];
};

static inline const struct object *session_curr_obj(struct session *sess)
{
    return sess->curr_obj;
}

const struct object *session_object_by_serial(struct session *sess, ck_object_handle_t obj_id);
void session_free(struct session *sess);

#endif
