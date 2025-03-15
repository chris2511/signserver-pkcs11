/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#ifndef _SESSION_H
#define _SESSION_H 1

#include "keyutil-pkcs11.h"
#include "key.h"

struct session {
    /* Keyring / SlotId */
    key_serial_t keyring;
    /* Operation (find, sign ..) in progress */
    unsigned long curr_op;
    /* Key management */
    unsigned long n_keys;
    struct key *keys;
    struct key *curr_key;
    /* FindObjects*() data */
    unsigned long find_pos;
    unsigned long n_found;
    struct key *found_keys[MAX_KEYS];
};

static inline struct key *session_curr_key(struct session *sess)
{
    return sess->curr_key;
}

struct key *session_key_by_serial(struct session *sess, key_serial_t key);
ck_rv_t session_load_keys(struct session *sess);
void session_free(struct session *sess);

#endif
