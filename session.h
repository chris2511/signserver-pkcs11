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
    key_serial_t keyring;
    unsigned long curr_op;
    unsigned long n_keys;
    unsigned long find_pos;
    struct key *curr_key;
    struct key *keys;
    void *data;
    unsigned long data_len;
    struct ck_attribute *search_templ;
    unsigned long search_templ_count;
};

static inline unsigned long session_curr_key_pos(struct session *sess)
{
    if (sess->curr_key < sess->keys)
        return 0;
    return sess->curr_key - sess->keys;
}

static inline struct key *session_curr_key(struct session *sess)
{
    return sess->curr_key;
}

struct key *session_next_key(struct session *sess);
struct key *session_find_key(struct session *sess, key_serial_t key);

ck_rv_t session_load_keys(struct session *sess);
void session_free(struct session *sess);

#endif
