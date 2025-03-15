/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */
 
#include "session.h" 
#include <string.h>

struct key *session_key_by_serial(struct session *sess, key_serial_t key_id)
{
    struct key *key;
    if (sess->curr_key && sess->curr_key->key == key_id)
        return sess->curr_key;
    for (unsigned long i = 0; i < sess->slot->n_keys; i++) {
        key = sess->slot->keys + i;
        if (key->key == key_id) {
            sess->curr_key = key;
            return key;
        }
    }
    return NULL;
}

void session_free(struct session *sess)
{
    memset(sess, 0, sizeof(struct session));
}
