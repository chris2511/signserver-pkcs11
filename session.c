/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */
 
#include "session.h" 
#include <stdlib.h>
#include <string.h>

void session_free(struct session *sess)
{
    if (sess->keys)
        free(sess->keys);
    if(sess->data)
        free(sess->data);
    memset(sess, 0, sizeof(struct session));
}

static int key_scanner_cb(key_serial_t parent, key_serial_t key,
                          char *desc, int desc_len, void *data)
{
    struct session *sess = data;
    DBG("KEY %ld %ld %s", parent, key, desc);
    int ret = 0;
    if (sess->n_keys < MAX_KEYS || parent != 0) {
        ret = key_init(sess->keys + sess->n_keys, key, desc, desc_len);
        if (ret > 0)
            sess->n_keys++ ;
    }
    return ret;
}

ck_rv_t session_load_keys(struct session *sess, key_serial_t keyring)
{
    if (sess->keys)
        free(sess->keys);
    sess->keys = calloc(MAX_KEYS, sizeof(struct key));
    if (!sess->keys)
        return CKR_HOST_MEMORY;
    long r = recursive_key_scan(keyring, key_scanner_cb, sess);
    DBG("Found %ld keys", r);
    return 0;
}

struct key *session_next_key(struct session *sess)
{
    if (!sess->curr_key)
        sess->curr_key = sess->keys;
    else if (session_curr_key_pos(sess) >= sess->n_keys)
        sess->curr_key = NULL;
    else
        sess->curr_key++;
    return sess->curr_key;
}

struct key *session_find_key(struct session *sess, key_serial_t key_id)
{
    struct key *key = NULL;
    while (key = session_next_key(sess)) {
        if (key->key == key_id)
            return key;
    }
}
