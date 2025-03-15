/* vi: set sw=4 ts=4 expandtab: */
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) 2025 Christian Hohnstaedt.
 * All rights reserved.
 */

#include "keyutil-pkcs11.h"

#include "session.h"
#include "key.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>

#define INITIALIZED if (!initialized) return CKR_CRYPTOKI_NOT_INITIALIZED
#define CHECKARG(x) if (!(x)) return CKR_ARGUMENTS_BAD;
#define CHECK_SESSION(session) \
    if (session >= MAX_SESSIONS || sessions[session].keyring == 0) \
        return CKR_SESSION_HANDLE_INVALID;


struct slotids {
    unsigned long n_slots;
    ck_slot_id_t slot_ids[MAX_SLOTS];
};

int dbg;
static int initialized = 0;
struct session sessions[MAX_SESSIONS];

static int keyring_scanner_cb(key_serial_t parent, key_serial_t key,
                              char *desc, int desc_len, void *data)
{
    (void)desc_len;
    struct slotids *slots = data;
    DBG("KEYRING %d %s", key, desc);
    if (parent != 0 && strncmp(desc, "keyring;", 8u) == 0) {
        DBG("Found KEYRING %d %s", key, desc);
        if (slots->n_slots < MAX_SLOTS)
            slots->slot_ids[slots->n_slots++] = (ck_slot_id_t)key;
    }
    return 1;
}

const struct ck_info ckinfo = {
    .cryptoki_version = { .major = CRYPTOKI_VERSION_MAJOR,
                          .minor = CRYPTOKI_VERSION_MINOR },
    .manufacturer_id = "Linux Keyutils                  ",
    .flags = 0,
    .library_description = "Linux Kernel KeyRetentionService",
    .library_version = { .major = 0, .minor = 1 }
};

ck_rv_t C_Initialize(void *init)
{
    (void)init;
    dbg = getenv("DEBUG") ? 1 : 0 ;
    DBG("C_Initialize");
    memset(sessions, 0, sizeof sessions);
    initialized = 1;
    return CKR_OK;
}

ck_rv_t C_Finalize(void *reserved)
{
    (void)reserved;
    DBG("C_Finalize");
    INITIALIZED;
    initialized = 0;
    return CKR_OK;
}

ck_rv_t C_GetInfo(struct ck_info *info)
{
    DBG("C_GetInfo");
    INITIALIZED;
    CHECKARG(info);
    memcpy(info, &ckinfo, sizeof ckinfo);
    return CKR_OK;
}

ck_rv_t C_GetSlotList(unsigned char token_present, ck_slot_id_t *slot_list,
              unsigned long *count)
{
    (void)token_present;
    INITIALIZED;
    CHECKARG(count);

    DBG("C_GetSlotList %lu", slot_list ? *count : 0);
    struct slotids slots = { .n_slots = 0 };
    long r = recursive_key_scan(KEY_SPEC_USER_KEYRING, keyring_scanner_cb, &slots);
    if (r < 0)
        return CKR_GENERAL_ERROR;
    if (slot_list) {
        if (*count < slots.n_slots) {
            *count = slots.n_slots;
            return CKR_BUFFER_TOO_SMALL;
        }
        for (unsigned long i = 0; i < slots.n_slots; i++)
            slot_list[i] = slots.slot_ids[i];
    }
    *count = slots.n_slots;
    DBG("No. SLots %lu", *count);
    return CKR_OK;
}

static ck_rv_t keyutil_name_to_id(key_serial_t serial, char *ck_desc, size_t ck_len)
{
    char buffer[128], *name;
    int r = keyctl_describe(serial, buffer, sizeof buffer);
    if (r < 0)
        return CKR_SLOT_ID_INVALID;
    name = strrchr(buffer, ';');
    if (!name)
        return CKR_SLOT_ID_INVALID;
    name++;
    size_t slen = strlen(name);
    memset(ck_desc, ' ', ck_len);
    if (slen > ck_len)
        slen = ck_len;
    memcpy(ck_desc, name, slen);
    return CKR_OK;
}

ck_rv_t C_GetSlotInfo(ck_slot_id_t slot_id, struct ck_slot_info *info)
{
    INITIALIZED;
    CHECKARG(info);

    DBG("Slot ID %lu", slot_id);

    memset(info, 0, sizeof *info);
    memcpy(info->manufacturer_id, ckinfo.manufacturer_id, 32);
    info->flags = CKF_TOKEN_PRESENT;

    return keyutil_name_to_id((key_serial_t)slot_id,
                    (char *)info->slot_description, sizeof(info->slot_description));
}

ck_rv_t C_GetTokenInfo(ck_slot_id_t slot_id, struct ck_token_info *info)
{
    INITIALIZED;
    CHECKARG(info);
    DBG("Slot ID %lu", slot_id);
    memset(info, 0, sizeof *info);

    memcpy(info->manufacturer_id, ckinfo.manufacturer_id, 32);
    info->flags = CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED;

    memset(info->model, ' ', sizeof(info->model));
    memset(info->serial_number, ' ', sizeof(info->serial_number));
    info->serial_number[0] = '1';
    info->max_session_count = CK_EFFECTIVELY_INFINITE;
    info->session_count = CK_UNAVAILABLE_INFORMATION;
    info->max_rw_session_count = CK_EFFECTIVELY_INFINITE;
    info->rw_session_count = CK_UNAVAILABLE_INFORMATION;
    info->max_pin_len = 0;
    info->min_pin_len = 0;
    info->total_public_memory = CK_UNAVAILABLE_INFORMATION;
    info->free_public_memory = CK_UNAVAILABLE_INFORMATION;
    info->total_private_memory = CK_UNAVAILABLE_INFORMATION;
    info->free_private_memory = CK_UNAVAILABLE_INFORMATION;

    return keyutil_name_to_id((key_serial_t)slot_id,
                    (char *)info->label, sizeof(info->label));
}

ck_rv_t C_OpenSession( ck_slot_id_t slot_id, ck_flags_t flags,
                       void *application, ck_notify_t notify,
                       ck_session_handle_t *session)
{
    (void)application;
    (void)notify;
    INITIALIZED;
    CHECKARG(session);
    DBG("Slot ID %lu", slot_id);
    if ((flags & CKF_SERIAL_SESSION) == 0)
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    if (flags & CKF_RW_SESSION)
        return CKR_TOKEN_WRITE_PROTECTED;

    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].keyring == 0) {
            sessions[i].keyring = (key_serial_t)slot_id;
            *session = (ck_session_handle_t)i;
            return CKR_OK;
        }
    }
    return CKR_SESSION_COUNT;
}

ck_rv_t C_CloseSession(ck_session_handle_t session)
{
    INITIALIZED;
    DBG("Session %lu", session);
    CHECK_SESSION(session);
    session_free(sessions +session);
    return CKR_OK;
}

ck_rv_t C_CloseAllSessions(ck_slot_id_t slot_id)
{
    INITIALIZED;
    DBG("CloseAllSessions %lu", slot_id);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].keyring == (key_serial_t)slot_id)
            session_free(sessions +i);
    }
    return CKR_OK;
}

ck_rv_t C_FindObjectsInit(ck_session_handle_t session,
                          struct ck_attribute *templ,
                          unsigned long count)
{
    INITIALIZED;
    CHECK_SESSION(session);
    if (count > 0)
        CHECKARG(templ);

    struct session *sess = sessions +session;
    key_serial_t keyring = sess->keyring;

    if (sess->curr_op != 0)
        return CKR_OPERATION_ACTIVE;

    sess->search_templ = templ;
    sess->search_templ_count = count;
    DBG("C_FindObjectsInit %lu %d %lu", session, sess->keyring, count);
    ck_rv_t r = session_load_keys(sess);
    sess->search_templ = NULL;
    sess->search_templ_count = 0;
    
    if (r != CKR_OK)
        return r;

    DBG("Objects found %lu", sess->n_keys);
    sess->curr_key = NULL;
    sess->curr_op = 1;
    sess->find_pos = 0;
    return CKR_OK;
}

ck_rv_t C_FindObjects(ck_session_handle_t session,
    ck_object_handle_t *object,
    unsigned long max_object_count,
    unsigned long *object_count)
{
    INITIALIZED;
    CHECK_SESSION(session);
    CHECKARG(object_count);
    CHECKARG(object);
    DBG("Session:%lu Max objects:%lu", session, max_object_count);
    struct session *sess = sessions +session;

    if (sess->curr_op != 1)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (max_object_count > sess->n_keys - sess->find_pos)
        max_object_count = sess->n_keys - sess->find_pos;

    for (unsigned long i = 0; i < max_object_count; i++) {
        object[i] = sess->keys[sess->find_pos++].key;
    }
    *object_count = max_object_count;
    return CKR_OK;
}

ck_rv_t C_FindObjectsFinal(ck_session_handle_t session)
{
    INITIALIZED;
    CHECK_SESSION(session);
    DBG("Session %lu", session);
    struct session *sess = sessions +session;

    if (sess->curr_op != 1)
        return CKR_OPERATION_NOT_INITIALIZED;
    sess->curr_key = NULL;
    sess->curr_op = 0;

    return CKR_OK;
}

ck_rv_t C_GetAttributeValue(ck_session_handle_t session,
    ck_object_handle_t object, struct ck_attribute *templ, unsigned long count)
{
    INITIALIZED;
    CHECK_SESSION(session);
    CHECKARG(templ);
    struct session *sess = sessions +session;
    unsigned long i;

    DBG("Session: %lu Object: %lu Max attributes: %lu", session, object, count);
    DBG("Curr key %p %lu", (void*)sess->curr_key, sess->n_keys);

    struct key *key = session_find_key(sess, object);
    if (!key)
        return CKR_OBJECT_HANDLE_INVALID;

    if (key->n_attributes == 0) {
        ck_rv_t r = key_collect_attributes(key);
        if (r != CKR_OK)
            return r;
    }
    for (i = 0; i < count; i++) {
        DBG("Attribute %lu %lu", templ[i].type, templ[i].value_len);
        unsigned long new_len = CK_UNAVAILABLE_INFORMATION;
        for (unsigned long j = 0; j<key->n_attributes; j++) {
            if (key->attributes[j].type != templ[i].type)
                continue;
            if (!templ[i].value) {
                new_len = key->attributes[j].value_len;
            } else {
                if (templ[i].value_len >= key->attributes[j].value_len) {
                    new_len = key->attributes[j].value_len;
                    memcpy(templ[i].value, key->attributes[j].value, new_len);
                }
            }
        }
        templ[i].value_len = new_len;
    }
    return CKR_OK;
}

ck_rv_t C_GetMechanismList(ck_slot_id_t slot_id,
        ck_mechanism_type_t *mechanism_list, unsigned long *count)
{
    INITIALIZED;
    CHECKARG(count);
    DBG("Slot ID %lu No. Mechs: %ld", slot_id, n_mechs);

    if (mechanism_list) {
        if (*count < n_mechs) {
            *count = n_mechs;
            return CKR_BUFFER_TOO_SMALL;
        }
        memcpy(mechanism_list, rsa_mechs, n_mechs * sizeof(ck_mechanism_type_t));
    }
    *count = n_mechs;
    return CKR_OK;
}

ck_rv_t C_GetMechanismInfo(ck_slot_id_t slot_id,
        ck_mechanism_type_t type, struct ck_mechanism_info *info)
{
    INITIALIZED;
    CHECKARG(info);
    DBG("Slot ID %lu Mechanism: %lu", slot_id, type);
    memset(info, 0, sizeof *info);
    info->flags = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY;
    return CKR_OK;
}

ck_rv_t C_SignInit(ck_session_handle_t session,
        struct ck_mechanism *mechanism, ck_object_handle_t key_id)
{
    INITIALIZED;
    CHECK_SESSION(session);
    CHECKARG(mechanism);
    struct session *sess = sessions +session;
    DBG("Session: %lu Key: %lu", session, key_id);

    if (sess->curr_op != 0)
        return CKR_OPERATION_ACTIVE;

    struct key *key = session_find_key(sess, key_id);
    sess->curr_op = 1;
    if (!key)
        return CKR_OBJECT_HANDLE_INVALID;
    key->data_len = 0;
    return key_mechanism_dup(key, mechanism);
}

ck_rv_t C_SignUpdate(ck_session_handle_t session,
        unsigned char *part, unsigned long part_len)
{
    INITIALIZED;
    CHECK_SESSION(session);
    CHECKARG(part);
    CHECKARG(part_len);
    struct session *sess = sessions +session;
    struct key *key = session_curr_key(sess);

    if (sess->curr_op != 1 || !key)
        return CKR_OPERATION_NOT_INITIALIZED;

    return key_data_add(key, part, part_len);
}

ck_rv_t C_SignFinal(ck_session_handle_t session,
        unsigned char *signature, unsigned long *signature_len)
{
    INITIALIZED;
    CHECK_SESSION(session);
    CHECKARG(signature);
    CHECKARG(signature_len);
    struct session *sess = sessions +session;

    DBG("Session: %lu", session);
    struct key *key = session_curr_key(sess);
    if (!key)
        return CKR_OBJECT_HANDLE_INVALID;
    if (sess->curr_op != 1)
        return CKR_OPERATION_NOT_INITIALIZED;

    ck_rv_t r = key_sign(key, signature, signature_len);
    sess->curr_op = 0;
    return r;
}

ck_rv_t C_Sign(ck_session_handle_t session,
        unsigned char *data, unsigned long data_len,
        unsigned char *signature, unsigned long *signature_len)
{
    ck_rv_t r = C_SignUpdate(session, data, data_len);
    if (r == CKR_OK)
        r = C_SignFinal(session, signature, signature_len);
    return r;
}

ck_rv_t C_GetFunctionList(struct ck_function_list **function_list)
{
    extern struct ck_function_list pkcs11_function_list;
    struct ck_function_list *fl = &pkcs11_function_list;

    fl->version = ckinfo.cryptoki_version;
    fl->C_Initialize = C_Initialize;
    fl->C_Finalize = C_Finalize;
    fl->C_GetInfo = C_GetInfo;
    fl->C_GetSlotList = C_GetSlotList;
    fl->C_GetSlotInfo = C_GetSlotInfo;
    fl->C_GetTokenInfo = C_GetTokenInfo;
    fl->C_OpenSession = C_OpenSession;
    fl->C_CloseSession = C_CloseSession;
    fl->C_CloseAllSessions = C_CloseAllSessions;
    fl->C_FindObjectsInit = C_FindObjectsInit;
    fl->C_FindObjects = C_FindObjects;
    fl->C_FindObjectsFinal = C_FindObjectsFinal;
    fl->C_GetAttributeValue = C_GetAttributeValue;
    fl->C_GetMechanismList = C_GetMechanismList;
    fl->C_GetMechanismInfo = C_GetMechanismInfo;
    fl->C_SignInit = C_SignInit;
    fl->C_SignFinal = C_SignFinal;
    fl->C_SignUpdate = C_SignUpdate;
    fl->C_Sign = C_Sign;

    *function_list = fl;
    return CKR_OK;
}
