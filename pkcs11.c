#define CRYPTOKI_GNU
#include "opensc-pkcs11.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <keyutils.h>

#define INITIALIZED if (!initialized) return CKR_CRYPTOKI_NOT_INITIALIZED
#define CHECKARG(x) if (!(x)) return CKR_ARGUMENTS_BAD;
#define CHECK_SESSION(session) \
    if (session >= MAX_SESSIONS || sessions[session].keyring == 0) \
        return CKR_SESSION_HANDLE_INVALID;

#define MAX_SLOTS 128
#define MAX_SESSIONS 128
#define MAX_KEYS 32

struct slotids {
    int n_slots;
    ck_flags_t flags;
    ck_slot_id_t slot_ids[MAX_SLOTS];
};

struct session {
    key_serial_t keyring;
    long n_keys;
    long curr_key;
    key_serial_t keys[MAX_KEYS];
} sessions[MAX_SESSIONS];

static int initialized = 0;

static int keyring_scanner_cb(key_serial_t parent, key_serial_t key,
                              char *desc, int desc_len, void *data)
{
    struct slotids *slots = data;
    printf("KEYRING %ld %s\n", key, desc);
    if (parent != 0 && strncmp(desc, "keyring;", 8u) == 0) {
        if (slots->n_slots < MAX_SLOTS)
            slots->slot_ids[slots->n_slots++] = (ck_slot_id_t)key;
    }
    return 1;
}
#if 0
        struct keyctl_pkey_query query;
        long r = keyctl_pkey_query(key, "", &query);
        if (r == -1) {
            printf("QUERY %ld - %s\n", r, strerror(errno));
            return 1;
        }
        if (query.supported_ops & KEYCTL_SUPPORTS_ENCRYPT) {
            printf("ENCR %ld 0x%lx %ld\n", r, query.supported_ops, query.key_size);
#endif

static int key_scanner_cb(key_serial_t parent, key_serial_t key,
                              char *desc, int desc_len, void *data)
{
    struct session *sess = data;
    printf("### KEY %ld %ld %s\n", parent, key, desc);
    if (parent != 0 && strncmp(desc, "asymmetric;", 11u) == 0) {
        if (sess->n_keys < MAX_KEYS) {
            sess->keys[sess->n_keys++] = key;
        }
        return 1;
    }
    return 0;
}

const struct ck_info ckinfo = {
    .cryptoki_version = { .major = CRYPTOKI_VERSION_MAJOR,
                          .minor = CRYPTOKI_VERSION_MINOR },
    .manufacturer_id = "Linux Keyutils                  ",
    .flags = 0,
    .library_description = "Linux Kernel KeyRetentionService",
    .library_version = { .major = 0, .minor = 1 }
};

ck_rv_t C_Initialize(void *init_args)
{
    printf("### C_Initialize\n");
    memset(sessions, 0, sizeof sessions);
    initialized = 1;
    return CKR_OK;
}

ck_rv_t C_Finalize(void *reserved)
{
    printf("### C_Finalize\n");
    INITIALIZED;
    initialized = 0;
    return CKR_OK;
}

ck_rv_t C_GetInfo(struct ck_info *info)
{
    printf("### C_GetInfo\n");
    INITIALIZED;
    CHECKARG(info);
    memcpy(info, &ckinfo, sizeof ckinfo);
    return CKR_OK;
}

ck_rv_t C_GetSlotList(unsigned char token_present, ck_slot_id_t *slot_list,
              unsigned long *count)
{
    INITIALIZED;
    CHECKARG(count);

    printf("### C_GetSlotList %lu\n", *count);
    struct slotids slots = { .n_slots = 0 };
    long r = recursive_key_scan(KEY_SPEC_USER_KEYRING, keyring_scanner_cb, &slots);
    if (r < 0)
        return CKR_GENERAL_ERROR;
    if (slot_list) {
        if (*count < slots.n_slots) {
            *count = slots.n_slots;
            return CKR_BUFFER_TOO_SMALL;
        }
        printf("NSLOTS %lu\n", slots.n_slots);
        for (int i = 0; i < slots.n_slots; i++)
            slot_list[i] = slots.slot_ids[i];
    }
    *count = slots.n_slots;
    printf("#### Endegelände %lu\n", *count);
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

#define TRACE fprintf(stderr, "LINE %d\n", __LINE__);
ck_rv_t C_GetSlotInfo(ck_slot_id_t slot_id, struct ck_slot_info *info)
{
    INITIALIZED;
    CHECKARG(info);
    
    fprintf(stderr, "### C_GetSlotInfo %lu\n", slot_id);

    memset(info, 0, sizeof *info);
    memcpy(info->manufacturer_id, ckinfo.manufacturer_id, 32);
    info->flags = CKF_TOKEN_PRESENT;

    return keyutil_name_to_id((key_serial_t)slot_id,
                    info->slot_description, sizeof(info->slot_description));
}

ck_rv_t C_GetTokenInfo(ck_slot_id_t slot_id, struct ck_token_info *info)
{
    INITIALIZED;
    CHECKARG(info);
    fprintf(stderr, "### C_GetTokenInfo %lu\n", slot_id);
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
                    info->label, sizeof(info->label));
}

ck_rv_t C_OpenSession( ck_slot_id_t slot_id, ck_flags_t flags,
                       void *application, ck_notify_t notify,
                       ck_session_handle_t *session)
{
    INITIALIZED;
    CHECKARG(session);
    fprintf(stderr, "### C_OpenSession %lu\n", slot_id);
    if (flags & CKF_SERIAL_SESSION == 0)
        return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    if (flags & CKF_RW_SESSION == 0)
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
    fprintf(stderr, "### C_CloseSession %lu\n", session);
    CHECK_SESSION(session);
    memset(sessions +session, 0, sizeof(struct session));
    return CKR_OK;
}

ck_rv_t C_CloseAllSessions(ck_slot_id_t slot_id)
{
    INITIALIZED;
    fprintf(stderr, "### C_CloseAllSessions %lu\n", slot_id);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].keyring == (key_serial_t)slot_id) 
            memset(sessions +i, 0, sizeof(struct session));
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

    if (sess->n_keys > 0)
        return CKR_OPERATION_ACTIVE;

    fprintf(stderr, "### C_FindObjectsInit %lu %lu %lu\n", session, keyring, count);
    for (unsigned long i = 0; i < count; i++) {
        fprintf(stderr, "### Attribute %lu %lu\n", templ[i].type, templ[i].value_len);
    }
    
    struct slotids slots = { .n_slots = 0 };
    long r = recursive_key_scan(keyring, key_scanner_cb, sess);
    if (r < 0)
        return CKR_GENERAL_ERROR;
    printf("#### Endegelände %lu\n", r);
    
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
    fprintf(stderr, "### C_FindObjects %lu %lu %lu\n", session, max_object_count);    
    struct session *sess = sessions +session;
    if (max_object_count > sess->n_keys - sess->curr_key)
        max_object_count = sess->n_keys - sess->curr_key;
    
    for (unsigned long i = 0; i < max_object_count; i++) {
        object[i] = sess->keys[sess->curr_key++];
    }
    *object_count = max_object_count;
    return CKR_OK;
}

ck_rv_t C_FindObjectsFinal(ck_session_handle_t session)
{
    INITIALIZED;
    CHECK_SESSION(session);
    fprintf(stderr, "### C_FindObjectsFinal %lu\n", session);
    
    struct session *sess = sessions +session;
    memset(sess->keys, 0, sizeof sess->keys);   
    sess->n_keys = 0;
    sess->curr_key = 0;

    return CKR_OK;
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

    *function_list = fl;
    return CKR_OK;
}
