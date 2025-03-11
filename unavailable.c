#define CRYPTOKI_GNU
#include "opensc-pkcs11.h"

#undef _CK_DECLARE_FUNCTION
#define _CK_DECLARE_FUNCTION(name, args) \
	ck_rv_t UNSUP_ ## name args { return CKR_FUNCTION_NOT_SUPPORTED; }

_CK_DECLARE_FUNCTION (C_Initialize, (void *init_args));
_CK_DECLARE_FUNCTION (C_Finalize, (void *reserved));
_CK_DECLARE_FUNCTION (C_GetInfo, (struct ck_info *info));
_CK_DECLARE_FUNCTION (C_GetFunctionList,
		      (struct ck_function_list **function_list));

_CK_DECLARE_FUNCTION (C_GetSlotList,
		      (unsigned char token_present, ck_slot_id_t *slot_list,
		       unsigned long *count));
_CK_DECLARE_FUNCTION (C_GetSlotInfo,
		      (ck_slot_id_t slot_id, struct ck_slot_info *info));
_CK_DECLARE_FUNCTION (C_GetTokenInfo,
		      (ck_slot_id_t slot_id, struct ck_token_info *info));
_CK_DECLARE_FUNCTION (C_WaitForSlotEvent,
		      (ck_flags_t flags, ck_slot_id_t *slot, void *reserved));
_CK_DECLARE_FUNCTION (C_GetMechanismList,
		      (ck_slot_id_t slot_id,
		       ck_mechanism_type_t *mechanism_list,
		       unsigned long *count));
_CK_DECLARE_FUNCTION (C_GetMechanismInfo,
		      (ck_slot_id_t slot_id, ck_mechanism_type_t type,
		       struct ck_mechanism_info *info));
_CK_DECLARE_FUNCTION (C_InitToken,
		      (ck_slot_id_t slot_id, unsigned char *pin,
		       unsigned long pin_len, unsigned char *label));
_CK_DECLARE_FUNCTION (C_InitPIN,
		      (ck_session_handle_t session, unsigned char *pin,
		       unsigned long pin_len));
_CK_DECLARE_FUNCTION (C_SetPIN,
		      (ck_session_handle_t session, unsigned char *old_pin,
		       unsigned long old_len, unsigned char *new_pin,
		       unsigned long new_len));

_CK_DECLARE_FUNCTION (C_OpenSession,
		      (ck_slot_id_t slot_id, ck_flags_t flags,
		       void *application, ck_notify_t notify,
		       ck_session_handle_t *session));
_CK_DECLARE_FUNCTION (C_CloseSession, (ck_session_handle_t session));
_CK_DECLARE_FUNCTION (C_CloseAllSessions, (ck_slot_id_t slot_id));
_CK_DECLARE_FUNCTION (C_GetSessionInfo,
		      (ck_session_handle_t session,
		       struct ck_session_info *info));
_CK_DECLARE_FUNCTION (C_GetOperationState,
		      (ck_session_handle_t session,
		       unsigned char *operation_state,
		       unsigned long *operation_state_len));
_CK_DECLARE_FUNCTION (C_SetOperationState,
		      (ck_session_handle_t session,
		       unsigned char *operation_state,
		       unsigned long operation_state_len,
		       ck_object_handle_t encryption_key,
		       ck_object_handle_t authentiation_key));
_CK_DECLARE_FUNCTION (C_Login,
		      (ck_session_handle_t session, ck_user_type_t user_type,
		       unsigned char *pin, unsigned long pin_len));
_CK_DECLARE_FUNCTION (C_Logout, (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_CreateObject,
		      (ck_session_handle_t session,
		       struct ck_attribute *templ,
		       unsigned long count, ck_object_handle_t *object));
_CK_DECLARE_FUNCTION (C_CopyObject,
		      (ck_session_handle_t session, ck_object_handle_t object,
		       struct ck_attribute *templ, unsigned long count,
		       ck_object_handle_t *new_object));
_CK_DECLARE_FUNCTION (C_DestroyObject,
		      (ck_session_handle_t session,
		       ck_object_handle_t object));
_CK_DECLARE_FUNCTION (C_GetObjectSize,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       unsigned long *size));
_CK_DECLARE_FUNCTION (C_GetAttributeValue,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       struct ck_attribute *templ,
		       unsigned long count));
_CK_DECLARE_FUNCTION (C_SetAttributeValue,
		      (ck_session_handle_t session,
		       ck_object_handle_t object,
		       struct ck_attribute *templ,
		       unsigned long count));
_CK_DECLARE_FUNCTION (C_FindObjectsInit,
		      (ck_session_handle_t session,
		       struct ck_attribute *templ,
		       unsigned long count));
_CK_DECLARE_FUNCTION (C_FindObjects,
		      (ck_session_handle_t session,
		       ck_object_handle_t *object,
		       unsigned long max_object_count,
		       unsigned long *object_count));
_CK_DECLARE_FUNCTION (C_FindObjectsFinal,
		      (ck_session_handle_t session));

_CK_DECLARE_FUNCTION (C_EncryptInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key));
_CK_DECLARE_FUNCTION (C_Encrypt,
		      (ck_session_handle_t session,
		       unsigned char *data, unsigned long data_len,
		       unsigned char *encrypted_data,
		       unsigned long *encrypted_data_len));
_CK_DECLARE_FUNCTION (C_EncryptUpdate,
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len,
		       unsigned char *encrypted_part,
		       unsigned long *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_EncryptFinal,
		      (ck_session_handle_t session,
		       unsigned char *last_encrypted_part,
		       unsigned long *last_encrypted_part_len));

_CK_DECLARE_FUNCTION (C_DecryptInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key));
_CK_DECLARE_FUNCTION (C_Decrypt,
		      (ck_session_handle_t session,
		       unsigned char *encrypted_data,
		       unsigned long encrypted_data_len,
		       unsigned char *data, unsigned long *data_len));
_CK_DECLARE_FUNCTION (C_DecryptUpdate,
		      (ck_session_handle_t session,
		       unsigned char *encrypted_part,
		       unsigned long encrypted_part_len,
		       unsigned char *part, unsigned long *part_len));
_CK_DECLARE_FUNCTION (C_DecryptFinal,
		      (ck_session_handle_t session,
		       unsigned char *last_part,
		       unsigned long *last_part_len));

_CK_DECLARE_FUNCTION (C_DigestInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism));
_CK_DECLARE_FUNCTION (C_Digest,
		      (ck_session_handle_t session,
		       unsigned char *data, unsigned long data_len,
		       unsigned char *digest,
		       unsigned long *digest_len));
_CK_DECLARE_FUNCTION (C_DigestUpdate,
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len));
_CK_DECLARE_FUNCTION (C_DigestKey,
		      (ck_session_handle_t session, ck_object_handle_t key));
_CK_DECLARE_FUNCTION (C_DigestFinal,
		      (ck_session_handle_t session,
		       unsigned char *digest,
		       unsigned long *digest_len));

_CK_DECLARE_FUNCTION (C_SignInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key));
_CK_DECLARE_FUNCTION (C_Sign,
		      (ck_session_handle_t session,
		       unsigned char *data, unsigned long data_len,
		       unsigned char *signature,
		       unsigned long *signature_len));
_CK_DECLARE_FUNCTION (C_SignUpdate,
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len));
_CK_DECLARE_FUNCTION (C_SignFinal,
		      (ck_session_handle_t session,
		       unsigned char *signature,
		       unsigned long *signature_len));
_CK_DECLARE_FUNCTION (C_SignRecoverInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key));
_CK_DECLARE_FUNCTION (C_SignRecover,
		      (ck_session_handle_t session,
		       unsigned char *data, unsigned long data_len,
		       unsigned char *signature,
		       unsigned long *signature_len));

_CK_DECLARE_FUNCTION (C_VerifyInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key));
_CK_DECLARE_FUNCTION (C_Verify,
		      (ck_session_handle_t session,
		       unsigned char *data, unsigned long data_len,
		       unsigned char *signature,
		       unsigned long signature_len));
_CK_DECLARE_FUNCTION (C_VerifyUpdate,
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len));
_CK_DECLARE_FUNCTION (C_VerifyFinal,
		      (ck_session_handle_t session,
		       unsigned char *signature,
		       unsigned long signature_len));
_CK_DECLARE_FUNCTION (C_VerifyRecoverInit,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t key));
_CK_DECLARE_FUNCTION (C_VerifyRecover,
		      (ck_session_handle_t session,
		       unsigned char *signature,
		       unsigned long signature_len,
		       unsigned char *data,
		       unsigned long *data_len));

_CK_DECLARE_FUNCTION (C_DigestEncryptUpdate,
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len,
		       unsigned char *encrypted_part,
		       unsigned long *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptDigestUpdate,
		      (ck_session_handle_t session,
		       unsigned char *encrypted_part,
		       unsigned long encrypted_part_len,
		       unsigned char *part,
		       unsigned long *part_len));
_CK_DECLARE_FUNCTION (C_SignEncryptUpdate,
		      (ck_session_handle_t session,
		       unsigned char *part, unsigned long part_len,
		       unsigned char *encrypted_part,
		       unsigned long *encrypted_part_len));
_CK_DECLARE_FUNCTION (C_DecryptVerifyUpdate,
		      (ck_session_handle_t session,
		       unsigned char *encrypted_part,
		       unsigned long encrypted_part_len,
		       unsigned char *part,
		       unsigned long *part_len));

_CK_DECLARE_FUNCTION (C_GenerateKey,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       struct ck_attribute *templ,
		       unsigned long count,
		       ck_object_handle_t *key));
_CK_DECLARE_FUNCTION (C_GenerateKeyPair,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       struct ck_attribute *public_key_template,
		       unsigned long public_key_attribute_count,
		       struct ck_attribute *private_key_template,
		       unsigned long private_key_attribute_count,
		       ck_object_handle_t *public_key,
		       ck_object_handle_t *private_key));
_CK_DECLARE_FUNCTION (C_WrapKey,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t wrapping_key,
		       ck_object_handle_t key,
		       unsigned char *wrapped_key,
		       unsigned long *wrapped_key_len));
_CK_DECLARE_FUNCTION (C_UnwrapKey,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t unwrapping_key,
		       unsigned char *wrapped_key,
		       unsigned long wrapped_key_len,
		       struct ck_attribute *templ,
		       unsigned long attribute_count,
		       ck_object_handle_t *key));
_CK_DECLARE_FUNCTION (C_DeriveKey,
		      (ck_session_handle_t session,
		       struct ck_mechanism *mechanism,
		       ck_object_handle_t base_key,
		       struct ck_attribute *templ,
		       unsigned long attribute_count,
		       ck_object_handle_t *key));

_CK_DECLARE_FUNCTION (C_SeedRandom,
		      (ck_session_handle_t session, unsigned char *seed,
		       unsigned long seed_len));
_CK_DECLARE_FUNCTION (C_GenerateRandom,
		      (ck_session_handle_t session,
		       unsigned char *random_data,
		       unsigned long random_len));

struct ck_function_list pkcs11_function_list =
{
  .C_Initialize = UNSUP_C_Initialize,
  .C_Finalize = UNSUP_C_Finalize,
  .C_GetInfo = UNSUP_C_GetInfo,
  .C_GetFunctionList = UNSUP_C_GetFunctionList,
  .C_GetSlotList = UNSUP_C_GetSlotList,
  .C_GetSlotInfo = UNSUP_C_GetSlotInfo,
  .C_GetTokenInfo = UNSUP_C_GetTokenInfo,
  .C_GetMechanismList = UNSUP_C_GetMechanismList,
  .C_GetMechanismInfo = UNSUP_C_GetMechanismInfo,
  .C_InitToken = UNSUP_C_InitToken,
  .C_InitPIN = UNSUP_C_InitPIN,
  .C_SetPIN = UNSUP_C_SetPIN,
  .C_OpenSession = UNSUP_C_OpenSession,
  .C_CloseSession = UNSUP_C_CloseSession,
  .C_CloseAllSessions = UNSUP_C_CloseAllSessions,
  .C_GetSessionInfo = UNSUP_C_GetSessionInfo,
  .C_GetOperationState = UNSUP_C_GetOperationState,
  .C_SetOperationState = UNSUP_C_SetOperationState,
  .C_Login = UNSUP_C_Login,
  .C_Logout = UNSUP_C_Logout,
  .C_CreateObject = UNSUP_C_CreateObject,
  .C_CopyObject = UNSUP_C_CopyObject,
  .C_DestroyObject = UNSUP_C_DestroyObject,
  .C_GetObjectSize = UNSUP_C_GetObjectSize,
  .C_GetAttributeValue = UNSUP_C_GetAttributeValue,
  .C_SetAttributeValue = UNSUP_C_SetAttributeValue,
  .C_FindObjectsInit = UNSUP_C_FindObjectsInit,
  .C_FindObjects = UNSUP_C_FindObjects,
  .C_FindObjectsFinal = UNSUP_C_FindObjectsFinal,
  .C_EncryptInit = UNSUP_C_EncryptInit,
  .C_Encrypt = UNSUP_C_Encrypt,
  .C_EncryptUpdate = UNSUP_C_EncryptUpdate,
  .C_EncryptFinal = UNSUP_C_EncryptFinal,
  .C_DecryptInit = UNSUP_C_DecryptInit,
  .C_Decrypt = UNSUP_C_Decrypt,
  .C_DecryptUpdate = UNSUP_C_DecryptUpdate,
  .C_DecryptFinal = UNSUP_C_DecryptFinal,
  .C_DigestInit = UNSUP_C_DigestInit,
  .C_Digest = UNSUP_C_Digest,
  .C_DigestUpdate = UNSUP_C_DigestUpdate,
  .C_DigestKey = UNSUP_C_DigestKey,
  .C_DigestFinal = UNSUP_C_DigestFinal,
  .C_SignInit = UNSUP_C_SignInit,
  .C_Sign = UNSUP_C_Sign,
  .C_SignUpdate = UNSUP_C_SignUpdate,
  .C_SignFinal = UNSUP_C_SignFinal,
  .C_SignRecoverInit = UNSUP_C_SignRecoverInit,
  .C_SignRecover = UNSUP_C_SignRecover,
  .C_VerifyInit = UNSUP_C_VerifyInit,
  .C_Verify = UNSUP_C_Verify,
  .C_VerifyUpdate = UNSUP_C_VerifyUpdate,
  .C_VerifyFinal = UNSUP_C_VerifyFinal,
  .C_VerifyRecoverInit = UNSUP_C_VerifyRecoverInit,
  .C_VerifyRecover = UNSUP_C_VerifyRecover,
  .C_DigestEncryptUpdate = UNSUP_C_DigestEncryptUpdate,
  .C_DecryptDigestUpdate = UNSUP_C_DecryptDigestUpdate,
  .C_SignEncryptUpdate = UNSUP_C_SignEncryptUpdate,
  .C_DecryptVerifyUpdate = UNSUP_C_DecryptVerifyUpdate,
  .C_GenerateKey = UNSUP_C_GenerateKey,
  .C_GenerateKeyPair = UNSUP_C_GenerateKeyPair,
  .C_WrapKey = UNSUP_C_WrapKey,
  .C_UnwrapKey = UNSUP_C_UnwrapKey,
  .C_DeriveKey = UNSUP_C_DeriveKey,
  .C_SeedRandom = UNSUP_C_SeedRandom,
  .C_GenerateRandom = UNSUP_C_GenerateRandom,
  .C_WaitForSlotEvent = UNSUP_C_WaitForSlotEvent,
};
