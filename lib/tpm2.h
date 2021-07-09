/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef LIB_TPM2_H_
#define LIB_TPM2_H_

#include <tss2/tss2_esys.h>

#include "object.h"
#include "tool_rc.h"

tool_rc tpm2_from_tpm_public(ESYS_CONTEXT *esys_context, TPM2_HANDLE tpm_handle,
        ESYS_TR optional_session1, ESYS_TR optional_session2,
        ESYS_TR optional_session3, ESYS_TR *object);

tool_rc tpm2_close(ESYS_CONTEXT *esys_context, ESYS_TR *rsrc_handle);

tool_rc tpm2_tr_deserialize(ESYS_CONTEXT *esys_context, uint8_t const *buffer,
        size_t buffer_size, ESYS_TR *esys_handle);

tool_rc tpm2_tr_serialize(ESYS_CONTEXT *esys_context, ESYS_TR object,
        uint8_t **buffer, size_t *buffer_size);

tool_rc tpm2_nv_readpublic(ESYS_CONTEXT *esys_context, ESYS_TR nv_index,
        TPM2B_NV_PUBLIC **nv_public, TPM2B_NAME **nv_name);

tool_rc tpm2_readpublic(ESYS_CONTEXT *esys_context, ESYS_TR object_handle,
        TPM2B_PUBLIC **out_public, TPM2B_NAME **name,
        TPM2B_NAME **qualified_name);

tool_rc tpm2_getcap(ESYS_CONTEXT *esys_context,TPM2_CAP capability,
        UINT32 property, UINT32 property_count, TPMI_YES_NO *more_data,
        TPMS_CAPABILITY_DATA **capability_data);

tool_rc tpm2_nv_read(ESYS_CONTEXT *esys_context,
    tpm2_loaded_object *auth_hierarchy_obj, TPM2_HANDLE nv_index, UINT16 size,
    UINT16 offset, TPM2B_MAX_NV_BUFFER **data, TPM2B_DIGEST *cp_hash,
    TPMI_ALG_HASH parameter_hash_algorithm);

tool_rc tpm2_context_save(ESYS_CONTEXT *esys_context, ESYS_TR save_handle,
        TPMS_CONTEXT **context);

tool_rc tpm2_context_load(ESYS_CONTEXT *esys_context,
        const TPMS_CONTEXT *context, ESYS_TR *loaded_handle);

tool_rc tpm2_flush_context(ESYS_CONTEXT *esys_context, ESYS_TR flush_handle);

tool_rc tpm2_start_auth_session(ESYS_CONTEXT *esys_context, ESYS_TR tpm_key,
        ESYS_TR bind, const TPM2B_NONCE *nonce_caller, TPM2_SE session_type,
        const TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH auth_hash,
        ESYS_TR *session_handle);

tool_rc tpm2_sess_set_attributes(ESYS_CONTEXT *esys_context, ESYS_TR session,
        TPMA_SESSION flags, TPMA_SESSION mask);

tool_rc tpm2_sess_get_attributes(ESYS_CONTEXT *esys_context, ESYS_TR session,
        TPMA_SESSION *flags);

tool_rc tpm2_sess_get_noncetpm(ESYS_CONTEXT *esys_context,
    ESYS_TR session_handle, TPM2B_NONCE **nonce_tpm);

tool_rc tpm2_policy_restart(ESYS_CONTEXT *esys_context, ESYS_TR session_handle,
        ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3);

tool_rc tpm2_get_capability(ESYS_CONTEXT *esys_context, ESYS_TR shandle1,
        ESYS_TR shandle2, ESYS_TR shandle3, TPM2_CAP capability,
        UINT32 property, UINT32 property_count, TPMI_YES_NO *more_data,
        TPMS_CAPABILITY_DATA **capability_data);

tool_rc tpm2_create_primary(ESYS_CONTEXT *esys_context, ESYS_TR primary_handle,
        ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3,
        const TPM2B_SENSITIVE_CREATE *in_sensitive, const TPM2B_PUBLIC *in_public,
        const TPM2B_DATA *outside_info, const TPML_PCR_SELECTION *creation_pcr,
        ESYS_TR *object_handle, TPM2B_PUBLIC **out_public,
        TPM2B_CREATION_DATA **creation_data, TPM2B_DIGEST **creation_hash,
        TPMT_TK_CREATION **creation_ticket);

tool_rc tpm2_pcr_read(ESYS_CONTEXT *esys_context, ESYS_TR shandle1,
        ESYS_TR shandle2, ESYS_TR shandle3,
        const TPML_PCR_SELECTION *pcr_selection_in, UINT32 *pcr_update_counter,
        TPML_PCR_SELECTION **pcr_selection_out, TPML_DIGEST **pcr_values);

tool_rc tpm2_policy_authorize(ESYS_CONTEXT *esys_context, ESYS_TR policy_session,
        ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3,
        const TPM2B_DIGEST *approved_policy, const TPM2B_NONCE *policy_ref,
        const TPM2B_NAME *key_sign, const TPMT_TK_VERIFIED *check_ticket);

tool_rc tpm2_policy_or(ESYS_CONTEXT *esys_context, ESYS_TR policy_session,
        ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3,
        const TPML_DIGEST *p_hash_list);

tool_rc tpm2_policy_namehash(ESYS_CONTEXT *esys_context, ESYS_TR policy_session,
    const TPM2B_DIGEST *name_hash);

tool_rc tpm2_policy_template(ESYS_CONTEXT *esys_context, ESYS_TR policy_session,
    const TPM2B_DIGEST *template_hash);

tool_rc tpm2_policy_cphash(ESYS_CONTEXT *esys_context, ESYS_TR policy_session,
    const TPM2B_DIGEST *cphash);

tool_rc tpm2_policy_pcr(ESYS_CONTEXT *esys_context, ESYS_TR policy_session,
        ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3,
        const TPM2B_DIGEST *pcr_digest, const TPML_PCR_SELECTION *pcrs);

tool_rc tpm2_policy_password(ESYS_CONTEXT *esys_context, ESYS_TR policy_session,
        ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3);

tool_rc tpm2_policy_signed(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *auth_entity_obj, ESYS_TR policy_session,
        const TPMT_SIGNATURE *signature, INT32 expiration,
        TPM2B_TIMEOUT **timeout, TPMT_TK_AUTH **policy_ticket,
        TPM2B_NONCE *policy_qualifier, TPM2B_NONCE *nonce_tpm,
        TPM2B_DIGEST *cphash);

tool_rc tpm2_policy_ticket(ESYS_CONTEXT *esys_context, ESYS_TR policy_session,
    const TPM2B_TIMEOUT *timeout, const TPM2B_NONCE *policyref,
    const TPM2B_NAME *authname, const TPMT_TK_AUTH *ticket);

tool_rc tpm2_policy_authvalue(ESYS_CONTEXT *esys_context, ESYS_TR policy_session,
        ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3);

tool_rc tpm2_policy_secret_no_tpm(TPMI_ALG_HASH halg, TPM2B_DIGEST *current, TPM2B_NAME *name, TPM2B_NONCE *policy_qualifier,
        TPMT_TK_AUTH *new);

tool_rc tpm2_policy_secret(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *auth_entity_obj, ESYS_TR policy_session,
        INT32 expiration, TPMT_TK_AUTH **policy_ticket,
        TPM2B_TIMEOUT **timeout, TPM2B_NONCE *nonce_tpm,
        TPM2B_NONCE *policy_qualifier, TPM2B_DIGEST *cp_hash);

tool_rc tpm2_policy_getdigest(ESYS_CONTEXT *esys_context, ESYS_TR policy_session,
        ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3,
        TPM2B_DIGEST **policy_digest);

tool_rc tpm2_policy_command_code(ESYS_CONTEXT *esys_context,
        ESYS_TR policy_session, ESYS_TR shandle1, ESYS_TR shandle2,
        ESYS_TR shandle3, TPM2_CC code);

tool_rc tpm2_policy_locality(ESYS_CONTEXT *esys_context, ESYS_TR policy_session,
        ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3,
        TPMA_LOCALITY locality);

tool_rc tpm2_policy_duplication_select(ESYS_CONTEXT *esys_context,
        ESYS_TR policy_session, ESYS_TR shandle1, ESYS_TR shandle2,
        ESYS_TR shandle3, const TPM2B_NAME *object_name,
        const TPM2B_NAME *new_parent_name, TPMI_YES_NO include_object);

tool_rc tpm2_tr_get_name(ESYS_CONTEXT *esys_context, ESYS_TR handle,
        TPM2B_NAME **name);

tool_rc tpm2_mu_tpm2_handle_unmarshal(uint8_t const buffer[], size_t size,
        size_t *offset, TPM2_HANDLE *out);

tool_rc tpm2_mu_tpmt_public_marshal(TPMT_PUBLIC const *src, uint8_t buffer[],
        size_t buffer_size, size_t *offset);

tool_rc tpm2_evictcontrol(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *auth_hierarchy_obj,
        tpm2_loaded_object *to_persist_key_obj,
        TPMI_DH_PERSISTENT persistent_handle, ESYS_TR *new_object_handle,
        TPM2B_DIGEST *cp_hash);

tool_rc tpm2_hash(ESYS_CONTEXT *esys_context, ESYS_TR shandle1, ESYS_TR shandle2,
        ESYS_TR shandle3, const TPM2B_MAX_BUFFER *data, TPMI_ALG_HASH hash_alg,
        TPMI_RH_HIERARCHY hierarchy, TPM2B_DIGEST **out_hash,
        TPMT_TK_HASHCHECK **validation);

tool_rc tpm2_hash_sequence_start(ESYS_CONTEXT *esys_context, const TPM2B_AUTH *auth,
        TPMI_ALG_HASH hash_alg, ESYS_TR *sequence_handle);

tool_rc tpm2_sequence_update(ESYS_CONTEXT *esys_context, ESYS_TR sequence_handle,
        const TPM2B_MAX_BUFFER *buffer);

tool_rc tpm2_sequence_complete(ESYS_CONTEXT *esys_context,
        ESYS_TR sequence_handle, const TPM2B_MAX_BUFFER *buffer,
        TPMI_RH_HIERARCHY hierarchy, TPM2B_DIGEST **result,
        TPMT_TK_HASHCHECK **validation);

tool_rc tpm2_event_sequence_complete(ESYS_CONTEXT *ectx, ESYS_TR pcr,
        ESYS_TR sequence_handle, tpm2_session *session,
        const TPM2B_MAX_BUFFER *buffer, TPML_DIGEST_VALUES **results);

tool_rc tpm2_tr_set_auth(ESYS_CONTEXT *esys_context, ESYS_TR handle,
        TPM2B_AUTH const *auth_value);

tool_rc tpm2_activatecredential(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *activatehandle, tpm2_loaded_object *keyhandle,
        const TPM2B_ID_OBJECT *credential_blob,
        const TPM2B_ENCRYPTED_SECRET *secret, TPM2B_DIGEST **cert_info,
        TPM2B_DIGEST *cp_hash, TPM2B_DIGEST *rp_hash,
        TPMI_ALG_HASH parameter_hash_algorithm, ESYS_TR shandle3);

tool_rc tpm2_create(ESYS_CONTEXT *esys_context, tpm2_loaded_object *parent_obj,
        const TPM2B_SENSITIVE_CREATE *in_sensitive, const TPM2B_PUBLIC *in_public,
        const TPM2B_DATA *outside_info, const TPML_PCR_SELECTION *creation_pcr,
        TPM2B_PRIVATE **out_private, TPM2B_PUBLIC **out_public,
        TPM2B_CREATION_DATA **creation_data, TPM2B_DIGEST **creation_hash,
        TPMT_TK_CREATION **creation_ticket, TPM2B_DIGEST *cp_hash,
        TPM2B_DIGEST *rp_hash, TPMI_ALG_HASH parameter_hash_algorithm,
        ESYS_TR shandle2, ESYS_TR shandle3);

tool_rc tpm2_create_loaded(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *parent_obj,
        const TPM2B_SENSITIVE_CREATE *in_sensitive,
        const TPM2B_TEMPLATE *in_public, ESYS_TR *object_handle,
        TPM2B_PRIVATE **out_private, TPM2B_PUBLIC **out_public,
        TPM2B_DIGEST *cp_hash, TPM2B_DIGEST *rp_hash,
        TPMI_ALG_HASH parameter_hash_algorithm, ESYS_TR shandle2,
        ESYS_TR shandle3);

tool_rc tpm2_object_change_auth(ESYS_CONTEXT *esys_context,
    tpm2_loaded_object *parent_object, tpm2_loaded_object *object,
    const TPM2B_AUTH *new_auth, TPM2B_PRIVATE **out_private,
    TPM2B_DIGEST *cp_hash, TPM2B_DIGEST *rp_hash,
    TPMI_ALG_HASH parameter_hash_algorithm, ESYS_TR shandle2,
    ESYS_TR shandle3);

tool_rc tpm2_nv_change_auth(ESYS_CONTEXT *esys_context, tpm2_loaded_object *nv,
    const TPM2B_AUTH *new_auth, TPM2B_DIGEST *cp_hash, TPM2B_DIGEST *rp_hash,
    TPMI_ALG_HASH parameter_hash_algorithm, ESYS_TR shandle2,
    ESYS_TR shandle3);

tool_rc tpm2_hierarchy_change_auth(ESYS_CONTEXT *esys_context,
    tpm2_loaded_object *hierarchy, const TPM2B_AUTH *new_auth,
    TPM2B_DIGEST *cp_hash, TPM2B_DIGEST *rp_hash,
    TPMI_ALG_HASH parameter_hash_algorithm, ESYS_TR shandle2,
    ESYS_TR shandle3);

tool_rc tpm2_certify(ESYS_CONTEXT *esys_context,
    tpm2_loaded_object *certifiedkey_obj,
    tpm2_loaded_object *signingkey_obj, TPM2B_DATA *qualifying_data,
    TPMT_SIG_SCHEME *scheme, TPM2B_ATTEST **certify_info,
    TPMT_SIGNATURE **signature, TPM2B_DIGEST *cp_hash, TPM2B_DIGEST *rp_hash,
    TPMI_ALG_HASH parameter_hash_algorithm, ESYS_TR shandle3);

tool_rc tpm2_rsa_decrypt(ESYS_CONTEXT *esys_context, tpm2_loaded_object *keyobj,
        const TPM2B_PUBLIC_KEY_RSA *cipher_text,
        const TPMT_RSA_DECRYPT *in_scheme, const TPM2B_DATA *label,
        TPM2B_PUBLIC_KEY_RSA **message, TPM2B_DIGEST *cp_hash);

tool_rc tpm2_rsa_encrypt(ESYS_CONTEXT *ectx, tpm2_loaded_object *keyobj,
        const TPM2B_PUBLIC_KEY_RSA *message, const TPMT_RSA_DECRYPT *scheme,
        const TPM2B_DATA *label, TPM2B_PUBLIC_KEY_RSA **cipher_text);

tool_rc tpm2_load(ESYS_CONTEXT *esys_context, tpm2_loaded_object *parentobj,
        const TPM2B_PRIVATE *in_private, const TPM2B_PUBLIC *in_public,
        ESYS_TR *object_handle, TPM2B_DIGEST *cp_hash);

tool_rc tpm2_clear(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *auth_hierarchy, TPM2B_DIGEST *cp_hash);

tool_rc tpm2_clearcontrol(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *auth_hierarchy, TPMI_YES_NO disable_clear,
        TPM2B_DIGEST *cp_hash);

tool_rc tpm2_clockrateadjust(ESYS_CONTEXT *ectx, tpm2_loaded_object *object,
        TPM2_CLOCK_ADJUST rate_adjust, TPM2B_DIGEST *cp_hash);

tool_rc tpm2_dictionarylockout_reset(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *auth_hierarchy, TPM2B_DIGEST *cp_hash);

tool_rc tpm2_dictionarylockout_setup(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *auth_hierarchy, UINT32 max_tries,
        UINT32 recovery_time, UINT32 lockout_recovery_time,
        TPM2B_DIGEST *cp_hash);

tool_rc tpm2_duplicate(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *duplicable_key, tpm2_loaded_object *new_parent_handle,
        const TPM2B_DATA *in_key, const TPMT_SYM_DEF_OBJECT *sym_alg,
        TPM2B_DATA **out_key, TPM2B_PRIVATE **duplicate,
        TPM2B_ENCRYPTED_SECRET **encrypted_seed, TPM2B_DIGEST *cp_hash);

tool_rc tpm2_encryptdecrypt(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *encryption_key_obj, TPMI_YES_NO decrypt,
        TPMI_ALG_SYM_MODE mode, const TPM2B_IV *iv_in,
        const TPM2B_MAX_BUFFER *input_data, TPM2B_MAX_BUFFER **output_data,
        TPM2B_IV **iv_out, TPM2B_DIGEST *cp_hash);

tool_rc tpm2_hierarchycontrol(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *auth_hierarchy, TPMI_RH_ENABLES enable,
        TPMI_YES_NO state, TPM2B_DIGEST *cp_hash);

tool_rc tpm2_hmac(ESYS_CONTEXT *esys_context, tpm2_loaded_object *hmac_key_obj,
        TPMI_ALG_HASH halg, const TPM2B_MAX_BUFFER *input_buffer,
        TPM2B_DIGEST **out_hmac, TPM2B_DIGEST *cp_hash);

tool_rc tpm2_hmac_start(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *hmac_key_obj, TPMI_ALG_HASH halg,
        ESYS_TR *sequence_handle);

tool_rc tpm2_hmac_sequenceupdate(ESYS_CONTEXT *esys_context,
        ESYS_TR sequence_handle, tpm2_loaded_object *hmac_key_obj,
        const TPM2B_MAX_BUFFER *input_buffer);

tool_rc tpm2_hmac_sequencecomplete(ESYS_CONTEXT *esys_context,
        ESYS_TR sequence_handle, tpm2_loaded_object *hmac_key_obj,
        const TPM2B_MAX_BUFFER *input_buffer, TPM2B_DIGEST **result,
        TPMT_TK_HASHCHECK **validation);

tool_rc tpm2_import(ESYS_CONTEXT *esys_context, tpm2_loaded_object *parent_obj,
        const TPM2B_DATA *encryption_key, const TPM2B_PUBLIC *object_public,
        const TPM2B_PRIVATE *duplicate, const TPM2B_ENCRYPTED_SECRET *in_sym_seed,
        const TPMT_SYM_DEF_OBJECT *symmetric_alg, TPM2B_PRIVATE **out_private,
        TPM2B_DIGEST *cp_hash);

tool_rc tpm2_nv_definespace(ESYS_CONTEXT *esys_context,
    tpm2_loaded_object *auth_hierarchy_obj, const TPM2B_AUTH *auth,
    const TPM2B_NV_PUBLIC *public_info, TPM2B_DIGEST *cp_hash,
    TPM2B_DIGEST *rp_hash, TPMI_ALG_HASH parameter_hash_algorithm,
    ESYS_TR shandle2, ESYS_TR shandle3);

tool_rc tpm2_nvextend(ESYS_CONTEXT *esys_context,
    tpm2_loaded_object *auth_hierarchy_obj, TPM2_HANDLE nv_index,
    TPM2B_MAX_NV_BUFFER *data, TPM2B_DIGEST *cp_hash, TPM2B_DIGEST *rp_hash,
    TPMI_ALG_HASH parameter_hash_algorithm, ESYS_TR shandle2,
    ESYS_TR shandle3);

tool_rc tpm2_nv_increment(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *auth_hierarchy_obj, TPM2_HANDLE nv_index,
        TPM2B_DIGEST *cp_hash);

tool_rc tpm2_nvreadlock(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *auth_hierarchy_obj, TPM2_HANDLE nv_index,
        TPM2B_DIGEST *cp_hash);

tool_rc tpm2_nvglobalwritelock(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *auth_hierarchy_obj, TPM2B_DIGEST *cp_hash);

tool_rc tpm2_nvwritelock(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *auth_hierarchy_obj, TPM2_HANDLE nv_index,
        TPM2B_DIGEST *cp_hash);

tool_rc tpm2_tr_from_tpm_public(ESYS_CONTEXT *esys_context,
        TPM2_HANDLE handle, ESYS_TR *tr_handle);

tool_rc tpm2_nvsetbits(ESYS_CONTEXT *esys_context,
    tpm2_loaded_object *auth_hierarchy_obj, TPM2_HANDLE nv_index,
    UINT64 bits, TPM2B_DIGEST *cp_hash, TPM2B_DIGEST *rp_hash,
    TPMI_ALG_HASH parameter_hash_algorithm, ESYS_TR shandle2,
    ESYS_TR shandle3);

tool_rc tpm2_nvundefine(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *auth_hierarchy_obj, TPM2_HANDLE nv_index,
         TPM2B_DIGEST *cp_hash);

tool_rc tpm2_nvundefinespecial(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *auth_hierarchy_obj, TPM2_HANDLE nv_index,
        tpm2_session *policy_session,  TPM2B_DIGEST *cp_hash);

tool_rc tpm2_nvwrite(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *auth_hierarchy_obj, TPM2_HANDLE nvindex,
        const TPM2B_MAX_NV_BUFFER *data, UINT16 offset, TPM2B_DIGEST *cp_hash);

tool_rc tpm2_pcr_allocate(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *auth_hierarchy_obj,
        const TPML_PCR_SELECTION *pcr_allocation);

tool_rc tpm2_sign(ESYS_CONTEXT *esys_context, tpm2_loaded_object *signingkey_obj,
        TPM2B_DIGEST *digest, TPMT_SIG_SCHEME *in_scheme,
        TPMT_TK_HASHCHECK *validation, TPMT_SIGNATURE **signature,
        TPM2B_DIGEST *cp_hash);

tool_rc tpm2_quote(ESYS_CONTEXT *esys_context, tpm2_loaded_object *quote_obj,
        TPMT_SIG_SCHEME *in_scheme, TPM2B_DATA *qualifying_data,
        TPML_PCR_SELECTION *PCRselect, TPM2B_ATTEST **quoted,
        TPMT_SIGNATURE **signature, TPM2B_DIGEST *cp_hash);

tool_rc tpm2_changeeps(ESYS_CONTEXT *ectx,
    tpm2_session *platform_hierarchy_session, TPM2B_DIGEST *cp_hash,
    TPM2B_DIGEST *rp_hash, TPMI_ALG_HASH parameter_hash_algorithm,
    ESYS_TR shandle2, ESYS_TR shandle3);

tool_rc tpm2_changepps(ESYS_CONTEXT *ectx,
    tpm2_session *platform_hierarchy_session, TPM2B_DIGEST *cp_hash,
    TPM2B_DIGEST *rp_hash, TPMI_ALG_HASH parameter_hash_algorithm,
    ESYS_TR shandle2, ESYS_TR shandle3);

tool_rc tpm2_unseal(ESYS_CONTEXT *esys_context, tpm2_loaded_object *sealkey_obj,
    TPM2B_SENSITIVE_DATA **out_data, TPM2B_DIGEST *cp_hash,
    TPM2B_DIGEST *rp_hash, TPMI_ALG_HASH parameter_hash_algorithm,
    ESYS_TR shandle2, ESYS_TR shandle3);

tool_rc tpm2_policy_authorize_nv(ESYS_CONTEXT *esys_context,
    tpm2_loaded_object *auth_entity_obj, TPM2_HANDLE nv_index,
    ESYS_TR policy_session, TPM2B_DIGEST *cp_hash);

tool_rc tpm2_incrementalselftest(ESYS_CONTEXT *ectx, const TPML_ALG *to_test,
        TPML_ALG **to_do_list);

tool_rc tpm2_stirrandom(ESYS_CONTEXT *ectx, const TPM2B_SENSITIVE_DATA *data);

tool_rc tpm2_selftest(ESYS_CONTEXT *ectx, TPMI_YES_NO full_test);

tool_rc tpm2_gettestresult(ESYS_CONTEXT *ectx, TPM2B_MAX_BUFFER **out_data,
        TPM2_RC *test_result);

tool_rc tpm2_loadexternal(ESYS_CONTEXT *ectx, const TPM2B_SENSITIVE *private,
        const TPM2B_PUBLIC *public, TPMI_RH_HIERARCHY hierarchy,
        ESYS_TR *object_handle);

tool_rc tpm2_pcr_event(ESYS_CONTEXT *ectx, ESYS_TR pcr, tpm2_session *session,
        const TPM2B_EVENT *event_data, TPML_DIGEST_VALUES **digests);

tool_rc tpm2_getrandom(ESYS_CONTEXT *ectx, UINT16 count,
        TPM2B_DIGEST **random, TPM2B_DIGEST *cp_hash, TPM2B_DIGEST *rp_hash,
        ESYS_TR session_handle_1, ESYS_TR session_handle_2,
        ESYS_TR session_handle_3, TPMI_ALG_HASH param_hash_algorithm) ;

tool_rc tpm2_startup(ESYS_CONTEXT *ectx, TPM2_SU startup_type);

tool_rc tpm2_pcr_reset(ESYS_CONTEXT *ectx, ESYS_TR pcr_handle);

tool_rc tpm2_makecredential(ESYS_CONTEXT *ectx, ESYS_TR handle,
        const TPM2B_DIGEST *credential, const TPM2B_NAME *object_name,
        TPM2B_ID_OBJECT **credential_blob, TPM2B_ENCRYPTED_SECRET **secret);

tool_rc tpm2_verifysignature(ESYS_CONTEXT *ectx, ESYS_TR key_handle,
        const TPM2B_DIGEST *digest, const TPMT_SIGNATURE *signature,
        TPMT_TK_VERIFIED **validation);

tool_rc tpm2_readclock(ESYS_CONTEXT *ectx, TPMS_TIME_INFO **current_time);

tool_rc tpm2_setclock(ESYS_CONTEXT *ectx, tpm2_loaded_object *object,
UINT64 new_time, TPM2B_DIGEST *cp_hash);

tool_rc tpm2_shutdown(ESYS_CONTEXT *ectx, TPM2_SU shutdown_type);

tool_rc tpm2_policy_nv(ESYS_CONTEXT *esys_context,
    tpm2_loaded_object *auth_entity_obj, TPM2_HANDLE nv_index,
    ESYS_TR policy_session, const TPM2B_OPERAND *operand_b, UINT16 offset,
    TPM2_EO operation, TPM2B_DIGEST *cp_hash);

tool_rc tpm2_policy_countertimer(ESYS_CONTEXT *esys_context,
    ESYS_TR policy_session, const TPM2B_OPERAND *operand_b, UINT16 offset,
    TPM2_EO operation);

tool_rc tpm2_policy_nv_written(ESYS_CONTEXT *esys_context,
        ESYS_TR policy_session, ESYS_TR shandle1, ESYS_TR shandle2,
        ESYS_TR shandle3, TPMI_YES_NO written_set);

TSS2_RC fix_esys_hierarchy(uint32_t in, uint32_t *out);

tool_rc tpm2_certifycreation(ESYS_CONTEXT *esys_context,
    tpm2_loaded_object *signingkey_obj, tpm2_loaded_object *certifiedkey_obj,
    TPM2B_DIGEST *creation_hash, TPMT_SIG_SCHEME *in_scheme,
    TPMT_TK_CREATION *creation_ticket, TPM2B_ATTEST **certify_info,
    TPMT_SIGNATURE **signature, TPM2B_DATA *policy_qualifier,
    TPM2B_DIGEST *cp_hash, TPM2B_DIGEST *rp_hash,
    TPMI_ALG_HASH parameter_hash_algorithm, ESYS_TR shandle2, ESYS_TR shandle3);

tool_rc tpm2_nvcertify(ESYS_CONTEXT *esys_context,
    tpm2_loaded_object *signingkey_obj, tpm2_loaded_object *nvindex_authobj,
    TPM2_HANDLE nv_index, UINT16 offset, UINT16 size,
    TPMT_SIG_SCHEME *in_scheme, TPM2B_ATTEST **certify_info,
    TPMT_SIGNATURE **signature, TPM2B_DATA *policy_qualifier,
    TPM2B_DIGEST *cp_hash);

tool_rc tpm2_setprimarypolicy(ESYS_CONTEXT *esys_context,
    tpm2_loaded_object *hierarchy_object, TPM2B_DIGEST *auth_policy,
    TPMI_ALG_HASH hash_algorithm, TPM2B_DIGEST *cp_hash);

tool_rc tpm2_gettime(ESYS_CONTEXT *ectx,
        tpm2_loaded_object *privacy_admin,
        tpm2_loaded_object *signing_object,
        const TPM2B_DATA *qualifying_data,
        const TPMT_SIG_SCHEME *scheme,
        TPM2B_ATTEST **time_info,
        TPMT_SIGNATURE **signature,
        TPM2B_DIGEST *cp_hash);

tool_rc tpm2_setcommandcodeaudit(ESYS_CONTEXT *esys_context,
    tpm2_loaded_object *auth_entity_obj, TPMI_ALG_HASH hash_algorithm,
    const TPML_CC *setlist, const TPML_CC *clearlist);

tool_rc tpm2_getcommandauditdigest(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *privacy_object, tpm2_loaded_object *sign_object,
        TPMT_SIG_SCHEME *in_scheme, TPM2B_DATA *qualifying_data,
        TPM2B_ATTEST **audit_info, TPMT_SIGNATURE **signature);

tool_rc tpm2_getsessionauditdigest(ESYS_CONTEXT *esys_context,
        tpm2_loaded_object *privacy_object, tpm2_loaded_object *sign_object,
        TPMT_SIG_SCHEME *in_scheme, TPM2B_DATA *qualifying_data,
        TPM2B_ATTEST **audit_info, TPMT_SIGNATURE **signature,
        ESYS_TR audit_session_handle);

tool_rc tpm2_geteccparameters(ESYS_CONTEXT *esys_context,
    TPMI_ECC_CURVE curve_id, TPMS_ALGORITHM_DETAIL_ECC **parameters);

tool_rc tpm2_ecephemeral(ESYS_CONTEXT *esys_context, TPMI_ECC_CURVE curve_id,
    TPM2B_ECC_POINT **Q, uint16_t *counter);

tool_rc tpm2_commit(ESYS_CONTEXT *esys_context,
    tpm2_loaded_object *signing_key_object, TPM2B_ECC_POINT *P1,
    TPM2B_SENSITIVE_DATA *s2, TPM2B_ECC_PARAMETER *y2, TPM2B_ECC_POINT **K,
    TPM2B_ECC_POINT **L, TPM2B_ECC_POINT **E, uint16_t *counter);

tool_rc tpm2_ecdhkeygen(ESYS_CONTEXT *esys_context,
    tpm2_loaded_object *ecc_public_key, TPM2B_ECC_POINT **Z,
    TPM2B_ECC_POINT **Q);

tool_rc tpm2_ecdhzgen(ESYS_CONTEXT *esys_context,
    tpm2_loaded_object *ecc_key_object, TPM2B_ECC_POINT **Z,
    TPM2B_ECC_POINT *Q);

tool_rc tpm2_zgen2phase(ESYS_CONTEXT *esys_context,
    tpm2_loaded_object *ecc_key_object, TPM2B_ECC_POINT *Q1,
    TPM2B_ECC_POINT *Q2, TPM2B_ECC_POINT **Z1, TPM2B_ECC_POINT **Z2,
    TPMI_ECC_KEY_EXCHANGE keyexchange_scheme, UINT16 commit_counter);

tool_rc tpm2_getsapicontext(ESYS_CONTEXT *esys_context,
    TSS2_SYS_CONTEXT **sys_context);

tool_rc tpm2_sapi_getcphash(TSS2_SYS_CONTEXT *sys_context,
    const TPM2B_NAME *name1, const TPM2B_NAME *name2, const TPM2B_NAME *name3,
    TPMI_ALG_HASH halg, TPM2B_DIGEST *cp_hash);

tool_rc tpm2_sapi_getrphash(TSS2_SYS_CONTEXT *sys_context,
    TSS2_RC response_code, TPM2B_DIGEST *rp_hash, TPMI_ALG_HASH halg);

#endif /* LIB_TPM2_H_ */
