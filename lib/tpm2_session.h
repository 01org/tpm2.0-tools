/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef SRC_TPM2_SESSION_H_
#define SRC_TPM2_SESSION_H_

#include <stdbool.h>

#include <tss2/tss2_esys.h>

#include "tool_rc.h"

typedef struct tpm2_session_data tpm2_session_data;
typedef struct tpm2_session tpm2_session;

/**
 * Creates a new session data object, based around the inputs to
 * TPM2_StartAuthSession as listed in Section 11.1:
 *   https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
 *
 * The defaults are set to:
 *   tpmKey = TPM2_RH_NULL
 *   bind = TPM2_RH_NULL
 *   nonceCaller = a SHA1 hash of all 0s.
 *   symmetric = TPM2_ALG_NULL
 *   authHash = TPM2_ALG_SHA256
 ^ *
 * @param type
 *  The type of policy session, one of:
 *    - TPM2_SE_HMAC   - For an HMAC session.
 *    - TPM2_SE_POLICY - For a policy session.
 *    - TPM2_SE_TRIAL  - For a trial session, useful for building policies.
 * @return
 *  A tpm2_session_data object on success, NULL on failure.
 */
tpm2_session_data *tpm2_session_data_new(TPM2_SE type);

/**
 * Sets the tpmKey parameter.
 * @param data
 *  The session data object to modify.
 * @param key
 *  The tpmKey parameter value itself.
 */
void tpm2_session_set_key(tpm2_session_data *data, TPMI_DH_OBJECT key);

/**
 * Sets the nonceCaller parameter.
 * @param data
 *  The session data object to modify.
 * @param nonce
 *  The nonce parameter value itself.
 */
void tpm2_session_set_nonce_caller(tpm2_session_data *data, TPM2B_NONCE *nonce);

/**
 * Retrieves the session nonce
 *
 * @param ectx
 *  The ESAPI context
 * @param session
 *  The session started
 * @param nonce_tpm
 *  The nonceTPM for the session
 *
 */
tool_rc tpm2_session_get_noncetpm(ESYS_CONTEXT *ectx, tpm2_session *session,
    TPM2B_NONCE **nonce_tpm);

/**
 * Sets the bind parameter.
 * @param data
 *  The session data object to modify.
 * @param bind
 *  The bind parameter value itself.
 */
void tpm2_session_set_bind(tpm2_session_data *data, TPMI_DH_ENTITY bind);

/**
 * Sets the symmetric parameter.
 * @param data
 *  The session data object to modify.
 * @param symmetric
 *  The symmetric parameter value itself.
 */
void tpm2_session_set_symmetric(tpm2_session_data *data,
        TPMT_SYM_DEF *symmetric);

/**
 * Sets the authHash parameter.
 * @param data
 *  The session data object to modify.
 * @param auth_hash
 *  The authHash parameter value itself.
 */
void tpm2_session_set_authhash(tpm2_session_data *data, TPMI_ALG_HASH auth_hash);

void tpm2_session_set_path(tpm2_session_data *data, const char *path);

/**
 * Set the session attributes
 * @param data
 *  The session data to set
 * @param attrs
 *  The session attributes to use.
 */
void tpm2_session_set_attrs(tpm2_session_data *data, TPMA_SESSION attrs);

/**
 * Retrieves the authHash parameter used to start the authorization session.
 * @param session
 *  The tpm2_session started with tpm2_session_new().
 * @return
 *  The authHash value.
 */
TPMI_ALG_HASH tpm2_session_get_authhash(tpm2_session *session);

/**
 * Retrieves the session handle from starting the authorization session
 * with tpm2_session_new().
 * @param session
 *  The session started with tpm2_session_new().
 * @return
 *  The session handle.
 */
ESYS_TR tpm2_session_get_handle(tpm2_session *session);

/**
 * Retrieves the type of session, ie trial or policy session.
 * @param session
 * @return
 *  The type of the session, either TPM2_SE_HMAC, TPM2_SE_POLICY or
 *  TPM2_SE_TRIAL.
 */
TPM2_SE tpm2_session_get_type(tpm2_session *session);

/**
 * True if a session is of type TPM2_SE_TRIAL
 * @param session
 *  The session to check the type of.
 * @return
 *  True if a session is of type TPM2_SE_TRIAL, false otherwise.
 */
static inline bool tpm2_session_is_trial(tpm2_session *session) {
    return tpm2_session_get_type(session) == TPM2_SE_TRIAL;
}

/**
 * Starts a session with the tpm via StartAuthSession().
 * @param context
 *  The Enhanced System API (ESAPI) context.
 * @param data
 *  A session data object created with tpm2_session_data_new() and potentially
 *  modified with the tpm2_session_data_set_*() routines.
 *  This pointer is owned by the tpm2_session object and the caller can
 *  forget about it at this point.
 * @param session
 *  The output session on success.
 * @return
 *  A tool_rc indicating status.
 */
tool_rc tpm2_session_open(ESYS_CONTEXT *context, tpm2_session_data *data,
        tpm2_session **session);

tool_rc tpm2_session_open_password(tpm2_session **session, const char *password);

/**
 * Saves session data to disk allowing tpm2_session_from_file() to
 * restore the session if applicable and frees resources.
 *
 * @Note
 * This is accomplished by calling:
 *   - Eys_ContextSave - marks to some RMs like tpm2-abrmd not to flush this session
 *                            handle on client disconnection.
 *   - Eys_ContextLoad - restores the session so it can be used.
 *   - Saving a custom file format at path - records the handle and algorithm.
 * @param session
 *  The session context to save
 * @return
 *  tool_rc indicating status.
 */
tool_rc tpm2_session_close(tpm2_session **session);

/**
 * Restores a session saved with tpm2_session_save().
 * @param context
 *  The Enhanced System API (ESAPI) context
 * @param path
 *  The path to restore from.
 * @param is_final
 *  True if this is is the last tool to use the session, causes a flush.
 * @param session
 *  The session
 * @return
 *  tool_rc indicating status.
 */
tool_rc tpm2_session_restore(ESYS_CONTEXT *ctx, const char *path, bool is_final,
        tpm2_session **session);

/**
 * restarts the session to it's initial state via a call to
 * PolicyRestart().
 * @param context
 *  The Enhanced System API (ESAPI) context
 * @param s
 *  The session
 * @return
 *  tool_rc indicating status.
 */
tool_rc tpm2_session_restart(ESYS_CONTEXT *context, tpm2_session *s);

tpm2_session_data *tpm2_hmac_session_data_new(TPM2B_AUTH *auth_value);

void tpm2_session_set_auth_value(tpm2_session *session, TPM2B_AUTH *auth_value);

const TPM2B_AUTH *tpm2_session_get_auth_value(tpm2_session *session);

#endif /* SRC_TPM2_SESSION_H_ */
