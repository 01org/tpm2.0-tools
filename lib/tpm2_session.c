/* SPDX-License-Identifier: BSD-3-Clause */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_session.h"

struct tpm2_session_data {
    ESYS_TR key;
    ESYS_TR bind;
    TPM2_SE session_type;
    TPMT_SYM_DEF symmetric;
    TPMI_ALG_HASH auth_hash;
    TPM2B_NONCE nonce_caller;
    TPMA_SESSION attrs;
    TPM2B_AUTH auth_data;
    const char *path;
};

struct tpm2_session {

    tpm2_session_data* input;

    struct {
        ESYS_TR session_handle;
    } output;

    struct {
        char *path;
        ESYS_CONTEXT *ectx;
        bool is_final;
    } internal;
};

tpm2_session_data *tpm2_session_data_new(TPM2_SE type) {
    tpm2_session_data * d = calloc(1, sizeof(tpm2_session_data));
    if (d) {
        d->symmetric.algorithm = TPM2_ALG_NULL;
        d->key = ESYS_TR_NONE;
        d->bind = ESYS_TR_NONE;
        d->session_type = type;
        d->auth_hash = TPM2_ALG_SHA256;
    }
    return d;
}

void tpm2_session_set_key(tpm2_session_data *data, ESYS_TR key) {
    data->key = key;
}

void tpm2_session_set_attrs(tpm2_session_data *data, TPMA_SESSION attrs) {
    data->attrs = attrs;
}

void tpm2_session_set_auth_value(tpm2_session *session, TPM2B_AUTH *auth) {

    if (auth == NULL) {
        session->input->auth_data.size = 0;
        memset(session->input->auth_data.buffer, 0xBA,
                sizeof(session->input->auth_data.buffer));
    } else {
        memcpy(&session->input->auth_data, auth, sizeof(*auth));
    }
}

void tpm2_session_set_nonce_caller(tpm2_session_data *data, TPM2B_NONCE *nonce) {
    data->nonce_caller = *nonce;
}

void tpm2_session_set_bind(tpm2_session_data *data, ESYS_TR bind) {
    data->bind = bind;
}

void tpm2_session_set_type(tpm2_session_data *data, TPM2_SE type) {
    data->session_type = type;
}

void tpm2_session_set_symmetric(tpm2_session_data *data,
        TPMT_SYM_DEF *symmetric) {
    data->symmetric = *symmetric;
}

void tpm2_session_set_authhash(tpm2_session_data *data, TPMI_ALG_HASH auth_hash) {
    data->auth_hash = auth_hash;
}

void tpm2_session_set_path(tpm2_session_data *data, const char *path) {
    data->path = path;
}

TPMI_ALG_HASH tpm2_session_get_authhash(tpm2_session *session) {
    return session->input->auth_hash;
}

ESYS_TR tpm2_session_get_handle(tpm2_session *session) {
    return session->output.session_handle;
}

TPM2_SE tpm2_session_get_type(tpm2_session *session) {
    return session->input->session_type;
}

const TPM2B_AUTH *tpm2_session_get_auth_value(tpm2_session *session) {
    return &session->input->auth_data;
}

//
// This is a wrapper function around the StartAuthSession command.
// It performs the command, calculates the session key, and updates a
// SESSION structure.
//
static tool_rc start_auth_session(tpm2_session *session) {

    tpm2_session_data *d = session->input;

    TPM2B_NONCE *nonce =
            session->input->nonce_caller.size > 0 ?
                    &session->input->nonce_caller : NULL;

    tool_rc rc = tpm2_start_auth_session(session->internal.ectx, d->key,
            d->bind, nonce, d->session_type, &d->symmetric, d->auth_hash,
            &session->output.session_handle);
    if (rc != tool_rc_success) {
        return rc;
    }

    if (d->attrs) {
        rc = tpm2_sess_set_attributes(session->internal.ectx,
                session->output.session_handle, d->attrs, 0xff);
        if (rc != tool_rc_success) {
            tool_rc tmp_rc = tpm2_flush_context(session->internal.ectx,
                    session->output.session_handle);
            UNUSED(tmp_rc);
            return rc;
        }
    }

    return tool_rc_success;
}

static void tpm2_session_free(tpm2_session **session) {

    tpm2_session *s = *session;

    if (s) {
        free(s->input);
        if (s->internal.path) {
            free(s->internal.path);
        }
        free(s);
        *session = NULL;
    }
}

tool_rc tpm2_session_open(ESYS_CONTEXT *context, tpm2_session_data *data,
        tpm2_session **session) {

    tpm2_session *s = calloc(1, sizeof(tpm2_session));
    if (!s) {
        free(data);
        LOG_ERR("oom");
        return tool_rc_general_error;
    }

    if (data->path) {
        s->internal.path = strdup(data->path);
        if (!s->internal.path) {
            LOG_ERR("oom");
            tpm2_session_free(&s);
            return tool_rc_general_error;
        }
    }

    s->input = data;
    s->internal.ectx = context;

    if (!context) {
        s->output.session_handle = ESYS_TR_PASSWORD;
        *session = s;
        return tool_rc_success;
    }

    tool_rc rc = start_auth_session(s);
    if (rc != tool_rc_success) {
        tpm2_session_free(&s);
        return rc;
    }

    *session = s;

    return tool_rc_success;
}

tool_rc tpm2_session_open_password(tpm2_session **session, const char *password) {

    tpm2_session *s = calloc(1, sizeof(tpm2_session));
    if (!s) {
        LOG_ERR("oom");
        return tool_rc_general_error;
    }

    s->input = calloc(1, sizeof(tpm2_session_data));
    if (!s->input) {
        free(s);
        LOG_ERR("oom");
        return tool_rc_general_error;
    }

    if (password) {
        if (strlen(password) > sizeof(s->input->auth_data.buffer)) {
            LOG_ERR("Password too big, got %zu is greater than %zu",
                strlen(password), sizeof(s->input->auth_data.buffer));
            free(s->input);
            free(s);
        }

        s->input->auth_data.size = strlen(password);
        memcpy(s->input->auth_data.buffer, password, s->input->auth_data.size);

    }

	s->output.session_handle = ESYS_TR_PASSWORD;
	*session = s;
    return tool_rc_success;
}

/* SESSION_VERSION 1 was used prior to the switch to ESAPI. As the types of
 * several of the tpm2_session_data object members have changed the version is
 * bumped.
 */
#define SESSION_VERSION 2

/*
 * Checks that two types are equal in size.
 *
 * It works by leveraging the fact that C does not allow negative array sizes.
 * If the sizes are equal, the boolean equality operator will return 1, thus
 * a subtraction of 1 yields 0, which is a legal array size in C. In the false
 * case (ie sizes not equal), 0 - 1 is -1, which will cause the compiler to
 * complain.
 */
#define COMPILE_ASSERT_SIZE(a, b) \
    typedef char WRONG_SIZE_##a[(sizeof(a) == sizeof(b)) - 1]

// We check that the TSS library does not change sizes unbeknownst to us.
COMPILE_ASSERT_SIZE(ESYS_TR, UINT32);
COMPILE_ASSERT_SIZE(TPMI_ALG_HASH, UINT16);
COMPILE_ASSERT_SIZE(TPM2_SE, UINT8);

tool_rc tpm2_session_restore(ESYS_CONTEXT *ctx, const char *path, bool is_final,
        tpm2_session **session) {

    tool_rc rc = tool_rc_general_error;
    tpm2_session *s = NULL;

    /*
     * Copy the string internally so callers need
     * not worry about it.
     */
    char *dup_path = strdup(path);
    if (!dup_path) {
        LOG_ERR("oom");
        return tool_rc_general_error;
    }

    FILE *f = fopen(dup_path, "rb");
    if (!f) {
        LOG_ERR("Could not open path \"%s\", due to error: \"%s\"", dup_path,
                strerror(errno));
        free(dup_path);
        return tool_rc_general_error;
    }

    uint32_t version;
    bool result = files_read_header(f, &version);

    TPM2_SE type;
    result = files_read_bytes(f, &type, sizeof(type));
    if (!result) {
        LOG_ERR("Could not read session type");
        goto out;
    }

    TPMI_ALG_HASH auth_hash;
    result = files_read_16(f, &auth_hash);
    if (!result) {
        LOG_ERR("Could not read session digest algorithm");
        goto out;
    }

    ESYS_TR handle;
    tool_rc tmp_rc = files_load_tpm_context_from_file(ctx, &handle, f);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
        LOG_ERR("Could not load session context");
        goto out;
    }

    tpm2_session_data *d = tpm2_session_data_new(type);
    if (!d) {
        LOG_ERR("oom");
        goto out;
    }

    tpm2_session_set_authhash(d, auth_hash);

    tmp_rc = tpm2_session_open(NULL, d, &s);
    if (tmp_rc != tool_rc_success) {
        rc = tmp_rc;
        LOG_ERR("oom new session object");
        goto out;
    }

    s->output.session_handle = handle;
    s->internal.path = dup_path;
    s->internal.ectx = ctx;
    dup_path = NULL;

    TPMA_SESSION attrs = 0;

    if (ctx) {

        /* hack this in here, should be done when starting the session */
        tmp_rc = tpm2_sess_get_attributes(ctx, handle, &attrs);
        UNUSED(tmp_rc);
    }

    s->internal.is_final = is_final;

    *session = s;

    LOG_INFO("Restored session: ESYS_TR(0x%x) attrs(0x%x)", handle, attrs);

    rc = tool_rc_success;

out:
    free(dup_path);
    if (f) {
        fclose(f);
    }

    return rc;
}

tool_rc tpm2_session_get_noncetpm(ESYS_CONTEXT *ectx, tpm2_session *s,
    TPM2B_NONCE **nonce_tpm) {

    ESYS_TR session_handle = tpm2_session_get_handle(s);

    return tpm2_sess_get_noncetpm(ectx, session_handle, nonce_tpm);
}

tool_rc tpm2_session_close(tpm2_session **s) {

    if (!*s) {
        return tool_rc_success;
    }

    /*
     * Do not back up:
     *   - password sessions are implicit
     *   - hmac sessions live the life of the tool
     */
    tool_rc rc = tool_rc_success;
    tpm2_session *session = *s;
    if (session->output.session_handle == ESYS_TR_PASSWORD) {
        goto out2;
    }

    const char *path = session->internal.path;
    FILE *session_file = path ? fopen(path, "w+b") : NULL;
    if (path && !session_file) {
        LOG_ERR("Could not open path \"%s\", due to error: \"%s\"", path,
                strerror(errno));
        rc = tool_rc_general_error;
        goto out;
    }

    bool flush = path ? session->internal.is_final : true;
    if (flush) {
        rc = tpm2_flush_context(session->internal.ectx,
                session->output.session_handle);
        /* done, use rc to indicate status */
        goto out;
    }

    /*
     * Now write the session_type, handle and auth hash data to disk
     */
    bool result = files_write_header(session_file, SESSION_VERSION);
    if (!result) {
        LOG_ERR("Could not write context file header");
        rc = tool_rc_general_error;
        goto out;
    }

    // UINT8 session type:
    TPM2_SE session_type = session->input->session_type;
    result = files_write_bytes(session_file, &session_type,
            sizeof(session_type));
    if (!result) {
        LOG_ERR("Could not write session type");
        rc = tool_rc_general_error;
        goto out;
    }

    // UINT16 - auth hash digest
    TPMI_ALG_HASH hash = tpm2_session_get_authhash(session);
    result = files_write_16(session_file, hash);
    if (!result) {
        LOG_ERR("Could not write auth hash");
        rc = tool_rc_general_error;
        goto out;
    }

    /*
     * Save session context at end of tpm2_session. With tabrmd support it
     * can be reloaded under certain circumstances.
     */

    ESYS_TR handle = tpm2_session_get_handle(session);
    LOG_INFO("Saved session: ESYS_TR(0x%x)", handle);
    rc = files_save_tpm_context_to_file(session->internal.ectx, handle,
    session_file);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not write session context");
        /* done, free session resources and use rc to indicate status */
    }

out:
    if (session_file) {
        fclose(session_file);
    }
out2:
    tpm2_session_free(s);

    return rc;
}

tool_rc tpm2_session_restart(ESYS_CONTEXT *context, tpm2_session *s) {

    ESYS_TR handle = tpm2_session_get_handle(s);

    return tpm2_policy_restart(context, handle, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE);
}
