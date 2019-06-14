#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_esys.h>

#include "files.h"
#include "log.h"
#include "object.h"
#include "tpm2_auth_util.h"
#include "tpm2_hierarchy.h"

#define NULL_OBJECT "null"
#define NULL_OBJECT_LEN (sizeof(NULL_OBJECT) - 1)

static tool_rc do_ctx_file(ESYS_CONTEXT *ctx,
        const char *objectstr,
        FILE *f,
        tpm2_loaded_object *outobject) {
    /* assign a dummy transient handle */
    outobject->handle = TPM2_TRANSIENT_FIRST;
    outobject->path = objectstr;
    return files_load_tpm_context_from_file(ctx,
            &outobject->tr_handle, f);
}

static tool_rc tpm2_util_object_load2(
            ESYS_CONTEXT *ctx,
            const char *objectstr,
            const char *auth,
            bool do_auth,
            tpm2_loaded_object *outobject,
            bool is_restricted_pswd_session) {

    ctx = is_restricted_pswd_session ? NULL: ctx;

    if (do_auth) {
        tpm2_session *s = NULL;
        tool_rc rc = tpm2_auth_util_from_optarg(ctx, auth, &s,
            is_restricted_pswd_session);
        if (rc != tool_rc_success) {
            return rc;
        }

        outobject->session = s;
    }

    if (!objectstr) {
        LOG_ERR("object string is empty");
        return tool_rc_general_error;
    }

    // 1. Always attempt file
    FILE *f = fopen(objectstr, "rb");
    if (f) {
        tool_rc rc = do_ctx_file(ctx, objectstr, f, outobject);
        fclose(f);
        return rc;
    }

    // 2. Try to convert a hierarchy or raw handle
    TPMI_RH_PROVISION handle;
    bool result = tpm2_hierarchy_from_optarg(objectstr, &handle,
            TPM2_HIERARCHY_FLAGS_ALL|TPM2_HIERARCHY_SUPPRESS);
    if (result){
        outobject->handle = handle;
        outobject->path = NULL;
        return tpm2_util_sys_handle_to_esys_handle(ctx, outobject->handle, &outobject->tr_handle);
    }

    LOG_ERR("Cannot make sense of object context \"%s\"", objectstr);

    return tool_rc_general_error;
}

tool_rc tpm2_util_object_load(ESYS_CONTEXT *ctx,
            const char *objectstr, tpm2_loaded_object *outobject) {

    return tpm2_util_object_load2(ctx, objectstr, NULL, false, outobject, false);
}

tool_rc tpm2_util_object_load_auth(
            ESYS_CONTEXT *ctx,
            const char *objectstr,
            const char *auth,
            tpm2_loaded_object *outobject,
            bool is_restricted_pswd_session) {

    return tpm2_util_object_load2(ctx, objectstr, auth, true, outobject,
        is_restricted_pswd_session);
}
