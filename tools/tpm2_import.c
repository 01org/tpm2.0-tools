/* SPDX-License-Identifier: BSD-3-Clause */

//**********************************************************************;
// Copyright 1999-2018 The OpenSSL Project Authors. All Rights Reserved.
// Licensed under the Apache License 2.0 (the "License"). You may not use
// this file except in compliance with the License. You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://www.openssl.org/source/license.html
//
// EME-OAEP as defined in RFC 2437 (PKCS #1 v2.0)
//
// See Victor Shoup, "OAEP reconsidered," Nov. 2000, <URL:
// http://www.shoup.net/papers/oaep.ps.Z> for problems with the security
// proof for the original OAEP scheme, which EME-OAEP is based on. A new
// proof can be found in E. Fujisaki, T. Okamoto, D. Pointcheval, J. Stern,
// "RSA-OEAP is Still Alive!", Dec. 2000, <URL:http://eprint.iacr.org/2000/061/>.
// The new proof has stronger requirements for the underlying permutation:
// "partial-one-wayness" instead of one-wayness. For the RSA function, this
// is an equivalent notion.
//**********************************************************************;
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <tss2/tss2_mu.h>

#include <openssl/rand.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_errata.h"
#include "tpm2_identity_util.h"
#include "tpm2_openssl.h"
#include "tpm2_options.h"

typedef struct tpm_import_ctx tpm_import_ctx;
struct tpm_import_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } parent;

    char *input_key_file;
    char *public_key_file;
    char *private_key_file;
    char *parent_key_public_file;
    char *name_alg;
    char *attrs; /* The attributes to use */
    char *key_auth_str;
    char *auth_key_file; /* an optional auth string for the input key file for OSSL */
    char *input_seed_file;
    char *input_enc_key_file;
    char *policy;
    bool import_tpm; /* Any param that is exclusively used by import tpm object sets this flag */
    TPMI_ALG_PUBLIC key_type;
    char *cp_hash_path;
};

static tpm_import_ctx ctx = {
    .key_type = TPM2_ALG_ERROR,
    .input_key_file = NULL,
};

static tool_rc readpublic(ESYS_CONTEXT *ectx, ESYS_TR handle,
        TPM2B_PUBLIC **public) {

    return tpm2_readpublic(ectx, handle, public, NULL, NULL);
}

static bool create_import_key_private_data(TPM2B_PRIVATE *private,
        TPMI_ALG_HASH parent_name_alg,
        TPM2B_MAX_BUFFER *encrypted_duplicate_sensitive,
        TPM2B_DIGEST *outer_hmac) {

    //UINT16 hash_size = tpm2_alg_util_get_hash_size(ctx.name_alg);
    UINT16 parent_hash_size = tpm2_alg_util_get_hash_size(parent_name_alg);

    private->size = sizeof(parent_hash_size) + parent_hash_size
            + encrypted_duplicate_sensitive->size;

    size_t hmac_size_offset = 0;
    TSS2_RC rval = Tss2_MU_UINT16_Marshal(parent_hash_size, private->buffer,
            sizeof(parent_hash_size), &hmac_size_offset);
    if (rval != TPM2_RC_SUCCESS)
    {
        LOG_ERR("Error serializing parent hash size");
        return false;
    }

    memcpy(private->buffer + hmac_size_offset, outer_hmac->buffer,
            parent_hash_size);
    memcpy(private->buffer + hmac_size_offset + parent_hash_size,
            encrypted_duplicate_sensitive->buffer,
            encrypted_duplicate_sensitive->size);

    return true;
}

static tool_rc key_import(ESYS_CONTEXT *ectx, TPM2B_PUBLIC *parent_pub,
        TPM2B_SENSITIVE *privkey, TPM2B_PUBLIC *pubkey,
        TPM2B_ENCRYPTED_SECRET *encrypted_seed,
        TPM2B_PRIVATE **imported_private) {

    TPMI_ALG_HASH name_alg = pubkey->publicArea.nameAlg;

    TPM2B_DIGEST *seed = &privkey->sensitiveArea.seedValue;

    /*
     * Create the protection encryption key that gets encrypted with the parents public key.
     */
    TPM2B_DATA enc_sensitive_key = {
        .size = parent_pub->publicArea.parameters.rsaDetail.symmetric.keyBits.sym / 8
    };

    if(enc_sensitive_key.size < 16) {
        LOG_ERR("Calculated wrapping keysize is less than 16 bytes, got: %u", enc_sensitive_key.size);
        return tool_rc_general_error;
    }

    int ossl_rc = RAND_bytes(enc_sensitive_key.buffer, enc_sensitive_key.size);
    if (ossl_rc != 1) {
        LOG_ERR("RAND_bytes failed: %s", ERR_error_string(ERR_get_error(), NULL));
        return tool_rc_general_error;
    }

    /*
     * Calculate the object name.
     */
    TPM2B_NAME pubname = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    bool res = tpm2_identity_create_name(pubkey, &pubname);
    if (!res) {
        return false;
    }

    TPM2B_MAX_BUFFER hmac_key;
    TPM2B_MAX_BUFFER enc_key;
    tpm2_identity_util_calc_outer_integrity_hmac_key_and_dupsensitive_enc_key(
            parent_pub, &pubname, seed, &hmac_key, &enc_key);

    TPM2B_MAX_BUFFER encrypted_inner_integrity = TPM2B_EMPTY_INIT;
    tpm2_identity_util_calculate_inner_integrity(name_alg, privkey, &pubname,
            &enc_sensitive_key,
            &parent_pub->publicArea.parameters.rsaDetail.symmetric,
            &encrypted_inner_integrity);

    TPM2B_DIGEST outer_hmac = TPM2B_EMPTY_INIT;
    TPM2B_MAX_BUFFER encrypted_duplicate_sensitive = TPM2B_EMPTY_INIT;
    tpm2_identity_util_calculate_outer_integrity(parent_pub->publicArea.nameAlg,
            &pubname, &encrypted_inner_integrity, &hmac_key, &enc_key,
            &parent_pub->publicArea.parameters.rsaDetail.symmetric,
            &encrypted_duplicate_sensitive, &outer_hmac);

    TPM2B_PRIVATE private = TPM2B_EMPTY_INIT;
    res = create_import_key_private_data(&private, parent_pub->publicArea.nameAlg,
            &encrypted_duplicate_sensitive, &outer_hmac);
    if (!res) {
        return tool_rc_general_error;
    }

    TPMT_SYM_DEF_OBJECT *sym_alg =
            &parent_pub->publicArea.parameters.rsaDetail.symmetric;

    if (!ctx.cp_hash_path) {
        return tpm2_import(ectx, &ctx.parent.object, &enc_sensitive_key, pubkey,
            &private, encrypted_seed, sym_alg, imported_private, NULL);
    }

    TPM2B_DIGEST cp_hash = { .size = 0 };
    tool_rc rc = tpm2_import(ectx, &ctx.parent.object, &enc_sensitive_key, pubkey,
            &private, encrypted_seed, sym_alg, imported_private, &cp_hash);
    if (rc != tool_rc_success) {
        return rc;
    }

    bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
    if (!result) {
        rc = tool_rc_general_error;
    }
    return rc;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'P':
        ctx.parent.auth_str = value;
        break;
    case 'p':
        ctx.key_auth_str = value;
        break;
    case 'G':
        ctx.key_type = tpm2_alg_util_from_optarg(value,
                tpm2_alg_util_flags_asymmetric | tpm2_alg_util_flags_symmetric | tpm2_alg_util_flags_keyedhash );
        if (ctx.key_type == TPM2_ALG_ERROR) {
            LOG_ERR("Unsupported key type");
            return false;
        }
        return true;
    case 'i':
        ctx.input_key_file = value;
        break;
    case 'C':
        ctx.parent.ctx_path = value;
        break;
    case 'U':
        ctx.parent_key_public_file = value;
        break;
    case 'k':
        ctx.import_tpm = true;
        ctx.input_enc_key_file = value;
        break;
    case 'u':
        ctx.public_key_file = value;
        break;
    case 'r':
        ctx.private_key_file = value;
        break;
    case 'a':
        ctx.attrs = value;
        break;
    case 'g':
        ctx.name_alg = value;
        break;
    case 's':
        ctx.import_tpm = true;
        ctx.input_seed_file = value;
        break;
    case 'L':
        ctx.policy = value;
        break;
    case 0:
        ctx.auth_key_file = value;
        break;
    case 1:
        ctx.cp_hash_path = value;
        break;
    default:
        LOG_ERR("Invalid option");
        return false;
    }

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    const struct option topts[] = {
      { "parent-auth",        required_argument, NULL, 'P'},
      { "key-auth",           required_argument, NULL, 'p'},
      { "key-algorithm",      required_argument, NULL, 'G'},
      { "input",              required_argument, NULL, 'i'},
      { "parent-context",     required_argument, NULL, 'C'},
      { "parent-public",      required_argument, NULL, 'U'},
      { "private",            required_argument, NULL, 'r'},
      { "public",             required_argument, NULL, 'u'},
      { "attributes",  required_argument, NULL, 'a'},
      { "hash-algorithm",     required_argument, NULL, 'g'},
      { "seed",               required_argument, NULL, 's'},
      { "policy",             required_argument, NULL, 'L'},
      { "encryption-key",     required_argument, NULL, 'k'},
      { "passin",             required_argument, NULL,  0 },
      { "cphash",             required_argument, NULL,  1 },
    };

    *opts = tpm2_options_new("P:p:G:i:C:U:u:r:a:g:s:L:k:", ARRAY_LEN(topts),
            topts, on_option, NULL, 0);

    return *opts != NULL;
}

/**
 * Check all options and report as many errors as possible via LOG_ERR.
 * @return
 *  tool_rc indicating error.
 */
static tool_rc check_options(void) {

    tool_rc rc = tool_rc_success;

    /* Check the tpm import specific options */
    if (ctx.import_tpm) {
        if (!ctx.input_seed_file) {
            LOG_ERR("Expected SymSeed to be specified via \"-s\","
                    " missing option.");
            rc = tool_rc_option_error;
        }

        /* If a key file is specified we choose aes else null
         for symmetricAlgdefinition */
        if (!ctx.input_enc_key_file) {
            ctx.key_type = TPM2_ALG_NULL;
        } else {
            ctx.key_type = TPM2_ALG_AES;
        }

        if (ctx.key_auth_str) {
            LOG_ERR("Cannot specify key password when importing a TPM key.\n"
                "use tpm2_changeauth after import");
            rc = tool_rc_option_error;
        }

    } else { /* Openssl specific option(s) */

        if (!ctx.key_type) {
            LOG_ERR("Expected key type to be specified via \"-G\","
                    " missing option.");
            rc = tool_rc_option_error;
        }

        if (ctx.cp_hash_path) {
            LOG_WARN("CAUTION CpHash calculation includes parameters that"
                     "have a derived/random seed!");
        }
    }

    /* Common options */
    if (!ctx.input_key_file) {
        LOG_ERR("Expected to be imported key data to be specified via \"-i\","
                " missing option.");
        rc = tool_rc_option_error;
    }

    if (!ctx.public_key_file) {
        LOG_ERR("Expected output public file missing, specify \"-u\","
                " missing option.");
        rc = tool_rc_option_error;
    }

    if (!ctx.private_key_file) {
        LOG_ERR("Expected output private file missing, specify \"-r\","
                " missing option.");
        rc = tool_rc_option_error;
    }

    if (!ctx.parent.ctx_path) {
        LOG_ERR("Expected parent key to be specified via \"-C\","
                " missing option.");
        rc = tool_rc_option_error;
    }

    return rc;
}


static tool_rc openssl_import(ESYS_CONTEXT *ectx) {

    /*
     * Load the parent public file, or read it from the TPM if not specified.
     * We need this information for encrypting the protection seed.
     */
    bool free_ppub = false;
    tool_rc tmp_rc;
    tool_rc rc = tool_rc_general_error;
    TPM2B_PUBLIC ppub = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC *parent_pub = NULL;

    bool result;
    tmp_rc = tool_rc_general_error;
    if (ctx.parent_key_public_file) {
        result = files_load_public(ctx.parent_key_public_file, &ppub);
        parent_pub = &ppub;
    } else {
        tmp_rc = readpublic(ectx, ctx.parent.object.tr_handle, &parent_pub);
        free_ppub = true;
        result = tmp_rc == tool_rc_success;
    }
    if (!result) {
        LOG_ERR("Failed loading parent key public.");
        return tmp_rc;
    }

    TPM2B_SENSITIVE private = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC public = TPM2B_EMPTY_INIT;
    TPM2B_ENCRYPTED_SECRET encrypted_seed = TPM2B_EMPTY_INIT;

    result = tpm2_openssl_import_keys(
        parent_pub,
        &private,
        &public,
        &encrypted_seed,
        ctx.input_key_file,
        ctx.key_type,
        ctx.auth_key_file,
        ctx.policy,
        ctx.key_auth_str,
        ctx.attrs,
        ctx.name_alg
    );
    if (!result)
        goto out;

    TPM2B_PRIVATE *imported_private = NULL;
    tmp_rc = key_import(ectx, parent_pub, &private, &public, &encrypted_seed,
            &imported_private);
    if (tmp_rc != tool_rc_success || ctx.cp_hash_path) {
        rc = tmp_rc;
        goto keyout;
    }

    /*
     * Save the public and imported_private structure to disk
     */
    result = files_save_public(&public, ctx.public_key_file);
    if (!result) {
        goto keyout;
    }

    result = files_save_private(imported_private, ctx.private_key_file);
    if (!result) {
        goto keyout;
    }

    /*
     * Output the stats on the created object on Success.
     */
    tpm2_util_public_to_yaml(&public, NULL);

    rc = tool_rc_success;

keyout:
    free(imported_private);
out:
    if (free_ppub) {
        free(parent_pub);
    }

    return rc;
}

static bool set_key_algorithm(TPMI_ALG_PUBLIC alg, TPMT_SYM_DEF_OBJECT * obj) {
    bool result = true;
    switch (alg) {
    case TPM2_ALG_AES:
        obj->algorithm = TPM2_ALG_AES;
        obj->keyBits.aes = 128;
        obj->mode.aes = TPM2_ALG_CFB;
        break;
    case TPM2_ALG_NULL:
        obj->algorithm = TPM2_ALG_NULL;
        break;
    default:
        LOG_ERR("The algorithm type input(0x%x) is not supported!", alg);
        result = false;
        break;
    }
    return result;
}

static tool_rc tpm_import(ESYS_CONTEXT *ectx) {

    TPM2B_DATA enc_key = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC public = TPM2B_EMPTY_INIT;
    TPM2B_PRIVATE duplicate;
    TPM2B_ENCRYPTED_SECRET encrypted_seed;
    TPM2B_PRIVATE *imported_private = NULL;
    TPMT_SYM_DEF_OBJECT sym_alg;

    tool_rc rc;
    bool result = set_key_algorithm(ctx.key_type, &sym_alg);
    if (!result) {
        return tool_rc_general_error;
    }

    /* Symmetric key */
    if (ctx.input_enc_key_file) {
        enc_key.size = 16;
        result = files_load_bytes_from_path(ctx.input_enc_key_file,
                enc_key.buffer, &enc_key.size);
        if (!result) {
            LOG_ERR("Failed to load symmetric encryption key\"%s\"",
                    ctx.input_enc_key_file);
            return tool_rc_general_error;
        }
        if (enc_key.size != 16) {
            LOG_ERR("Invalid AES key size, got %u bytes, expected 16",
                    enc_key.size);
            return tool_rc_general_error;
        }
    }

    /* Private key */
    result = files_load_private(ctx.input_key_file, &duplicate);
    if (!result) {
        LOG_ERR("Failed to load duplicate \"%s\"", ctx.input_key_file);
        return tool_rc_general_error;
    }

    /* Encrypted seed */
    result = files_load_encrypted_seed(ctx.input_seed_file, &encrypted_seed);
    if (!result) {
        LOG_ERR("Failed to load encrypted seed \"%s\"", ctx.input_seed_file);
        return tool_rc_general_error;
    }

    /* Public key */
    result = files_load_public(ctx.public_key_file, &public);
    if (!result) {
        LOG_ERR(":( Failed to load public key \"%s\"", ctx.public_key_file);
        return tool_rc_general_error;
    }

    if (ctx.policy) {
        public.publicArea.authPolicy.size =
            sizeof(public.publicArea.authPolicy.buffer);
        result = files_load_bytes_from_path(ctx.policy,
        public.publicArea.authPolicy.buffer,
        &public.publicArea.authPolicy.size);
        if (!result) {
            LOG_ERR("Failed to copy over the auth policy to the public data");
            return tool_rc_general_error;
        }
    }

    if (!ctx.cp_hash_path) {
        rc = tpm2_import(ectx, &ctx.parent.object, &enc_key, &public, &duplicate,
            &encrypted_seed, &sym_alg, &imported_private, NULL);
        if (rc != tool_rc_success) {
            return rc;
        }

        assert(imported_private);

        result = files_save_private(imported_private, ctx.private_key_file);
        free(imported_private);
        if (!result) {
            LOG_ERR("Failed to save private key into file \"%s\"",
                    ctx.private_key_file);
            return tool_rc_general_error;
        }
        return tool_rc_success;
    }

    TPM2B_DIGEST cp_hash = { .size = 0 };
    rc = tpm2_import(ectx, &ctx.parent.object, &enc_key, &public, &duplicate,
            &encrypted_seed, &sym_alg, &imported_private, &cp_hash);
    if (rc != tool_rc_success) {
        return rc;
    }

    result = files_save_digest(&cp_hash, ctx.cp_hash_path);
    if (!result) {
        rc = tool_rc_general_error;
    }
    return rc;

}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {
    UNUSED(flags);

    tool_rc rc = check_options();
    if (rc != tool_rc_success) {
        return rc;
    }

    rc = tpm2_util_object_load_auth(ectx, ctx.parent.ctx_path,
            ctx.parent.auth_str, &ctx.parent.object, false,
            TPM2_HANDLE_ALL_W_NV);
    if (rc != tool_rc_success) {
        LOG_ERR("Invalid parent key authorization");
        return rc;
    }

    return ctx.import_tpm ? tpm_import(ectx) : openssl_import(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);

    if (!ctx.import_tpm) {
        return tool_rc_success;
    }

    return tpm2_session_close(&ctx.parent.object.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("import", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
