/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_openssl.h"
#include "tpm2_policy.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"

static bool evaluate_populate_pcr_digests(TPML_PCR_SELECTION *pcr_selections,
        const char *raw_pcrs_file, TPML_DIGEST *pcr_values) {

    unsigned expected_pcr_input_file_size = 0;
    unsigned dgst_cnt = 0;

    //Iterating the number of pcr banks selected
    UINT32 i;
    for (i = 0; i < pcr_selections->count; i++) {

        UINT8 total_indices_for_this_alg = 0;

        //Looping to check total pcr select bits in the pcr-select-octets for a bank
        UINT32 j;
        for (j = 0; j < pcr_selections->pcrSelections[i].sizeofSelect; j++) {
            UINT8 group_val = pcr_selections->pcrSelections[i].pcrSelect[j];
            total_indices_for_this_alg += tpm2_util_pop_count(group_val);
        }

        if (pcr_values->count
                + total_indices_for_this_alg> ARRAY_LEN(pcr_values->digests)) {
            LOG_ERR("Number of PCR is limited to %zu",
                    ARRAY_LEN(pcr_values->digests));
            return false;
        }

        //digest size returned per the hashAlg type
        unsigned dgst_size = tpm2_alg_util_get_hash_size(
                pcr_selections->pcrSelections[i].hash);
        if (!dgst_size) {
            return false;
        }
        expected_pcr_input_file_size +=
                (total_indices_for_this_alg * dgst_size);

        //Cumulative total of all the pcr indices across banks selected in setlist
        pcr_values->count += total_indices_for_this_alg;

        /*
         * Populating the digest sizes in the PCR digest list per algorithm bank
         * Once iterated through all banks, creates an file offsets map for all pcr indices
         */
        UINT8 k;
        for (k = 0; k < total_indices_for_this_alg; k++) {
            pcr_values->digests[dgst_cnt].size = dgst_size;
            dgst_cnt++;
        }
    }

    //Check if the input pcrs file size is the same size as the pcr selection setlist
    if (raw_pcrs_file) {
        unsigned long filesize = 0;
        bool result = files_get_file_size_path(raw_pcrs_file, &filesize);
        if (!result) {
            LOG_ERR("Could not retrieve raw_pcrs_file size");
            return false;
        }
        if (filesize != expected_pcr_input_file_size) {
            LOG_ERR("pcr-input-file filesize does not match pcr set-list");
            return false;
        }
    }

    return true;
}

tool_rc tpm2_policy_build_pcr(ESYS_CONTEXT *ectx, tpm2_session *policy_session,
        const char *raw_pcrs_file, TPML_PCR_SELECTION *pcr_selections,
        TPM2B_DIGEST *raw_pcr_digest) {

    TPML_DIGEST pcr_values = { .count = 0 };

    if (!pcr_selections->count) {
        LOG_ERR("No pcr selection data specified!");
        return tool_rc_general_error;
    }


    TPM2B_DIGEST pcr_digest = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMI_ALG_HASH auth_hash = tpm2_session_get_authhash(policy_session);
    ESYS_TR handle = tpm2_session_get_handle(policy_session);

    /*
     * If digest of all PCRs is directly given, handle it here.
     */
    if (raw_pcr_digest &&
    raw_pcr_digest->size != tpm2_alg_util_get_hash_size(auth_hash)) {
        LOG_ERR("Specified PCR digest length not suitable with the policy session digest");
        return tool_rc_general_error;
    }
    // Call the PolicyPCR command
    if (raw_pcr_digest) {
        return tpm2_policy_pcr(ectx, handle, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, raw_pcr_digest, pcr_selections);
    }


    bool result = evaluate_populate_pcr_digests(pcr_selections, raw_pcrs_file,
            &pcr_values);
    if (!result) {
        return tool_rc_general_error;
    }

    //If PCR input for policy is from raw pcrs file
    if (raw_pcrs_file) {
        FILE *fp = fopen(raw_pcrs_file, "rb");
        if (fp == NULL) {
            LOG_ERR("Cannot open pcr-input-file %s", raw_pcrs_file);
            return tool_rc_general_error;
        }
        // Bank hashAlg values dictates the order of the list of digests
        unsigned i;
        for (i = 0; i < pcr_values.count; i++) {
            size_t sz = fread(&pcr_values.digests[i].buffer, 1,
                    pcr_values.digests[i].size, fp);
            if (sz != pcr_values.digests[i].size) {
                const char *msg =
                        ferror(fp) ? strerror(errno) : "end of file reached";
                LOG_ERR("Reading from file \"%s\" failed: %s", raw_pcrs_file,
                        msg);
                fclose(fp);
                return tool_rc_general_error;
            }
        }
        fclose(fp);
    } else {
        UINT32 pcr_update_counter;
        TPML_DIGEST *pcr_val = NULL;
        // Read PCRs
        tool_rc rc = tpm2_pcr_read(ectx, ESYS_TR_NONE, ESYS_TR_NONE,
                ESYS_TR_NONE, pcr_selections, &pcr_update_counter,
                NULL, &pcr_val);
        if (rc != tool_rc_success) {
            return rc;
        }

        UINT32 i;
        pcr_val->count = pcr_values.count;
        for (i = 0; i < pcr_val->count; i++) {
            memcpy(pcr_values.digests[i].buffer, pcr_val->digests[i].buffer,
                    pcr_val->digests[i].size);
            pcr_values.digests[i].size = pcr_val->digests[i].size;
        }
        free(pcr_val);
    }

    // Calculate hashes
    result = tpm2_openssl_hash_pcr_values(auth_hash, &pcr_values, &pcr_digest);
    if (!result) {
        LOG_ERR("Could not hash pcr values");
        return tool_rc_general_error;
    }

    // Call the PolicyPCR command
    return tpm2_policy_pcr(ectx, handle, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, &pcr_digest, pcr_selections);
}

tool_rc tpm2_policy_build_policyauthorize(ESYS_CONTEXT *ectx,
        tpm2_session *policy_session, const char *policy_digest_path,
        const char *qualifying_data,
        const char *verifying_pubkey_name_path, const char *ticket_path) {

    bool result = true;
    TPM2B_DIGEST approved_policy = { .size = 0 };
    if (policy_digest_path) {
        approved_policy.size = sizeof(TPMU_HA);
        result = files_load_bytes_from_path(policy_digest_path,
            approved_policy.buffer, &approved_policy.size);
    }
    if (!result) {
        return tool_rc_general_error;
    }

    /*
     * Qualifier data is optional. If not specified default to 0
     */

    TPM2B_NONCE policy_qualifier = { .size = 0 };

    if (qualifying_data) {
        policy_qualifier.size = sizeof(policy_qualifier.buffer);
        result = tpm2_util_bin_from_hex_or_file(qualifying_data,
                &policy_qualifier.size, policy_qualifier.buffer);
        if (!result) {
            return tool_rc_general_error;
        }
    }

    unsigned long file_size = 0;
    result = files_get_file_size_path(verifying_pubkey_name_path, &file_size);
    if (!result) {
        return tool_rc_general_error;
    }

    if (!file_size) {
        LOG_ERR("Verifying public key name file \"%s\", cannot be empty",
                verifying_pubkey_name_path);
        return tool_rc_general_error;
    }

    TPM2B_NAME key_sign = { .size = (uint16_t) file_size };

    result = files_load_bytes_from_path(verifying_pubkey_name_path,
            key_sign.name, &key_sign.size);
    if (!result) {
        return tool_rc_general_error;
    }

    TPMT_TK_VERIFIED check_ticket = { .tag = TPM2_ST_VERIFIED, .hierarchy =
            TPM2_RH_OWNER, .digest = { 0 } };
    result = tpm2_session_is_trial(policy_session);
    if (!result) {
        result = files_load_ticket(ticket_path, &check_ticket);
        if (!result) {
            LOG_ERR("Could not load verification ticket file");
            return tool_rc_general_error;
        }
    }

    ESYS_TR sess_handle = tpm2_session_get_handle(policy_session);
    return tpm2_policy_authorize(ectx, sess_handle, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, &approved_policy, &policy_qualifier, &key_sign,
            &check_ticket);
}

tool_rc tpm2_policy_build_policyor(ESYS_CONTEXT *ectx,
        tpm2_session *policy_session, TPML_DIGEST *policy_list) {

    ESYS_TR sess_handle = tpm2_session_get_handle(policy_session);
    return tpm2_policy_or(ectx, sess_handle, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, policy_list);
}

tool_rc tpm2_policy_build_policypassword(ESYS_CONTEXT *ectx,
        tpm2_session *session) {

    ESYS_TR policy_session_handle = tpm2_session_get_handle(session);

    return tpm2_policy_password(ectx, policy_session_handle, ESYS_TR_NONE,
            ESYS_TR_NONE, ESYS_TR_NONE);
}

tool_rc tpm2_policy_build_policynamehash(ESYS_CONTEXT *ectx,
    tpm2_session *session, const TPM2B_DIGEST *name_hash) {

    ESYS_TR policy_session_handle = tpm2_session_get_handle(session);

    return tpm2_policy_namehash(ectx, policy_session_handle, name_hash);
}

tool_rc tpm2_policy_build_policytemplate(ESYS_CONTEXT *ectx,
    tpm2_session *session, const TPM2B_DIGEST *template_hash) {

    ESYS_TR policy_session_handle = tpm2_session_get_handle(session);

    return tpm2_policy_template(ectx, policy_session_handle, template_hash);
}

tool_rc tpm2_policy_build_policycphash(ESYS_CONTEXT *ectx,
    tpm2_session *session, const TPM2B_DIGEST *cphash) {

    ESYS_TR policy_session_handle = tpm2_session_get_handle(session);

    return tpm2_policy_cphash(ectx, policy_session_handle, cphash);
}

tool_rc tpm2_policy_build_policyauthvalue(ESYS_CONTEXT *ectx,
        tpm2_session *session) {

    ESYS_TR policy_session_handle = tpm2_session_get_handle(session);

    return tpm2_policy_authvalue(ectx, policy_session_handle, ESYS_TR_NONE,
            ESYS_TR_NONE, ESYS_TR_NONE);
}

tool_rc tpm2_policy_build_policysecret(ESYS_CONTEXT *ectx,
        tpm2_session *policy_session, tpm2_loaded_object *auth_entity_obj,
        INT32 expiration, TPMT_TK_AUTH **policy_ticket,
        TPM2B_TIMEOUT **timeout, bool is_nonce_tpm,
        const char *policy_qualifier_data, TPM2B_DIGEST *cp_hash) {

    /*
     * Qualifier data is optional. If not specified default to 0
     */
    TPM2B_NONCE policy_qualifier = TPM2B_EMPTY_INIT;
    if (policy_qualifier_data) {
        policy_qualifier.size = sizeof(policy_qualifier.buffer);
        bool result = tpm2_util_bin_from_hex_or_file(policy_qualifier_data,
                &policy_qualifier.size,
                policy_qualifier.buffer);
        if (!result) {
            return tool_rc_general_error;
        }
    }

    if (!ectx || true) {
        if (is_nonce_tpm) {
            LOG_ERR("Cannot specify is_nonce_tpm with NULL ESYS Context");
            return tool_rc_general_error;
        }
        /* TODO: Get old from input file -L */
        TPM2B_DIGEST old = { 0 };
        old.size = 32;
        /* TODO get name, not hardcoded! */
        TPM2B_NAME name ={
                .size = 4,
                .name = { 0x40, 0x00, 0x00, 0x01 }
        };
        /* TODO get halg */
        /* TODO This needs to be tied to Esys_Malloc.... but that doesn't exist */
        TPMT_TK_AUTH *pt = calloc(sizeof(*pt), 1);
        /* TODO error check */
        tool_rc rc = tpm2_policy_secret_no_tpm(TPM2_ALG_SHA256, &old, &name, &policy_qualifier, pt);
        if (rc == tool_rc_success) {
            *policy_ticket = pt;
        }
        return rc;
    }

    ESYS_TR policy_session_handle = tpm2_session_get_handle(policy_session);

    TPM2B_NONCE *nonce_tpm = NULL;
    tool_rc rc = tool_rc_success;
    if (is_nonce_tpm) {
        rc = tpm2_sess_get_noncetpm(ectx, policy_session_handle, &nonce_tpm);
        if (rc != tool_rc_success) {
            goto tpm2_policy_build_policysecret_out;
        }
    }

    rc = tpm2_policy_secret(ectx, auth_entity_obj, policy_session_handle,
        expiration, policy_ticket, timeout, nonce_tpm, &policy_qualifier,
        cp_hash);

tpm2_policy_build_policysecret_out:
    Esys_Free(nonce_tpm);
    return rc;
}

tool_rc tpm2_policy_build_policyticket(ESYS_CONTEXT *ectx,
    tpm2_session *policy_session, char *policy_timeout_path,
    const char *qualifier_data, char *policy_ticket_path,
    const char *auth_name_path) {

    unsigned long file_size = 0;

    bool result = files_get_file_size_path(policy_timeout_path, &file_size);
    if (!result) {
        return tool_rc_general_error;
    }
    TPM2B_TIMEOUT policy_timeout = { .size = (uint16_t) file_size };
    if (policy_timeout.size) {
        result = files_load_bytes_from_path(policy_timeout_path,
                policy_timeout.buffer, &policy_timeout.size);
        if (!result) {
            return tool_rc_general_error;
        }
    }

    result = files_get_file_size_path(auth_name_path, &file_size);
    if (!result) {
        return tool_rc_general_error;
    }
    TPM2B_NAME auth_name = { .size = (uint16_t) file_size };
    if (auth_name.size) {
        result = files_load_bytes_from_path(auth_name_path,
                auth_name.name, &auth_name.size);
        if (!result) {
            return tool_rc_general_error;
        }
    }

    TPM2B_NONCE policyref = TPM2B_EMPTY_INIT;
    if (qualifier_data) {
        policyref.size = sizeof(policyref.buffer);
        result = tpm2_util_bin_from_hex_or_file(qualifier_data, &policyref.size,
                policyref.buffer);
        if (!result) {
            return tool_rc_general_error;
        }
    }

    TPMT_TK_AUTH ticket = { 0 };
    result = files_load_authorization_ticket(policy_ticket_path, &ticket);
    if (!result) {
        LOG_ERR("Failed loading authorization ticket.");
        return tool_rc_general_error;
    }

    ESYS_TR policy_session_handle = tpm2_session_get_handle(policy_session);

    return tpm2_policy_ticket(ectx, policy_session_handle, &policy_timeout,
        &policyref, &auth_name, &ticket);

    return tool_rc_success;
}

tool_rc tpm2_policy_build_policysigned(ESYS_CONTEXT *ectx,
        tpm2_session *policy_session, tpm2_loaded_object *auth_entity_obj,
        TPMT_SIGNATURE *signature, INT32 expiration, TPM2B_TIMEOUT **timeout,
        TPMT_TK_AUTH **policy_ticket, const char *policy_qualifier_data,
        bool is_nonce_tpm, const char *raw_data_path,
        const char *cphash_path) {

    bool result = true;

    /*
     * Qualifier data is optional. If not specified default to 0
     */
    TPM2B_NONCE policy_qualifier = TPM2B_EMPTY_INIT;

    if (policy_qualifier_data) {
        policy_qualifier.size = sizeof(policy_qualifier.buffer);
        result = tpm2_util_bin_from_hex_or_file(policy_qualifier_data,
                &policy_qualifier.size,
                policy_qualifier.buffer);
        if (!result) {
            return tool_rc_general_error;
        }
    }

    /*
     * CpHashA (digest of command parameters for approved command) optional.
     * If not specified default to NULL
     */
    TPM2B_DIGEST cphash = TPM2B_EMPTY_INIT;

    if (cphash_path) {
        bool result = files_load_digest(cphash_path, &cphash);
        if (!result) {
            return tool_rc_general_error;
        }
    }

    ESYS_TR policy_session_handle = tpm2_session_get_handle(policy_session);

    TPM2B_NONCE *nonce_tpm = NULL;
    tool_rc rc = tool_rc_success;
    if (is_nonce_tpm) {
        rc = tpm2_sess_get_noncetpm(ectx, policy_session_handle, &nonce_tpm);
        if (rc != tool_rc_success) {
            goto tpm2_policy_build_policysigned_out;
        }
    }

    /*
     * TPM-Rev-2.0-Part-3-Commands-01.38.pdf
     * aHash ≔ HauthAlg(nonceTPM || expiration || cpHashA || policyRef)
     */
    if (raw_data_path) {
        uint16_t raw_data_len = (nonce_tpm ? nonce_tpm->size : 0) +
            sizeof(INT32) + cphash.size + policy_qualifier.size;

        uint8_t *raw_data = malloc(raw_data_len);
        if (!raw_data) {
            LOG_ERR("oom");
            rc = tool_rc_general_error;
            goto tpm2_policy_build_policysigned_out;
        }
        /* nonceTPM */
        uint16_t offset = 0;
        if (nonce_tpm) {
            memcpy(raw_data, nonce_tpm->buffer, nonce_tpm->size);
            offset += nonce_tpm->size;
        }
        /* expiration */
        UINT32 endswap_data = tpm2_util_endian_swap_32(expiration);
        memcpy(raw_data + offset, (UINT8 *)&endswap_data, sizeof(INT32));
        offset += sizeof(INT32);
        /* cpHash */
        if (cphash_path) {
            memcpy(raw_data + offset, cphash.buffer, cphash.size);
            offset += cphash.size;
        }
        /* policyRef */
        memcpy(raw_data + offset, policy_qualifier.buffer,
            policy_qualifier.size);

        bool result = files_save_bytes_to_file(raw_data_path, raw_data,
            raw_data_len);
        free(raw_data);
        if (!result) {
            rc = tool_rc_general_error;
        }
        /*
         * We return since we only need to generate the raw signing data
         */
        goto tpm2_policy_build_policysigned_out;
    }

    rc = tpm2_policy_signed(ectx, auth_entity_obj, policy_session_handle,
        signature, expiration, timeout, policy_ticket, &policy_qualifier,
        nonce_tpm, &cphash);

tpm2_policy_build_policysigned_out:
    Esys_Free(nonce_tpm);
    return rc;
}

tool_rc tpm2_policy_get_digest(ESYS_CONTEXT *ectx, tpm2_session *session,
        TPM2B_DIGEST **policy_digest) {

    ESYS_TR handle = tpm2_session_get_handle(session);

    return tpm2_policy_getdigest(ectx, handle, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, policy_digest);
}

tool_rc tpm2_policy_build_policycommandcode(ESYS_CONTEXT *ectx,
        tpm2_session *session, uint32_t command_code) {

    ESYS_TR handle = tpm2_session_get_handle(session);

    return tpm2_policy_command_code(ectx, handle, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, command_code);
}

tool_rc tpm2_policy_build_policynvwritten(ESYS_CONTEXT *ectx,
        tpm2_session *session, TPMI_YES_NO written_set) {

    ESYS_TR handle = tpm2_session_get_handle(session);

    return tpm2_policy_nv_written(ectx, handle, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, written_set);
}

tool_rc tpm2_policy_build_policylocality(ESYS_CONTEXT *ectx,
        tpm2_session *session, TPMA_LOCALITY locality) {

    ESYS_TR handle = tpm2_session_get_handle(session);

    return tpm2_policy_locality(ectx, handle, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, locality);
}

tool_rc tpm2_policy_build_policyduplicationselect(ESYS_CONTEXT *ectx,
        tpm2_session *session, const char *obj_name_path,
        const char *new_parent_name_path, TPMI_YES_NO is_include_obj) {

    TPM2B_NAME obj_name;
    bool result = true;

    if (obj_name_path) {
        obj_name.size = sizeof(obj_name.name);
        result = files_load_bytes_from_path(obj_name_path, obj_name.name,
                &obj_name.size);
    } else {
        obj_name.size = 0;
    }

    if (!result) {
        LOG_ERR("Failed to load duplicable object name.");
        return tool_rc_general_error;
    }

    TPM2B_NAME new_parent_name = { .size = sizeof(new_parent_name.name) };

    result = files_load_bytes_from_path(new_parent_name_path,
            new_parent_name.name, &new_parent_name.size);
    if (!result) {
        return tool_rc_general_error;
    }

    ESYS_TR handle = tpm2_session_get_handle(session);

    return tpm2_policy_duplication_select(ectx, handle, ESYS_TR_NONE,
            ESYS_TR_NONE, ESYS_TR_NONE, &obj_name, &new_parent_name,
            is_include_obj);
}

static bool tpm2_policy_populate_digest_list(char *buf,
        TPML_DIGEST *policy_list, TPMI_ALG_HASH hash) {

    uint8_t hash_len = tpm2_alg_util_get_hash_size(hash);
    if (!hash_len) {
        return false;
    }

    unsigned long file_size;
    bool retval = files_get_file_size_path(buf, &file_size);
    if (!retval) {
        return false;
    }
    if (file_size != hash_len) {
        return false;
    }

    policy_list->digests[policy_list->count].size = hash_len;
    /* All policy digests are expected to be of same hash len */
    if (policy_list->count > 0
            && policy_list->digests[policy_list->count].size
                    != policy_list->digests[policy_list->count - 1].size) {
        return false;
    }

    uint16_t policy_digest_size = hash_len;
    retval = files_load_bytes_from_path(buf,
            policy_list->digests[policy_list->count].buffer,
            &policy_digest_size);
    if (!retval) {
        return false;
    }

    policy_list->count++;

    return true;
}

bool tpm2_policy_parse_policy_list(char *str, TPML_DIGEST *policy_list) {

    char *str1;
    char *str2;
    char *token;
    char *subtoken;
    char *saveptr1;
    char *saveptr2;
    const char *delimiter1 = ":";
    const char *delimiter2 = ",";

    unsigned int j;
    bool retval;
    TPMI_ALG_HASH hash = TPM2_ALG_ERROR;

    for (j = 1, str1 = str;; j++, str1 = NULL) {

        token = strtok_r(str1, delimiter1, &saveptr1);
        if (token == NULL) {
            break;
        }

        for (str2 = token;; str2 = NULL) {

            subtoken = strtok_r(str2, delimiter2, &saveptr2);
            if (subtoken == NULL) {
                break;
            }

            //Expecting one policy digest of same hash alg type for all policies
            if (j == 1) {
                hash = tpm2_alg_util_from_optarg(subtoken,
                        tpm2_alg_util_flags_hash);
                if (hash == TPM2_ALG_ERROR) {
                    LOG_ERR("Invalid/ Unspecified policy digest algorithm.");
                    return false;
                }
            }

            //Multiple valid policy files
            if (j > 1) {
                retval = tpm2_policy_populate_digest_list(subtoken, policy_list,
                        hash);
                if (!retval) {
                    return false;
                }
            }

        }
    }

    return true;
}

tool_rc tpm2_policy_tool_finish(ESYS_CONTEXT *ectx, tpm2_session *session,
        const char *save_path) {

    TPM2B_DIGEST *policy_digest = NULL;
    tool_rc rc = tpm2_policy_get_digest(ectx, session, &policy_digest);
    if (rc != tool_rc_success) {
        LOG_ERR("Could not build tpm policy");
        return rc;
    }

    tpm2_util_hexdump(policy_digest->buffer, policy_digest->size);
    tpm2_tool_output("\n");

    rc = tool_rc_general_error;

    if (save_path) {
        bool result = files_save_bytes_to_file(save_path, policy_digest->buffer,
                policy_digest->size);
        if (!result) {
            LOG_ERR("Failed to save policy digest into file \"%s\"", save_path);
            goto error;
        }
    }

    rc = tool_rc_success;

error:
    free(policy_digest);
    return rc;
}
