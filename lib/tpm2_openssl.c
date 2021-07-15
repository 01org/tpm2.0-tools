/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/rand.h>

#include "files.h"
#include "log.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_attr_util.h"
#include "tpm2_identity_util.h"
#include "tpm2_openssl.h"
#include "tpm2_errata.h"
#include "tpm2_systemdeps.h"

/* compatibility function for OpenSSL versions < 1.1.0 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
static int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen) {
    int r;
    int topad;
    int islen;

    islen = BN_num_bytes(a);

    if (tolen < islen)
        return -1;

    topad = tolen - islen;

    memset(to, 0x00, topad);
    r = BN_bn2bin(a, to + topad);
    if (r == 0) {
        return -1;
    }

    return tolen;
}
#endif

int tpm2_openssl_halgid_from_tpmhalg(TPMI_ALG_HASH algorithm) {

    switch (algorithm) {
    case TPM2_ALG_SHA1:
        return NID_sha1;
    case TPM2_ALG_SHA256:
        return NID_sha256;
    case TPM2_ALG_SHA384:
        return NID_sha384;
    case TPM2_ALG_SHA512:
        return NID_sha512;
    default:
        return NID_sha256;
    }
    /* no return, not possible */
}

const EVP_MD *tpm2_openssl_halg_from_tpmhalg(TPMI_ALG_HASH algorithm) {

    switch (algorithm) {
    case TPM2_ALG_SHA1:
        return EVP_sha1();
    case TPM2_ALG_SHA256:
        return EVP_sha256();
    case TPM2_ALG_SHA384:
        return EVP_sha384();
    case TPM2_ALG_SHA512:
        return EVP_sha512();
    default:
        return NULL;
    }
    /* no return, not possible */
}

#if defined(LIB_TPM2_OPENSSL_OPENSSL_PRE11)
int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d) {

    if ((r->n == NULL && n == NULL) || (r->e == NULL && e == NULL)) {
        return 0;
    }

    if (n != NULL) {
        BN_free(r->n);
        r->n = n;
    }

    if (e != NULL) {
        BN_free(r->e);
        r->e = e;
    }

    if (d != NULL) {
        BN_free(r->d);
        r->d = d;
    }

    return 1;
}

void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q) {
    if(p) {
        *p = r->p;
    }

    if (q) {
        *q = r->q;
    }
}

int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s) {

    if (!r || !s) {
        return 0;
    }

    BN_clear_free(sig->r);
    BN_clear_free(sig->s);

    sig->r = r;
    sig->s = s;

    return 1;
}

EVP_ENCODE_CTX *EVP_ENCODE_CTX_new(void) {
	EVP_ENCODE_CTX *ctx = OPENSSL_malloc(sizeof(EVP_ENCODE_CTX));
	if (ctx) {
		memset(ctx, 0, sizeof(*ctx));
	}
	return ctx;
}

void EVP_ENCODE_CTX_free(EVP_ENCODE_CTX *ctx) {
    OPENSSL_free(ctx);
}

#endif

bool tpm2_openssl_hash_compute_data(TPMI_ALG_HASH halg, BYTE *buffer,
        UINT16 length, TPM2B_DIGEST *digest) {

    bool result = false;

    const EVP_MD *md = tpm2_openssl_halg_from_tpmhalg(halg);
    if (!md) {
        return false;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (!mdctx) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        return false;
    }

    int rc = EVP_DigestInit_ex(mdctx, md, NULL);
    if (!rc) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    rc = EVP_DigestUpdate(mdctx, buffer, length);
    if (!rc) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    unsigned size = EVP_MD_size(md);
    rc = EVP_DigestFinal_ex(mdctx, digest->buffer, &size);
    if (!rc) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    digest->size = size;

    result = true;

out:
    EVP_MD_CTX_destroy(mdctx);
    return result;
}

bool tpm2_openssl_pcr_extend(TPMI_ALG_HASH halg, BYTE *pcr,
        const BYTE *data, UINT16 length) {

    bool result = false;

    const EVP_MD *md = tpm2_openssl_halg_from_tpmhalg(halg);
    if (!md) {
        return false;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (!mdctx) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        return false;
    }

    int rc = EVP_DigestInit_ex(mdctx, md, NULL);
    if (!rc) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    // extend operation is pcr = HASH(pcr + data)
    unsigned size = EVP_MD_size(md);
    rc = EVP_DigestUpdate(mdctx, pcr, size);
    if (!rc) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    rc = EVP_DigestUpdate(mdctx, data, length);
    if (!rc) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    rc = EVP_DigestFinal_ex(mdctx, pcr, &size);
    if (!rc) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    result = true;

out:
    EVP_MD_CTX_destroy(mdctx);
    return result;
}

bool tpm2_openssl_hash_pcr_values(TPMI_ALG_HASH halg, TPML_DIGEST *digests,
        TPM2B_DIGEST *digest) {

    bool result = false;

    const EVP_MD *md = tpm2_openssl_halg_from_tpmhalg(halg);
    if (!md) {
        return false;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (!mdctx) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        return false;
    }

    int rc = EVP_DigestInit_ex(mdctx, md, NULL);
    if (!rc) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    size_t i;
    for (i = 0; i < digests->count; i++) {

        TPM2B_DIGEST *b = &digests->digests[i];
        rc = EVP_DigestUpdate(mdctx, b->buffer, b->size);
        if (!rc) {
            LOG_ERR("%s", tpm2_openssl_get_err());
            goto out;
        }
    }

    unsigned size = EVP_MD_size(EVP_sha256());

    rc = EVP_DigestFinal_ex(mdctx, digest->buffer, &size);
    if (!rc) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    digest->size = size;

    result = true;

out:
    EVP_MD_CTX_destroy(mdctx);
    return result;
}

// show all PCR banks according to g_pcrSelection & g_pcrs->
bool tpm2_openssl_hash_pcr_banks(TPMI_ALG_HASH hash_alg,
        TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs, TPM2B_DIGEST *digest) {

    UINT32 vi = 0, di = 0, i;
    bool result = false;

    const EVP_MD *md = tpm2_openssl_halg_from_tpmhalg(hash_alg);
    if (!md) {
        return false;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (!mdctx) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        return false;
    }

    int rc = EVP_DigestInit_ex(mdctx, md, NULL);
    if (!rc) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    // Loop through all PCR/hash banks
    for (i = 0; i < pcr_select->count; i++) {

        // Loop through all PCRs in this bank
        unsigned int pcr_id;
        for (pcr_id = 0; pcr_id < pcr_select->pcrSelections[i].sizeofSelect * 8u;
                pcr_id++) {
            if (!tpm2_util_is_pcr_select_bit_set(&pcr_select->pcrSelections[i],
                    pcr_id)) {
                // skip non-selected banks
                continue;
            }
            if (vi >= pcrs->count || di >= pcrs->pcr_values[vi].count) {
                LOG_ERR("Something wrong, trying to print but nothing more");
                goto out;
            }

            // Update running digest (to compare with quote)
            TPM2B_DIGEST *b = &pcrs->pcr_values[vi].digests[di];
            rc = EVP_DigestUpdate(mdctx, b->buffer, b->size);
            if (!rc) {
                LOG_ERR("%s", tpm2_openssl_get_err());
                goto out;
            }

            if (++di < pcrs->pcr_values[vi].count) {
                continue;
            }

            di = 0;
            if (++vi < pcrs->count) {
                continue;
            }
        }
    }

    // Finalize running digest
    unsigned size = EVP_MD_size(md);
    rc = EVP_DigestFinal_ex(mdctx, digest->buffer, &size);
    if (!rc) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    digest->size = size;

    result = true;

out:
    EVP_MD_CTX_destroy(mdctx);
    return result;
}

/* show all PCR banks according to g_pcrSelection & g_pcrs-> */
bool tpm2_openssl_hash_pcr_banks_le(TPMI_ALG_HASH hash_alg,
        TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs, TPM2B_DIGEST *digest) {

    UINT32 vi = 0, di = 0, i;
    bool result = false;

    const EVP_MD *md = tpm2_openssl_halg_from_tpmhalg(hash_alg);
    if (!md) {
        return false;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (!mdctx) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        return false;
    }

    int rc = EVP_DigestInit_ex(mdctx, md, NULL);
    if (!rc) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    /* Loop through all PCR/hash banks */
    for (i = 0; i < le32toh(pcr_select->count); i++) {

        /* Loop through all PCRs in this bank */
        unsigned int pcr_id;
        for (pcr_id = 0; pcr_id < pcr_select->pcrSelections[i].sizeofSelect * 8u;
                pcr_id++) {
            if (!tpm2_util_is_pcr_select_bit_set(&pcr_select->pcrSelections[i],
                    pcr_id)) {
                continue; // skip non-selected banks
            }
            if (vi >= le64toh(pcrs->count) || di >= le32toh(pcrs->pcr_values[vi].count)) {
                LOG_ERR("Something wrong, trying to print but nothing more");
                goto out;
            }

            /* Update running digest (to compare with quote) */
            TPM2B_DIGEST *b = &pcrs->pcr_values[vi].digests[di];
            rc = EVP_DigestUpdate(mdctx, b->buffer, le16toh(b->size));
            if (!rc) {
                LOG_ERR("%s", tpm2_openssl_get_err());
                goto out;
            }

            if (++di < le32toh(pcrs->pcr_values[vi].count)) {
                continue;
            }

            di = 0;
            if (++vi < le64toh(pcrs->count)) {
                continue;
            }
        }
    }

    /* Finalize running digest */
    unsigned size = EVP_MD_size(md);
    rc = EVP_DigestFinal_ex(mdctx, digest->buffer, &size);
    if (!rc) {
        LOG_ERR("%s", tpm2_openssl_get_err());
        goto out;
    }

    digest->size = size;

    result = true;

out:
    EVP_MD_CTX_destroy(mdctx);
    return result;
}

HMAC_CTX *tpm2_openssl_hmac_new() {
    HMAC_CTX *ctx;
#if defined(LIB_TPM2_OPENSSL_OPENSSL_PRE11)
    ctx = malloc(sizeof(*ctx));
#else
    ctx = HMAC_CTX_new();
#endif
    if (!ctx)
        return NULL;

#if defined(LIB_TPM2_OPENSSL_OPENSSL_PRE11)
    HMAC_CTX_init(ctx);
#endif

    return ctx;
}

void tpm2_openssl_hmac_free(HMAC_CTX *ctx) {
#if defined(LIB_TPM2_OPENSSL_OPENSSL_PRE11)
    HMAC_CTX_cleanup(ctx);
    free(ctx);
#else
    HMAC_CTX_free(ctx);
#endif
}

EVP_CIPHER_CTX *tpm2_openssl_cipher_new(void) {
    EVP_CIPHER_CTX *ctx;
#if defined(LIB_TPM2_OPENSSL_OPENSSL_PRE11)
    ctx = malloc(sizeof(*ctx));
#else
    ctx = EVP_CIPHER_CTX_new();
#endif
    if (!ctx)
        return NULL;

#if defined(LIB_TPM2_OPENSSL_OPENSSL_PRE11)
    EVP_CIPHER_CTX_init(ctx);
#endif

    return ctx;
}

void tpm2_openssl_cipher_free(EVP_CIPHER_CTX *ctx) {
#if defined(LIB_TPM2_OPENSSL_OPENSSL_PRE11)
    EVP_CIPHER_CTX_cleanup(ctx);
    free(ctx);
#else
    EVP_CIPHER_CTX_free(ctx);
#endif
}

digester tpm2_openssl_halg_to_digester(TPMI_ALG_HASH halg) {

    switch (halg) {
    case TPM2_ALG_SHA1:
        return SHA1;
    case TPM2_ALG_SHA256:
        return SHA256;
    case TPM2_ALG_SHA384:
        return SHA384;
    case TPM2_ALG_SHA512:
        return SHA512;
        /* no default */
    }

    return NULL;
}

/*
 * Per man openssl(1), handle the following --passin formats:
 *     pass:password
 *             the actual password is password. Since the password is visible to utilities (like 'ps' under Unix) this form should only be used where security is not
 *             important.
 *
 *   env:var   obtain the password from the environment variable var. Since the environment of other processes is visible on certain platforms (e.g. ps under certain
 *             Unix OSes) this option should be used with caution.
 *
 *   file:pathname
 *             the first line of pathname is the password. If the same pathname argument is supplied to -passin and -passout arguments then the first line will be used
 *             for the input password and the next line for the output password. pathname need not refer to a regular file: it could for example refer to a device or
 *             named pipe.
 *
 *   fd:number read the password from the file descriptor number. This can be used to send the data via a pipe for example.
 *
 *   stdin     read the password from standard input.
 *
 */

typedef bool (*pfn_ossl_pw_handler)(const char *passin, char **pass);

static bool do_pass(const char *passin, char **pass) {

    char *tmp = strdup(passin);
    if (!tmp) {
        LOG_ERR("oom");
        return false;
    }

    *pass = tmp;
    return true;
}

static bool do_env(const char *envvar, char **pass) {

    char *tmp = getenv(envvar);
    if (!tmp) {
        LOG_ERR("Environment variable \"%s\" not found", envvar);
        return false;
    }

    tmp = strdup(tmp);
    if (!tmp) {
        LOG_ERR("oom");
        return false;
    }

    *pass = tmp;
    return true;
}

static bool do_open_file(FILE *f, const char *path, char **pass) {

    bool rc = false;

    unsigned long file_size = 0;
    bool result = files_get_file_size(f, &file_size, path);
    if (!result) {
        goto out;
    }

    if (file_size + 1 <= file_size) {
        LOG_ERR("overflow: file_size too large");
        goto out;
    }

    char *tmp = calloc(sizeof(char), file_size + 1);
    if (!tmp) {
        LOG_ERR("oom");
        goto out;
    }

    result = files_read_bytes(f, (UINT8 *) tmp, file_size);
    if (!result) {
        free(tmp);
        goto out;
    }

    *pass = tmp;

    rc = true;

out:
    fclose(f);

    return rc;
}

static bool do_file(const char *path, char **pass) {

    FILE *f = fopen(path, "rb");
    if (!f) {
        LOG_ERR("could not open file \"%s\" error: %s", path, strerror(errno));
        return false;
    }

    return do_open_file(f, path, pass);
}

static bool do_fd(const char *passin, char **pass) {

    char *end_ptr = NULL;
    int fd = strtoul(passin, &end_ptr, 0);
    if (passin[0] != '\0' && end_ptr[0] != '\0') {
        LOG_ERR("Invalid fd, got: \"%s\"", passin);
        return false;
    }

    FILE *f = fdopen(fd, "rb");
    if (!f) {
        LOG_ERR("could not open fd \"%d\" error: %s", fd, strerror(errno));
        return false;
    }

    return do_open_file(f, "fd", pass);
}

static bool do_stdin(const char *passin, char **pass) {

    UNUSED(passin);

    void *buf = calloc(sizeof(BYTE), UINT16_MAX + 1);
    if (!buf) {
        LOG_ERR("oom");
        return false;
    }

    UINT16 size = UINT16_MAX;

    bool result = files_load_bytes_from_buffer_or_file_or_stdin(NULL, NULL,
            &size, buf);
    if (!result) {
        free(buf);
        return false;
    }

    *pass = buf;
    return true;
}

static bool handle_ossl_pass(const char *passin, char **pass) {

    pfn_ossl_pw_handler pfn = NULL;

    if (!passin) {
        *pass = NULL;
        return true;
    }

    if (!strncmp("pass:", passin, 5)) {
        passin += 5;
        pfn = do_pass;
    } else if (!strncmp("env:", passin, 4)) {
        pfn = do_env;
        passin += 4;
    } else if (!strncmp("file:", passin, 5)) {
        pfn = do_file;
        passin += 5;
    } else if (!strncmp("fd:", passin, 3)) {
        pfn = do_fd;
        passin += 3;
    } else if (!strcmp("stdin", passin)) {
        pfn = do_stdin;
    } else {
        LOG_ERR("Unknown OSSL style password argument, got: \"%s\"", passin);
        return false;
    }

    return pfn(passin, pass);
}

static bool load_public_RSA_from_key(RSA *k, TPM2B_PUBLIC *pub) {

    TPMT_PUBLIC *pt = &pub->publicArea;
    pt->type = TPM2_ALG_RSA;

    TPMS_RSA_PARMS *rdetail = &pub->publicArea.parameters.rsaDetail;
    rdetail->scheme.scheme = TPM2_ALG_NULL;
    rdetail->symmetric.algorithm = TPM2_ALG_NULL;
    rdetail->scheme.details.anySig.hashAlg = TPM2_ALG_NULL;

    /* NULL out sym details */
    TPMT_SYM_DEF_OBJECT *sym = &rdetail->symmetric;
    sym->algorithm = TPM2_ALG_NULL;
    sym->keyBits.sym = 0;
    sym->mode.sym = TPM2_ALG_NULL;

    const BIGNUM *n; /* modulus */
    const BIGNUM *e; /* public key exponent */

#if defined(LIB_TPM2_OPENSSL_OPENSSL_PRE11)
    n = k->n;
    e = k->e;
#else
    RSA_get0_key(k, &n, &e, NULL);
#endif

    /*
     * The size of the modulus is the key size in RSA, store this as the
     * keyBits in the RSA details.
     */
    rdetail->keyBits = BN_num_bytes(n) * 8;
    switch (rdetail->keyBits) {
    case 1024: /* falls-through */
    case 2048: /* falls-through */
    case 4096: /* falls-through */
        break;
    default:
        LOG_ERR("RSA key-size %u is not supported", rdetail->keyBits);
        return false;
    }

    /* copy the modulus to the unique RSA field */
    pt->unique.rsa.size = rdetail->keyBits / 8;
    int success = BN_bn2bin(n, pt->unique.rsa.buffer);
    if (!success) {
        LOG_ERR("Could not copy public modulus N");
        return false;
    }

    /*Make sure that we can fit the exponent into a UINT32 */
    unsigned e_size = BN_num_bytes(e);
    if (e_size > sizeof(rdetail->exponent)) {
        LOG_ERR(
                "Exponent is too big. Got %d expected less than or equal to %zu",
                e_size, sizeof(rdetail->exponent));
        return false;
    }

    /*
     * Copy the exponent into the field.
     * Returns 1 on success false on error.
     */
    return BN_bn2bin(e, (unsigned char *) &rdetail->exponent);
}

static RSA *tpm2_openssl_get_public_RSA_from_pem(FILE *f, const char *path) {

    /*
     * Public PEM files appear in two formats:
     * 1. PEM format, read with PEM_read_RSA_PUBKEY
     * 2. PKCS#1 format, read with PEM_read_RSAPublicKey
     *
     * See:
     *  - https://stackoverflow.com/questions/7818117/why-i-cant-read-openssl-generated-rsa-pub-key-with-pem-read-rsapublickey
     */
    RSA *pub = PEM_read_RSA_PUBKEY(f, NULL, NULL, NULL);
    if (!pub) {
        pub = PEM_read_RSAPublicKey(f, NULL, NULL, NULL);
    }

    if (!pub) {
        ERR_print_errors_fp(stderr);
        LOG_ERR("Reading public PEM file \"%s\" failed", path);
        return NULL;
    }

    return pub;
}

static bool load_public_RSA_from_pem(FILE *f, const char *path,
        TPM2B_PUBLIC *pub) {

    /*
     * Public PEM files appear in two formats:
     * 1. PEM format, read with PEM_read_RSA_PUBKEY
     * 2. PKCS#1 format, read with PEM_read_RSAPublicKey
     *
     * See:
     *  - https://stackoverflow.com/questions/7818117/why-i-cant-read-openssl-generated-rsa-pub-key-with-pem-read-rsapublickey
     */
    RSA *k = tpm2_openssl_get_public_RSA_from_pem(f, path);
    if (!k) {
        /* tpm2_openssl_get_public_RSA_from_pem() should already log errors */
        return false;
    }

    bool result = load_public_RSA_from_key(k, pub);

    RSA_free(k);

    return result;
}

static const struct {
    TPMI_ECC_CURVE curve;
    int nid;
} nid_curve_map[] = {
    { TPM2_ECC_NIST_P192, NID_X9_62_prime192v1 },
    { TPM2_ECC_NIST_P224, NID_secp224r1        },
    { TPM2_ECC_NIST_P256, NID_X9_62_prime256v1 },
    { TPM2_ECC_NIST_P384, NID_secp384r1        },
    { TPM2_ECC_NIST_P521, NID_secp521r1        }
    /*
     * XXX
     * See if it's possible to support the other curves, I didn't see the
     * mapping in OSSL:
     *  - TPM2_ECC_BN_P256
     *  - TPM2_ECC_BN_P638
     *  - TPM2_ECC_SM2_P256
     */
};

/**
 * Maps an OSSL nid as defined obj_mac.h to a TPM2 ECC curve id.
 * @param nid
 *  The nid to map.
 * @return
 *  A valid TPM2_ECC_* or TPM2_ALG_ERROR on error.
 */
static TPMI_ECC_CURVE ossl_nid_to_curve(int nid) {

    unsigned i;
    for (i = 0; i < ARRAY_LEN(nid_curve_map); i++) {
        TPMI_ECC_CURVE c = nid_curve_map[i].curve;
        int n = nid_curve_map[i].nid;

        if (n == nid) {
            return c;
        }
    }

    LOG_ERR("Cannot map nid \"%d\" to TPM ECC curve", nid);
    return TPM2_ALG_ERROR;
}

int tpm2_ossl_curve_to_nid(TPMI_ECC_CURVE curve) {

    unsigned i;
    for (i = 0; i < ARRAY_LEN(nid_curve_map); i++) {
        TPMI_ECC_CURVE c = nid_curve_map[i].curve;
        int n = nid_curve_map[i].nid;

        if (c == curve) {
            return n;
        }
    }

    LOG_ERR("Cannot map TPM ECC curve \"%u\" to nid", curve);
    return -1;
}

static bool load_public_ECC_from_key(EC_KEY *k, TPM2B_PUBLIC *pub) {

    bool result = false;

    BIGNUM *y = BN_new();
    BIGNUM *x = BN_new();
    if (!x || !y) {
        LOG_ERR("oom");
        goto out;
    }

    /*
     * Set the algorithm type
     */
    pub->publicArea.type = TPM2_ALG_ECC;

    /*
     * Get the curve type
     */
    const EC_GROUP *group = EC_KEY_get0_group(k);
    int nid = EC_GROUP_get_curve_name(group);

    TPMS_ECC_PARMS *pp = &pub->publicArea.parameters.eccDetail;
    TPM2_ECC_CURVE curve_id = ossl_nid_to_curve(nid); // Not sure what lines up with NIST 256...
    if (curve_id == TPM2_ALG_ERROR) {
        goto out;
    }

    pp->curveID = curve_id;

    /*
     * Set the unique data to the public key.
     */
    const EC_POINT *point = EC_KEY_get0_public_key(k);

    int ret = EC_POINT_get_affine_coordinates_tss(group, point, x, y, NULL);
    if (!ret) {
        LOG_ERR("Could not get X and Y affine coordinates");
        goto out;
    }

    /*
     * Copy the X and Y coordinate data into the ECC unique field,
     * ensuring that it fits along the way.
     */
    TPM2B_ECC_PARAMETER *X = &pub->publicArea.unique.ecc.x;
    TPM2B_ECC_PARAMETER *Y = &pub->publicArea.unique.ecc.y;

    unsigned x_size = (EC_GROUP_get_degree(group) + 7) / 8;
    if (x_size > sizeof(X->buffer)) {
        LOG_ERR("X coordinate is too big. Got %u expected less than or equal to"
                " %zu", x_size, sizeof(X->buffer));
        goto out;
    }

    unsigned y_size = (EC_GROUP_get_degree(group) + 7) / 8;
    if (y_size > sizeof(Y->buffer)) {
        LOG_ERR("X coordinate is too big. Got %u expected less than or equal to"
                " %zu", y_size, sizeof(Y->buffer));
        goto out;
    }

    X->size = BN_bn2binpad(x, X->buffer, x_size);
    if (X->size != x_size) {
        LOG_ERR("Error converting X point BN to binary");
        goto out;
    }

    Y->size = BN_bn2binpad(y, Y->buffer, y_size);
    if (Y->size != y_size) {
        LOG_ERR("Error converting Y point BN to binary");
        goto out;
    }

    /*
     * no kdf - not sure what this should be
     */
    pp->kdf.scheme = TPM2_ALG_NULL;
    pp->scheme.scheme = TPM2_ALG_NULL;
    pp->symmetric.algorithm = TPM2_ALG_NULL;
    pp->scheme.details.anySig.hashAlg = TPM2_ALG_NULL;

    /* NULL out sym details */
    TPMT_SYM_DEF_OBJECT *sym = &pp->symmetric;
    sym->algorithm = TPM2_ALG_NULL;
    sym->keyBits.sym = 0;
    sym->mode.sym = TPM2_ALG_NULL;

    result = true;

out:
    if (x) {
        BN_free(x);
    }
    if (y) {
        BN_free(y);
    }

    return result;
}

EC_KEY *tpm2_openssl_get_public_ECC_from_pem(FILE *f, const char *path) {

    EC_KEY *pub = PEM_read_EC_PUBKEY(f, NULL, NULL, NULL);
    if (!pub) {
        ERR_print_errors_fp(stderr);
        LOG_ERR("Reading public PEM file \"%s\" failed", path);
        return NULL;
    }

    return pub;
}

static bool load_public_ECC_from_pem(FILE *f, const char *path,
        TPM2B_PUBLIC *pub) {

    EC_KEY *k = tpm2_openssl_get_public_ECC_from_pem(f, path);
    if (!k) {
        ERR_print_errors_fp(stderr);
        LOG_ERR("Reading PEM file \"%s\" failed", path);
        return false;
    }

    bool result = load_public_ECC_from_key(k, pub);

    EC_KEY_free(k);

    return result;
}

static bool load_public_AES_from_file(FILE *f, const char *path,
        TPM2B_PUBLIC *pub, TPM2B_SENSITIVE *priv) {

    /*
     * Get the file size and validate that it is the proper AES keysize.
     */
    unsigned long file_size = 0;
    bool result = files_get_file_size(f, &file_size, path);
    if (!result) {
        return false;
    }

    result = tpm2_alg_util_is_aes_size_valid(file_size);
    if (!result) {
        return false;
    }

    pub->publicArea.type = TPM2_ALG_SYMCIPHER;
    TPMT_SYM_DEF_OBJECT *s = &pub->publicArea.parameters.symDetail.sym;
    s->algorithm = TPM2_ALG_AES;
    s->keyBits.aes = file_size * 8;

    /* allow any mode later on */
    s->mode.aes = TPM2_ALG_NULL;

    /*
     * Calculate the unique field with is the
     * is HMAC(sensitive->seedValue, sensitive->sensitive(key itself))
     * Where:
     *   - HMAC Key is the seed
     *   - Hash algorithm is the name algorithm
     */
    TPM2B_DIGEST *unique = &pub->publicArea.unique.sym;
    TPM2B_DIGEST *seed = &priv->sensitiveArea.seedValue;
    TPM2B_PRIVATE_VENDOR_SPECIFIC *key = &priv->sensitiveArea.sensitive.any;
    TPMI_ALG_HASH name_alg = pub->publicArea.nameAlg;

    return tpm2_util_calc_unique(name_alg, key, seed, unique);
}

static bool load_public_KEYEDHASH_from_file(FILE *f, const char *path,
        TPM2B_PUBLIC *pub, TPM2B_SENSITIVE *priv) {

    /*
     * Get the file size and validate that it is within the allowed size for keyed hash objects
     */
    unsigned long file_size = 0;
    bool result = files_get_file_size(f, &file_size, path);
    if (!result) {
        return false;
    }

    if (file_size > 128 || file_size == 0) {
        return false;
    }

    pub->publicArea.type = TPM2_ALG_KEYEDHASH;
    TPMT_KEYEDHASH_SCHEME *s = &pub->publicArea.parameters.keyedHashDetail.scheme;
    s->scheme = TPM2_ALG_NULL;

    /*
     * Calculate the unique field, same as for AES keys
     */
    TPM2B_DIGEST *unique = &pub->publicArea.unique.keyedHash;
    TPM2B_DIGEST *seed = &priv->sensitiveArea.seedValue;
    TPM2B_PRIVATE_VENDOR_SPECIFIC *key = &priv->sensitiveArea.sensitive.any;
    TPMI_ALG_HASH name_alg = pub->publicArea.nameAlg;

    return tpm2_util_calc_unique(name_alg, key, seed, unique);
}

static bool load_private_RSA_from_key(RSA *k, TPM2B_SENSITIVE *priv) {

    const BIGNUM *p; /* the private key exponent */

#if defined(LIB_TPM2_OPENSSL_OPENSSL_PRE11)
    p = k->p;
#else
    RSA_get0_factors(k, &p, NULL);
#endif

    TPMT_SENSITIVE *sa = &priv->sensitiveArea;

    sa->sensitiveType = TPM2_ALG_RSA;

    TPM2B_PRIVATE_KEY_RSA *pkr = &sa->sensitive.rsa;

    unsigned priv_bytes = BN_num_bytes(p);
    if (priv_bytes > sizeof(pkr->buffer)) {
        LOG_ERR("Expected prime \"d\" to be less than or equal to %zu,"
                " got: %u", sizeof(pkr->buffer), priv_bytes);
        return false;
    }

    pkr->size = priv_bytes;

    int success = BN_bn2bin(p, pkr->buffer);
    if (!success) {
        ERR_print_errors_fp(stderr);
        LOG_ERR("Could not copy private exponent \"d\"");
        return false;
    }

    return true;
}

bool tpm2_openssl_load_public(const char *path, TPMI_ALG_PUBLIC alg,
        TPM2B_PUBLIC *pub) {

    FILE *f = fopen(path, "rb");
    if (!f) {
        LOG_ERR("Could not open file \"%s\" error: %s", path, strerror(errno));
        return false;
    }

    bool result = false;

    switch (alg) {
    case TPM2_ALG_RSA:
        result = load_public_RSA_from_pem(f, path, pub);
        break;
    case TPM2_ALG_ECC:
        result = load_public_ECC_from_pem(f, path, pub);
        break;
        /* Skip AES here, as we can only load this one from a private file */
    default:
        /* default try TSS */
        result = files_load_public(path, pub);
    }

    fclose(f);

    return result;
}

static bool load_private_ECC_from_key(EC_KEY *k, TPM2B_SENSITIVE *priv) {

    /*
     * private data
     */
    priv->sensitiveArea.sensitiveType = TPM2_ALG_ECC;

    TPM2B_ECC_PARAMETER *p = &priv->sensitiveArea.sensitive.ecc;

    const EC_GROUP *group = EC_KEY_get0_group(k);
    const BIGNUM *b = EC_KEY_get0_private_key(k);

    unsigned priv_bytes = (EC_GROUP_get_degree(group) + 7) / 8;
    if (priv_bytes > sizeof(p->buffer)) {
        LOG_ERR("Expected ECC private portion to be less than or equal to %zu,"
                " got: %u", sizeof(p->buffer), priv_bytes);
        return false;
    }

    p->size = BN_bn2binpad(b, p->buffer, priv_bytes);
    if (p->size != priv_bytes) {
        return false;
    }

    return true;
}

static tpm2_openssl_load_rc load_private_ECC_from_pem(FILE *f, const char *path,
        const char *passin, TPM2B_PUBLIC *pub, TPM2B_SENSITIVE *priv) {

    tpm2_openssl_load_rc rc = lprc_error;

    char *pass = NULL;
    bool result = handle_ossl_pass(passin, &pass);
    if (!result) {
        return lprc_error;
    }

    EC_KEY *k = PEM_read_ECPrivateKey(f, NULL,
    NULL, (void *) pass);
    free(pass);
    if (!k) {
        ERR_print_errors_fp(stderr);
        LOG_ERR("Reading PEM file \"%s\" failed", path);
        return lprc_error;
    }

    result = load_private_ECC_from_key(k, priv);
    if (!result) {
        rc = lprc_error;
        goto out;
    }

    rc |= lprc_private;

    result = load_public_ECC_from_key(k, pub);
    if (!result) {
        rc = lprc_error;
        goto out;
    }

    rc |= lprc_public;

out:
    EC_KEY_free(k);
    return rc;
}

static tpm2_openssl_load_rc load_private_RSA_from_pem(FILE *f, const char *path,
        const char *passin, TPM2B_PUBLIC *pub, TPM2B_SENSITIVE *priv) {

    RSA *k = NULL;

    tpm2_openssl_load_rc rc = lprc_error;

    char *pass = NULL;
    bool result = handle_ossl_pass(passin, &pass);
    if (!result) {
        return lprc_error;
    }

    k = PEM_read_RSAPrivateKey(f, NULL,
    NULL, (void *) pass);
    free(pass);
    if (!k) {
        ERR_print_errors_fp(stderr);
        LOG_ERR("Reading PEM file \"%s\" failed", path);
        return lprc_error;
    }

    bool loaded_priv = load_private_RSA_from_key(k, priv);
    if (!loaded_priv) {
        return lprc_error;
    } else {
        rc |= lprc_private;
    }

    bool loaded_pub = load_public_RSA_from_key(k, pub);
    if (!loaded_pub) {
        goto out;
    } else {
        rc |= lprc_public;
    }
out:
    RSA_free(k);
    return rc;
}

static tpm2_openssl_load_rc load_private_AES_from_file(FILE *f,
        const char *path, TPM2B_PUBLIC *pub, TPM2B_SENSITIVE *priv) {

    unsigned long file_size = 0;
    bool result = files_get_file_size(f, &file_size, path);
    if (!result) {
        return lprc_error;
    }

    result = tpm2_alg_util_is_aes_size_valid(file_size);
    if (!result) {
        return lprc_error;
    }

    priv->sensitiveArea.sensitiveType = TPM2_ALG_SYMCIPHER;

    TPM2B_SYM_KEY *s = &priv->sensitiveArea.sensitive.sym;
    s->size = file_size;

    result = files_read_bytes(f, s->buffer, s->size);
    if (!result) {
        return lprc_error;
    }

    result = load_public_AES_from_file(f, path, pub, priv);
    if (!result) {
        return lprc_error;
    }

    return lprc_private | lprc_public;
}

static tpm2_openssl_load_rc load_private_KEYEDHASH_from_file(FILE *f,
        const char *path, TPM2B_PUBLIC *pub, TPM2B_SENSITIVE *priv) {

    unsigned long file_size = 0;
    bool result = files_get_file_size(f, &file_size, path);
    if (!result) {
        return lprc_error;
    }

    if (file_size > 128 || file_size == 0) {
      LOG_ERR("Invalid keyedhash key size, got %lu bytes, expected 1 to 128 bytes",
                file_size);
      return lprc_error;
    }

    priv->sensitiveArea.sensitiveType = TPM2_ALG_KEYEDHASH;

    TPM2B_SENSITIVE_DATA *b = &priv->sensitiveArea.sensitive.bits;
    b->size = file_size;

    result = files_read_bytes(f, b->buffer, b->size);
    if (!result) {
        return lprc_error;
    }

    result = load_public_KEYEDHASH_from_file(f, path, pub, priv);
    if (!result) {
        return lprc_error;
    }

    return lprc_private | lprc_public;
}

/**
 * Loads a private portion of a key, and possibly the public portion, as for RSA the public data is in
 * a private pem file.
 *
 * @param path
 *  The path to load from.
 * @param alg
 *  algorithm type to import.
 * @param pub
 *  The public structure to populate. Note that nameAlg must be populated.
 * @param priv
 *  The sensitive structure to populate.
 *
 * @returns
 *  A private object loading status
 */
tpm2_openssl_load_rc tpm2_openssl_load_private(const char *path,
        const char *pass, TPMI_ALG_PUBLIC alg, TPM2B_PUBLIC *pub,
        TPM2B_SENSITIVE *priv) {

    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_ERR("Could not open file \"%s\", error: %s", path, strerror(errno));
        return 0;
    }

    tpm2_openssl_load_rc rc = lprc_error;

    switch (alg) {
    case TPM2_ALG_RSA:
        rc = load_private_RSA_from_pem(f, path, pass, pub, priv);
        break;
    case TPM2_ALG_AES:
        if (pass) {
            LOG_ERR("No password can be used for protecting AES key");
            rc = lprc_error;
        } else {
            rc = load_private_AES_from_file(f, path, pub, priv);
        }
        break;
    case TPM2_ALG_HMAC:
        if (pass) {
            LOG_ERR("No password can be used for protecting HMAC key");
            rc = lprc_error;
        } else {
            rc = load_private_KEYEDHASH_from_file(f, path, pub, priv);
	}
      break;
    case TPM2_ALG_ECC:
        rc = load_private_ECC_from_pem(f, path, pass, pub, priv);
        break;
    default:
        LOG_ERR("Cannot handle algorithm, got: %s", tpm2_alg_util_algtostr(alg,
            tpm2_alg_util_flags_any));
        rc = lprc_error;
    }

    fclose(f);

    return rc;
}

bool tpm2_openssl_import_keys(
    TPM2B_PUBLIC *parent_pub,
    TPM2B_SENSITIVE *private,
    TPM2B_PUBLIC *public,
    TPM2B_ENCRYPTED_SECRET *encrypted_seed,
    const char *input_key_file,
    TPMI_ALG_PUBLIC key_type,
    const char *auth_key_file,
    const char *policy_file,
    const char *key_auth_str,
    char *attrs_str,
    const char *name_alg_str
)
{
    bool result;

    TPMA_OBJECT attrs = TPMA_OBJECT_DECRYPT | TPMA_OBJECT_SIGN_ENCRYPT;

    if (policy_file) {
        public->publicArea.authPolicy.size = sizeof(public->publicArea.authPolicy.buffer);
        result = files_load_bytes_from_path(policy_file,
            public->publicArea.authPolicy.buffer,
                &public->publicArea.authPolicy.size);
        if (!result) {
            return false;
        }
    } else {
        attrs |= TPMA_OBJECT_USERWITHAUTH;
    }

    if (key_auth_str) {
        tpm2_session *tmp;
        tool_rc tmp_rc = tpm2_auth_util_from_optarg(NULL, key_auth_str, &tmp, true);
        if (tmp_rc != tool_rc_success) {
            LOG_ERR("Invalid key authorization");
            return false;
        }

        const TPM2B_AUTH *auth = tpm2_session_get_auth_value(tmp);
        private->sensitiveArea.authValue = *auth;

        tpm2_session_close(&tmp);
    }

    /*
     * Set the object attributes if specified, overwriting the defaults, but hooking the errata
     * fixups.
     */
    if (attrs_str) {
        TPMA_OBJECT *obj_attrs = &public->publicArea.objectAttributes;
        result = tpm2_attr_util_obj_from_optarg(attrs_str, obj_attrs);
        if (!result) {
            LOG_ERR("Invalid object attribute, got\"%s\"", attrs_str);
            return false;
        }

        tpm2_errata_fixup(SPEC_116_ERRATA_2_7,
                &public->publicArea.objectAttributes);
    } else {
        public->publicArea.objectAttributes = attrs;
    }

    if (name_alg_str) {
        TPMI_ALG_HASH alg = tpm2_alg_util_from_optarg(name_alg_str,
                tpm2_alg_util_flags_hash);
        if (alg == TPM2_ALG_ERROR) {
            LOG_ERR("Invalid name hashing algorithm, got\"%s\"", name_alg_str);
            return tool_rc_general_error;
        }
        public->publicArea.nameAlg = alg;
    } else {
        /*
         * use the parent name algorithm if not specified
         */
        public->publicArea.nameAlg = parent_pub->publicArea.nameAlg;
    }

    /*
     * The TPM Requires that the name algorithm for the child be less than the name
     * algorithm of the parent when the parent's scheme is NULL.
     *
     * This check can be seen in the simulator at:
     *   - File: CryptUtil.c
     *   - Func: CryptSecretDecrypt()
     *   - Line: 2019
     *   - Decription: Limits the size of the hash algorithm to less then the parent's name-alg when scheme is NULL.
     */
    UINT16 hash_size = tpm2_alg_util_get_hash_size(public->publicArea.nameAlg);
    UINT16 parent_hash_size = tpm2_alg_util_get_hash_size(
            parent_pub->publicArea.nameAlg);
    if (hash_size > parent_hash_size) {
        LOG_WARN("Hash selected is larger then parent hash size, coercing to "
                 "parent hash algorithm: %s",
                tpm2_alg_util_algtostr(parent_pub->publicArea.nameAlg,
                        tpm2_alg_util_flags_hash));
        public->publicArea.nameAlg = parent_pub->publicArea.nameAlg;
    }

    /*
     * Generate and encrypt seed, if requested
     */
    if (encrypted_seed)
    {
        TPM2B_DIGEST *seed = &private->sensitiveArea.seedValue;
        static const unsigned char label[] = { 'D', 'U', 'P', 'L', 'I', 'C', 'A', 'T', 'E', '\0' };
        result = tpm2_identity_util_share_secret_with_public_key(seed, parent_pub,
            label, sizeof(label), encrypted_seed);
        if (!result) {
            LOG_ERR("Failed Seed Encryption\n");
            return false;
        }
    }

    /*
     * Populate all the private and public data fields we can based on the key type and the PEM files read in.
     */
    tpm2_openssl_load_rc status = tpm2_openssl_load_private(input_key_file,
            auth_key_file, key_type, public, private);
    if (status == lprc_error) {
        return false;
    }

    if (!tpm2_openssl_did_load_public(status)) {
        LOG_ERR("Did not find public key information in file: \"%s\"",
                input_key_file);
        return false;
    }

    return true;
}
