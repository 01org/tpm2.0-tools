#include "tpm2_util.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

bool tpm2_util_concat_buffer(TPM2B_MAX_BUFFER *result, TPM2B *append) {

    if (!result || !append) {
        return false;
    }

    if ((result->t.size + append->size) < result->t.size) {
        return false;
    }

    if ((result->t.size + append->size) > MAX_DIGEST_BUFFER) {
        return false;
    }

    memcpy(&result->t.buffer[result->t.size], append->buffer, append->size);
    result->t.size += append->size;

    return true;
}

bool tpm2_util_string_to_uint16(const char *str, uint16_t *value) {

    uint32_t tmp;
    bool result = tpm2_util_string_to_uint32(str, &tmp);
    if (!result) {
        return false;
    }

    /* overflow on 16 bits? */
    if (tmp > UINT16_MAX) {
        return false;
    }

    *value = (uint16_t) tmp;
    return true;
}

bool tpm2_util_string_to_uint32(const char *str, uint32_t *value) {

    char *endptr;

    if (str == NULL || *str == '\0') {
        return false;
    }

    /* clear errno before the call, should be 0 afterwards */
    errno = 0;
    uint32_t tmp = strtoul(str, &endptr, 0);
    if (errno) {
        return false;
    }

    /*
     * The entire string should be able to be converted or fail
     * We already checked that str starts with a null byte, so no
     * need to check that again per the man page.
     */
    if (*endptr != '\0') {
        return false;
    }

    *value = tmp;
    return true;
}

int tpm2_util_hex_to_byte_structure(const char *inStr, UINT16 *byteLength,
        BYTE *byteBuffer) {
    int strLength; //if the inStr likes "1a2b...", no prefix "0x"
    int i = 0;
    if (inStr == NULL || byteLength == NULL || byteBuffer == NULL)
        return -1;
    strLength = strlen(inStr);
    if (strLength % 2)
        return -2;
    for (i = 0; i < strLength; i++) {
        if (!isxdigit(inStr[i]))
            return -3;
    }

    if (*byteLength < strLength / 2)
        return -4;

    *byteLength = strLength / 2;

    for (i = 0; i < *byteLength; i++) {
        char tmpStr[4] = { 0 };
        tmpStr[0] = inStr[i * 2];
        tmpStr[1] = inStr[i * 2 + 1];
        byteBuffer[i] = strtol(tmpStr, NULL, 16);
    }
    return 0;
}

void tpm2_util_print_tpm2b(TPM2B *buffer) {

    unsigned i;
    for (i = 0; i < buffer->size; i++) {
        printf("%2.2x ", buffer->buffer[i]);

        if (((i + 1) % 16) == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

/* TODO OPTIMIZE ME */
UINT16 tpm2_util_copy_tpm2b(TPM2B *dest, TPM2B *src) {
    int i;
    UINT16 rval = 0;

    if (dest != 0) {
        if (src == 0) {
            dest->size = 0;
            rval = 0;
        } else {
            dest->size = src->size;
            for (i = 0; i < src->size; i++)
                dest->buffer[i] = src->buffer[i];
            rval = (sizeof(UINT16) + src->size);
        }
    } else {
        rval = 0;
    }

    return rval;
}

bool tpm2_util_is_big_endian(void) {

    uint32_t test_word;
    uint8_t *test_byte;

    test_word = 0xFF000000;
    test_byte = (uint8_t *) (&test_word);

    return test_byte[0] == 0xFF;
}

#define STRING_BYTES_ENDIAN_CONVERT(size) \
    UINT##size tpm2_util_endian_swap_##size(UINT##size data) { \
    \
        UINT##size converted; \
        UINT8 *bytes = (UINT8 *)&data; \
        UINT8 *tmp = (UINT8 *)&converted; \
    \
        size_t i; \
        for(i=0; i < sizeof(UINT##size); i ++) { \
            tmp[i] = bytes[sizeof(UINT##size) - i - 1]; \
        } \
        \
        return converted; \
    }

STRING_BYTES_ENDIAN_CONVERT(16)
STRING_BYTES_ENDIAN_CONVERT(32)
STRING_BYTES_ENDIAN_CONVERT(64)

#define STRING_BYTES_ENDIAN_HTON(size) \
    UINT##size tpm2_util_hton_##size(UINT##size data) { \
    \
        bool is_big_endian = tpm2_util_is_big_endian(); \
        if (is_big_endian) { \
           return data; \
        } \
    \
        return tpm2_util_endian_swap_##size(data); \
    }

STRING_BYTES_ENDIAN_HTON(16)
STRING_BYTES_ENDIAN_HTON(32)
STRING_BYTES_ENDIAN_HTON(64)

/*
 * Converting from host-to-network (hton) or network-to-host (ntoh) is
 * the same operation: if endianess differs between host and data, swap
 * endianess. Thus we can just call the hton routines, but have some nice
 * names for folks.
 */
UINT16 tpm2_util_ntoh_16(UINT16 data) {
    return tpm2_util_hton_16(data);
}

UINT32 tpm2_util_ntoh_32(UINT32 data) {
    return tpm2_util_hton_32(data);
}
UINT64 tpm2_util_ntoh_64(UINT64 data) {
    return tpm2_util_hton_64(data);
}

static char nibble_to_char(BYTE b) {

    return (b <= 9) ?
        b + 0x30 : /* starting at 0, start returning ascii '0' */
        b + 0x37;  /* starting at 10, start returning ascii 'A' */
}

char *tpm2_util_to_hex(BYTE *bytes, UINT16 length) {

    //byte1[nibble|nibble]...\0
    // 2 chars per byte, +2 for the prefix, + 1 for null byte;
    char *s = malloc((2 * length) + 3);
    if (!s) {
        return s;
    }

    char *curr = s;
    curr += sprintf(curr, "0x");

    UINT16 i;
    for(i=0; i < length; i++) {
        BYTE low = bytes[i] & 0x0F;
        BYTE high = (bytes[i] & 0xF0) >> 4;

        char lowchar = nibble_to_char(low);
        char highchar = nibble_to_char(high);
        curr += sprintf(curr, "%c%c", highchar, lowchar);
    }

    return s;
}
