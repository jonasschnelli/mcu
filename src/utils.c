/*

 The MIT License (MIT)

 Copyright (c) 2015-2016 Douglas J. Bakkum

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/


#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "utils.h"
#include "flags.h"


static uint8_t buffer_hex_to_uint8[TO_UINT8_HEX_BUF_LEN];
static char buffer_uint8_to_hex[TO_UINT8_HEX_BUF_LEN];


volatile void *utils_zero(volatile void *dst, size_t len)
{
    volatile char *buf;
    for (buf = (volatile char *)dst;  len;  buf[--len] = 0);
    return dst;
}


void utils_clear_buffers(void)
{
    memset(buffer_hex_to_uint8, 0, TO_UINT8_HEX_BUF_LEN);
    memset(buffer_uint8_to_hex, 0, TO_UINT8_HEX_BUF_LEN);
}


uint8_t utils_is_hex(const char *str)
{
    static char characters[] = "abcdefABCDEF0123456789";
    size_t i;

    if (!strlens(str)) {
        return DBB_ERROR;
    }

    for (i = 0 ; i < strlens(str); i++) {
        if (!strchr(characters, str[i])) {
            return DBB_ERROR;
        }
    }
    return DBB_OK;
}


uint8_t utils_limit_alphanumeric_hyphen_underscore_period(const char *str)
{
    static char characters[] =
        ".-_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t i;

    if (!strlens(str)) {
        return DBB_ERROR;
    }

    for (i = 0 ; i < strlens(str); i++) {
        if (!strchr(characters, str[i])) {
            return DBB_ERROR;
        }
    }
    return DBB_OK;
}


uint8_t *utils_hex_to_uint8(const char *str)
{
    if (strlens(str) > TO_UINT8_HEX_BUF_LEN) {
        return NULL;
    }
    memset(buffer_hex_to_uint8, 0, TO_UINT8_HEX_BUF_LEN);
    uint8_t c;
    size_t i;
    for (i = 0; i < strlens(str) / 2; i++) {
        c = 0;
        if (str[i * 2] >= '0' && str[i * 2] <= '9') {
            c += (str[i * 2] - '0') << 4;
        }
        if (str[i * 2] >= 'a' && str[i * 2] <= 'f') {
            c += (10 + str[i  * 2] - 'a') << 4;
        }
        if (str[i * 2] >= 'A' && str[i * 2] <= 'F') {
            c += (10 + str[i * 2] - 'A') << 4;
        }
        if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') {
            c += (str[i * 2 + 1] - '0');
        }
        if (str[i * 2 + 1] >= 'a' && str[i * 2 + 1] <= 'f') {
            c += (10 + str[i * 2 + 1] - 'a');
        }
        if (str[i * 2 + 1] >= 'A' && str[i * 2 + 1] <= 'F') {
            c += (10 + str[i * 2 + 1] - 'A');
        }
        buffer_hex_to_uint8[i] = c;
    }
    return buffer_hex_to_uint8;
}


char *utils_uint8_to_hex(const uint8_t *bin, size_t l)
{
    if (l > (TO_UINT8_HEX_BUF_LEN / 2 - 1)) {
        return NULL;
    }
    static char digits[] = "0123456789abcdef";
    memset(buffer_uint8_to_hex, 0, TO_UINT8_HEX_BUF_LEN);
    size_t i;
    for (i = 0; i < l; i++) {
        buffer_uint8_to_hex[i * 2] = digits[(bin[i] >> 4) & 0xF];
        buffer_uint8_to_hex[i * 2 + 1] = digits[bin[i] & 0xF];
    }
    buffer_uint8_to_hex[l * 2] = '\0';
    return buffer_uint8_to_hex;
}


void utils_reverse_hex(char *h, int len)
{
    char copy[len];
    strncpy(copy, h, len);
    int i;
    for (i = 0; i < len; i += 2) {
        h[i] = copy[len - i - 2];
        h[i + 1] = copy[len - i - 1];
    }
}


void utils_uint64_to_varint(char *vi, int *l, uint64_t i)
{
    int len;
    char v[VARINT_LEN];

    if (i < 0xfd) {
        sprintf(v, "%02" PRIx64 , i);
        len = 2;
    } else if (i <= 0xffff) {
        sprintf(v, "%04" PRIx64 , i);
        sprintf(vi, "fd");
        len = 4;
    } else if (i <= 0xffffffff) {
        sprintf(v, "%08" PRIx64 , i);
        sprintf(vi, "fe");
        len = 8;
    } else {
        sprintf(v, "%016" PRIx64 , i);
        sprintf(vi, "ff");
        len = 16;
    }

    // reverse order
    if (len > 2) {
        utils_reverse_hex(v, len);
        strncat(vi, v, len);
    } else {
        strncpy(vi, v, len);
    }

    *l = len;
}


int utils_varint_to_uint64(const char *vi, uint64_t *i)
{
    char v[VARINT_LEN] = {0};
    int len;

    if (!vi) {
        len = 0;
    } else if (!strncmp(vi, "ff", 2)) {
        len = 16;
    } else if (!strncmp(vi, "fe", 2)) {
        len = 8;
    } else if (!strncmp(vi, "fd", 2)) {
        len = 4;
    } else {
        len = 2;
    }

    if (len == 0) {
        // continue
    } else if (len > 2) {
        strncpy(v, vi + 2, len);
        utils_reverse_hex(v, len);
    } else {
        strncpy(v, vi, len);
    }
    *i = strtoull(v, NULL, 16);

    return len;
}

#ifdef TESTING
#include <assert.h>
#include <ctype.h>
#include "commander.h"
#include "yajl/src/api/yajl_tree.h"

#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 8
#endif

void hexdump(void *mem, unsigned int len)
{
        unsigned int i, j;

        for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
        {
                /* print offset */
                if(i % HEXDUMP_COLS == 0)
                {
                        printf("0x%06x: ", i);
                }

                /* print hex data */
                if(i < len)
                {
                        printf("%02x ", 0xFF & ((char*)mem)[i]);
                }
                else /* end of block, just aligning for ASCII dump */
                {
                        printf("   ");
                }

                /* print ASCII dump */
                if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
                {
                        for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
                        {
                                if(j >= len) /* end of block, not really printing */
                                {
                                        putchar(' ');
                                }
                                else if(isprint(((char*)mem)[j])) /* printable char */
                                {
                                        putchar(0xFF & ((char*)mem)[j]);
                                }
                                else /* other char */
                                {
                                        putchar('.');
                                }
                        }
                        putchar('\n');
                }
        }
}

static const char *flag_msg_from_code(uint16_t search_code)
{
    int id = 0;
    for (id = 0; id < DBB_FLAG_NUM; id++) {
        if (search_code == flag_code(id)) {
            return flag_msg(id);
        }
    }
    return NULL;
}

static char decrypted_report[COMMANDER_REPORT_SIZE*2];
static uint8_t decrypted_report_bin[COMMANDER_REPORT_SIZE];
static int decrypted_report_bin_len = 0;


const char *utils_read_decrypted_report(void)
{
    return decrypted_report;
}

const uint8_t *utils_read_decrypted_report_bin(int *len_out)
{
    if (len_out)
        *len_out = decrypted_report_bin_len;
    return decrypted_report_bin;
}


static const char* commander_get_cmd_str(const uint16_t instr)
{
    int id;
    for (id = 0; id < CMD_NUM; id++) {
        if (instr == cmd_instr(id)) {
            return cmd_str(id);
        }
    }
    return NULL;
}


static const char* commander_get_attr_str(const uint16_t instr)
{
    int id;
    for (id = 0; id < ATTR_NUM; id++) {
        if (instr == attr_instr(id)) {
            return attr_str(id);
        }
    }
    return NULL;
}


void utils_decrypt_report_bin(const uint8_t *report, int len, PASSWORD_ID dec_id)
{
    int decrypt_len = 0;
    memset(decrypted_report_bin, 0, sizeof(decrypted_report_bin));
    memset(decrypted_report, 0, sizeof(decrypted_report));

    uint8_t response_flags = report[0];
    if (( (response_flags & DBB_RESPONSE_FLAG_ENCRYPTED) || (response_flags & DBB_RESPONSE_FLAG_ENCRYPTED_VERIFYKEY)) && len >= 16) {
        uint8_t *dec = aes_cbc_decrypt_pad((const unsigned char *)&report[1], len-1, &decrypt_len, (response_flags & DBB_RESPONSE_FLAG_ENCRYPTED_VERIFYKEY) ? PASSWORD_VERIFY : dec_id);
        // copy everything except the flag
        assert(decrypt_len < (int)sizeof(decrypted_report_bin));
        printf("Decrypted response:\n");
        hexdump(dec, decrypt_len);
        memcpy(decrypted_report_bin, dec, decrypt_len);
        decrypted_report_bin_len = decrypt_len;
        free(dec);
    }
    else {
        // copy everything except the flag
        memcpy(decrypted_report_bin, &report[1], len-1);
        decrypted_report_bin_len = len-1;
    }

    strncat(decrypted_report, "{", 1);

    int c = 0;
    while(c+4 <= decrypted_report_bin_len)
    {
        uint16_t instr = (decrypted_report_bin[c] << 8) + decrypted_report_bin[c+1];
        uint16_t attr = (decrypted_report_bin[c+2] << 8) + decrypted_report_bin[c+3];
        c+=4;
        if ( attr == cmd_instr(CMD_valuearray) )
        {
            /* we are parsing an array */
            snprintf(decrypted_report + strlens(decrypted_report), sizeof(decrypted_report) - strlens(decrypted_report)," \"%s\": {", commander_get_cmd_str(instr));
            uint16_t array_size = (decrypted_report_bin[c] << 8) + decrypted_report_bin[c+1];
            c+=2;
            for (unsigned int i = 0; i < array_size; i++)
            {
                uint16_t sub_cmd = (decrypted_report_bin[c] << 8) + decrypted_report_bin[c+1];
                c+=2;
                if( sub_cmd == cmd_instr(CMD_pubkeystatusarray) )
                {
                    snprintf(decrypted_report + strlens(decrypted_report), sizeof(decrypted_report) - strlens(decrypted_report)," \"%s\": [", cmd_str(CMD_checkpub));

                    uint16_t sub_array_size = (decrypted_report_bin[c] << 8) + decrypted_report_bin[c+1];
                    c+=2;
                    for (unsigned int j = 0; j < sub_array_size; j++)
                    {
                        uint8_t *pubkey = &decrypted_report_bin[c];
                        c+=33;
                        uint8_t status = (uint8_t)decrypted_report_bin[c];
                        c+=1;
                        char *pubkey_hex = utils_uint8_to_hex(pubkey, 33);
                        snprintf(decrypted_report + strlens(decrypted_report), sizeof(decrypted_report) - strlens(decrypted_report),"{ \"%s\":\"%s\", \"%s\":%s }", cmd_str(CMD_pubkey), pubkey_hex, cmd_str(CMD_present), (status == 1 ? attr_str(ATTR_true) : attr_str(ATTR_false)) );
                        if (j+1 < sub_array_size)
                            strcat(decrypted_report, ",");
                    }
                    strcat(decrypted_report, "]");
                }
                else if( sub_cmd == cmd_instr(CMD_hashkeypatharray) )
                {
                    snprintf(decrypted_report + strlens(decrypted_report), sizeof(decrypted_report) - strlens(decrypted_report)," \"%s\": [", cmd_str(CMD_data));

                    uint16_t sub_array_size = (decrypted_report_bin[c] << 8) + decrypted_report_bin[c+1];
                    c+=2;
                    for (unsigned int j = 0; j < sub_array_size; j++)
                    {
                        uint16_t ele_len = (decrypted_report_bin[c] << 8) + decrypted_report_bin[c+1];
                        c+=2;
                        uint8_t *hash = &decrypted_report_bin[c];
                        c+=32;
                        char *keypath = (char *)&decrypted_report_bin[c];
                        char *hash_hex = utils_uint8_to_hex(hash, 32);
                        snprintf(decrypted_report + strlens(decrypted_report), sizeof(decrypted_report) - strlens(decrypted_report),"{ \"%s\": \"%s\", \"%s\": \"%s\" }", cmd_str(CMD_hash), hash_hex, cmd_str(CMD_keypath), keypath);
                        if (j+1 < sub_array_size)
                            strcat(decrypted_report, ",");
                        c+=ele_len-32;
                    }
                    strcat(decrypted_report, "]");
                }
                else
                {
                    // get type
                    uint16_t val_type = (decrypted_report_bin[c] << 8) + decrypted_report_bin[c+1];
                    c+=2;
                    if (val_type == cmd_instr(CMD_value_str))
                    {
                        uint16_t sub_val_len = (decrypted_report_bin[c] << 8) + decrypted_report_bin[c+1];
                        c+=2;
                        char *val_str = (char *)&decrypted_report_bin[c];

                        snprintf(decrypted_report + strlens(decrypted_report), sizeof(decrypted_report) - strlens(decrypted_report)," \"%s\":\"%s\"", commander_get_attr_str(sub_cmd), val_str);
                        c+=sub_val_len;
                    }
                    else if (val_type == cmd_instr(CMD_value_bool))
                    {
                        uint8_t bool_val = (uint8_t)decrypted_report_bin[c];
                        c+=1;
                        snprintf(decrypted_report + strlens(decrypted_report), sizeof(decrypted_report) - strlens(decrypted_report)," \"%s\":%s", commander_get_attr_str(sub_cmd), (bool_val == 1 ? attr_str(ATTR_true) : attr_str(ATTR_false)));
                    }
                }

                if (i+1 < array_size)
                    strcat(decrypted_report, ",");
            }
            strcat(decrypted_report, "}");
        }
        else if( attr == cmd_instr(CMD_sigpubkeyarray) )
        {
            snprintf(decrypted_report + strlens(decrypted_report), sizeof(decrypted_report) - strlens(decrypted_report)," \"%s\": [", cmd_str(CMD_sign));

            uint16_t sub_array_size = (decrypted_report_bin[c] << 8) + decrypted_report_bin[c+1];
            c+=2;
            for (unsigned int j = 0; j < sub_array_size; j++)
            {
                uint8_t *sig = &decrypted_report_bin[c];
                uint8_t *pubkey = &decrypted_report_bin[c+64];
                char sig_hex[64*2+1];
                memcpy(sig_hex, utils_uint8_to_hex(sig, 64), 64*2+1);
                char *pubkey_hex = utils_uint8_to_hex(pubkey, 33);
                snprintf(decrypted_report + strlens(decrypted_report), sizeof(decrypted_report) - strlens(decrypted_report),"{ \"%s\": \"%s\", \"%s\": \"%s\" }", cmd_str(CMD_sig), sig_hex, cmd_str(CMD_pubkey), pubkey_hex);
                if (j+1 < sub_array_size)
                    strcat(decrypted_report, ",");
                c+=64+33;
            }
            strcat(decrypted_report, "]");
        }
        else if (instr == cmd_instr(CMD_error)) {
            uint16_t errored_instr = attr;
            uint16_t flag = (decrypted_report_bin[c] << 8) + decrypted_report_bin[c+1];
            uint16_t attempts_left = (decrypted_report_bin[c+2] << 8) + decrypted_report_bin[c+3];
            const char *error_str = flag_msg_from_code(flag);
            snprintf(decrypted_report + strlens(decrypted_report), sizeof(decrypted_report) - strlens(decrypted_report)," \"%s\": { \"message\" : \"%s\", \"code\" : \"%u\", \"command\" : \"%s\", \"attempts left\":%u } ", commander_get_cmd_str(instr), error_str, flag, commander_get_cmd_str(errored_instr), attempts_left);
            c+=6;
        }
        else {
            if (attr == cmd_instr(CMD_value_str)) {
                uint16_t str_len = (decrypted_report_bin[c] << 8) + decrypted_report_bin[c+1];
                const char *str_val = (const char *)&decrypted_report_bin[c+2];
                snprintf(decrypted_report + strlens(decrypted_report), sizeof(decrypted_report) - strlens(decrypted_report)," \"%s\": \"%s\"", commander_get_cmd_str(instr), str_val);
                c+=2+str_len;
            }
            else
                snprintf(decrypted_report + strlens(decrypted_report), sizeof(decrypted_report) - strlens(decrypted_report)," \"%s\": \"%s\"", commander_get_cmd_str(instr), commander_get_attr_str(attr));
        }

        if (c+4 <= decrypted_report_bin_len)
            strcat(decrypted_report, ", ");
    }
    strcat(decrypted_report, "}");
    printf("%s\n", decrypted_report);
}


void utils_decrypt_report(const char *report, PASSWORD_ID dec_id)
{
    int decrypt_len;
    char *dec;

    memset(decrypted_report, 0, sizeof(decrypted_report));

    yajl_val json_node = yajl_tree_parse(report, NULL, 0);

    if (!json_node) {
        strcpy(decrypted_report, "/* error: Failed to parse report. */");
        return;
    }

    size_t i, r = json_node->u.object.len;
    for (i = 0; i < r; i++) {
        const char *ciphertext_path[] = { cmd_str(CMD_ciphertext), (const char *) 0 };
        const char *echo_path[] = { "echo", (const char *) 0 };
        const char *ciphertext = YAJL_GET_STRING(yajl_tree_get(json_node, ciphertext_path,
                                 yajl_t_string));
        const char *echo = YAJL_GET_STRING(yajl_tree_get(json_node, echo_path, yajl_t_string));
        if (ciphertext) {
            dec = aes_cbc_b64_decrypt((const unsigned char *)ciphertext, strlens(ciphertext),
                                      &decrypt_len, dec_id);
            if (!dec) {
                strcpy(decrypted_report, "/* error: Failed to decrypt. */");
                goto exit;
            }

            sprintf(decrypted_report, "/* ciphertext */ %.*s", decrypt_len, dec);
            free(dec);
            goto exit;
        } else if (echo) {
            dec = aes_cbc_b64_decrypt((const unsigned char *)echo, strlens(echo), &decrypt_len,
                                      PASSWORD_VERIFY);
            if (!dec) {
                strcpy(decrypted_report, "/* error: Failed to decrypt echo. */");
                goto exit;
            }

            sprintf(decrypted_report, "/* echo */ %.*s", decrypt_len, dec);
            free(dec);
            goto exit;
        }
    }
    strcpy(decrypted_report, report);
exit:
    yajl_tree_free(json_node);
    return;
}


void utils_send_cmd(const uint8_t *command, uint16_t len, PASSWORD_ID enc_id)
{
    if (enc_id == PASSWORD_NONE) {
        int len_out = 0;
        uint8_t cmd[COMMANDER_REPORT_SIZE] = {0};
        cmd[0] = 0;
        assert(len < COMMANDER_REPORT_SIZE-1);
        memcpy(cmd+1, command, len);
        const uint8_t *out_buf = commander(cmd, len+1, &len_out);
        utils_decrypt_report_bin(out_buf, len_out, enc_id);
    } else {
        int encrypt_len;
        uint8_t *enc = aes_cbc_encrypt_pad((const unsigned char *)command, len,
                                        &encrypt_len,
                                        enc_id);
        uint8_t cmd[COMMANDER_REPORT_SIZE] = {0};
        assert(encrypt_len < COMMANDER_REPORT_SIZE-1);
        cmd[0] = 0;
        cmd[0] |= DBB_RESPONSE_FLAG_ENCRYPTED;
        memcpy(cmd+1, enc, encrypt_len);
        free(enc);
        int len_out = 0;
        const uint8_t *enc_respo = commander(cmd, encrypt_len+1, &len_out);
        utils_decrypt_report_bin(enc_respo, len_out, enc_id);
    }
}

#endif
