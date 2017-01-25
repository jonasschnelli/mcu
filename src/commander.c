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


#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "commander.h"
#include "version.h"
#include "random.h"
#include "base64.h"
#include "wallet.h"
#include "utils.h"
#include "flags.h"
#include "sha2.h"
#include "aes.h"
#include "led.h"
#include "ecc.h"
#ifndef TESTING
#include "ataes132.h"
#include "touch.h"
#include "mcu.h"
#include "sd.h"
#else
#include "sham.h"
#endif


extern const uint8_t MEM_PAGE_ERASE[MEM_PAGE_LEN];

static int REPORT_BUF_OVERFLOW = 0;
__extension__ static uint8_t response_report[] = {[0 ... COMMANDER_REPORT_SIZE] = 0};
static uint8_t *response_report_current_p = response_report;
__extension__ static uint8_t sign_command[] = {[0 ... COMMANDER_REPORT_SIZE] = 0};
static int sign_command_len = 0;
static char TFA_PIN[VERIFYPASS_LOCK_CODE_LEN * 2 + 1];
static int TFA_VERIFY = 0;

// Must free() returned value (allocated inside base64() function)
char *aes_cbc_b64_encrypt(const unsigned char *in, int inlen, int *out_b64len,
                          PASSWORD_ID id)
{
    int  pads;
    int  inpadlen = inlen + N_BLOCK - inlen % N_BLOCK;
    unsigned char inpad[inpadlen];
    unsigned char enc[inpadlen];
    unsigned char iv[N_BLOCK];
    unsigned char enc_cat[inpadlen + N_BLOCK]; // concatenating [ iv0  |  enc ]
    aes_context ctx[1];

    // Set cipher key
    memset(ctx, 0, sizeof(ctx));
    aes_set_key(memory_report_aeskey(id), 32, ctx);

    // PKCS7 padding
    memcpy(inpad, in, inlen);
    for (pads = 0; pads < N_BLOCK - inlen % N_BLOCK; pads++ ) {
        inpad[inlen + pads] = (N_BLOCK - inlen % N_BLOCK);
    }

    // Make a random initialization vector
    if (random_bytes((uint8_t *)iv, N_BLOCK, 0) == DBB_ERROR) {
        commander_fill_report(cmd_str(CMD_random), NULL, DBB_ERR_MEM_ATAES);
        utils_zero(inpad, inpadlen);
        return NULL;
    }
    memcpy(enc_cat, iv, N_BLOCK);

    // CBC encrypt multiple blocks
    aes_cbc_encrypt( inpad, enc, inpadlen / N_BLOCK, iv, ctx );
    memcpy(enc_cat + N_BLOCK, enc, inpadlen);

    // base64 encoding
    int b64len;
    char *b64;
    b64 = base64(enc_cat, inpadlen + N_BLOCK, &b64len);
    *out_b64len = b64len;
    utils_zero(inpad, inpadlen);
    return b64;
}

uint8_t *aes_cbc_encrypt_pad(const unsigned char *in, int inlen, int *out_len,
                          PASSWORD_ID id)
{
    int  pads;
    int  inpadlen = inlen + N_BLOCK - inlen % N_BLOCK;
    uint8_t inpad[inpadlen];
    uint8_t enc[inpadlen];
    uint8_t iv[N_BLOCK];
    uint8_t *enc_cat = malloc(inpadlen + N_BLOCK); // concatenating [ iv0  |  enc ]
    aes_context ctx[1];

    // Set cipher key
    memset(ctx, 0, sizeof(ctx));
    aes_set_key(memory_report_aeskey(id), 32, ctx);

    // PKCS7 padding
    memcpy(inpad, in, inlen);
    for (pads = 0; pads < N_BLOCK - inlen % N_BLOCK; pads++ ) {
        inpad[inlen + pads] = (N_BLOCK - inlen % N_BLOCK);
    }

    // Make a random initialization vector
    if (random_bytes((uint8_t *)iv, N_BLOCK, 0) == DBB_ERROR) {
        commander_fill_report(cmd_str(CMD_random), NULL, DBB_ERR_MEM_ATAES);
        utils_zero(inpad, inpadlen);
        return NULL;
    }
    memcpy(enc_cat, iv, N_BLOCK);

    // CBC encrypt multiple blocks
    aes_cbc_encrypt( inpad, enc, inpadlen / N_BLOCK, iv, ctx );
    memcpy(enc_cat + N_BLOCK, enc, inpadlen);
    *out_len = inpadlen + N_BLOCK;
    return enc_cat;
}


// Must free() returned value
char *aes_cbc_b64_decrypt(const unsigned char *in, int inlen, int *decrypt_len,
                          PASSWORD_ID id)
{
    *decrypt_len = 0;

    if (!in || inlen == 0) {
        return NULL;
    }

    // Unbase64
    int ub64len;
    unsigned char *ub64 = unbase64((const char *)in, inlen, &ub64len);
    if (!ub64 || (ub64len % N_BLOCK) || ub64len < N_BLOCK) {
        free(ub64);
        return NULL;
    }

    // Set cipher key
    aes_context ctx[1];
    memset(ctx, 0, sizeof(ctx));
    aes_set_key(memory_report_aeskey(id), 32, ctx);

    unsigned char dec_pad[ub64len - N_BLOCK];
    aes_cbc_decrypt(ub64 + N_BLOCK, dec_pad, ub64len / N_BLOCK - 1, ub64, ctx);
    memset(ub64, 0, ub64len);
    free(ub64);

    // Strip PKCS7 padding
    int padlen = dec_pad[ub64len - N_BLOCK - 1];
    if (ub64len - N_BLOCK - padlen <= 0) {
        utils_zero(dec_pad, sizeof(dec_pad));
        return NULL;
    }
    char *dec = malloc(ub64len - N_BLOCK - padlen + 1); // +1 for null termination
    if (!dec) {
        utils_zero(dec_pad, sizeof(dec_pad));
        return NULL;
    }
    memcpy(dec, dec_pad, ub64len - N_BLOCK - padlen);
    dec[ub64len - N_BLOCK - padlen] = '\0';
    *decrypt_len = ub64len - N_BLOCK - padlen + 1;
    utils_zero(dec_pad, sizeof(dec_pad));
    return dec;
}

uint8_t *aes_cbc_decrypt_pad(const unsigned char *in, int inlen, int *decrypt_len,
                          PASSWORD_ID id)
{
    *decrypt_len = 0;

    if (!in || inlen < N_BLOCK) {
        return NULL;
    }

    // Set cipher key
    aes_context ctx[1];
    memset(ctx, 0, sizeof(ctx));
    aes_set_key(memory_report_aeskey(id), 32, ctx);

    uint8_t dec_pad[inlen - N_BLOCK];
    // memcpy IV to kep *in's const-nes
    unsigned char iv[N_BLOCK];
    memcpy(iv, in, N_BLOCK);
    aes_cbc_decrypt(in + N_BLOCK, dec_pad, inlen / N_BLOCK - 1, iv, ctx);

    // Strip PKCS7 padding
    int padlen = dec_pad[inlen - N_BLOCK - 1];
    if (inlen - N_BLOCK - padlen <= 0) {
        utils_zero(dec_pad, sizeof(dec_pad));
        return NULL;
    }
    uint8_t *dec = malloc(inlen - N_BLOCK - padlen);
    if (!dec) {
        utils_zero(dec_pad, sizeof(dec_pad));
        return NULL;
    }
    memcpy(dec, dec_pad, inlen - N_BLOCK - padlen);
    *decrypt_len = inlen - N_BLOCK - padlen;
    utils_zero(dec_pad, sizeof(dec_pad));
    return dec;
}


//
//  Command processing  //
//

static int commander_get_command_idx(const char *cmd_str_check)
{
    int id;
    for (id = 0; id < CMD_NUM; id++) {
        if (strcmp(cmd_str(id), cmd_str_check) == 0) {
            return id;
        }
    }
    return 0;
}

static int commander_get_attr_idx(const char *attr_str_check)
{
    int id;
    for (id = 0; id < ATTR_NUM; id++) {
        if (strcmp(attr_str(id), attr_str_check) == 0) {
            return id;
        }
    }
    return 0;
}

static int commander_get_command(const uint8_t *command)
{
    int id;
    uint16_t cmd = (command[0] << 8) + command[1];
    for (id = 0; id < CMD_NUM; id++) {
        if (cmd == cmd_instr(id)) {
            return id;
        }
    }
    return 0;
}

static const uint8_t *commander_get_attribute(const uint8_t *command, int cmd_len, int cmd, int *len_out)
{
    uint16_t attr_instr = 0, attr_len = 0, c = 2;
    unsigned int i=0, j=0;
    /* loop until we have reachted the end */
    while (c + 4 < cmd_len) {
        attr_instr = ((uint8_t)command[c] << 8) + (uint8_t)command[c + 1];
        attr_len = ((uint8_t)command[c + 2] << 8) + (uint8_t)command[c + 3];
        /* bounds check */
        if (attr_len + c + 4 > cmd_len) {
            return NULL;
        }
        if (cmd_instr(cmd) == attr_instr) {
            /* probably a string attribute */
            if (len_out)
                *len_out = attr_len;
            return command + c + 4;
        }
        /* check if we parse an arguments array */
        if (attr_instr == cmd_instr(CMD_valuearray)) {
            uint16_t sub_attr_instr, sub_attr_len_or_instr;
            c += sizeof(attr_instr) + sizeof(attr_len);
            for (i = 0; i < attr_len; i++) {
                if (c + 4 > cmd_len) {
                    return NULL;
                }
                sub_attr_instr = ((uint8_t)command[c] << 8) + (uint8_t)command[c + 1];
                sub_attr_len_or_instr = ((uint8_t)command[c + 2] << 8) + (uint8_t)command[c + 3];
                /* be strict, only allow hashkeypatharray and pubkeykeypatharray as sub-arrays */
                if (sub_attr_instr == cmd_instr(CMD_hashkeypatharray) || sub_attr_instr == cmd_instr(CMD_pubkeykeypatharray)) {
                    const unsigned char *found_cmd = NULL;
                    int len_start = 0;
                    if (cmd_instr(cmd) == sub_attr_instr) {
                        found_cmd = command + c + 2;
                        len_start = c + 2; //remember the length
                    }
                    c += sizeof(sub_attr_instr) + sizeof(sub_attr_len_or_instr);
                    /* hashkey_path string */
                    for (j = 0; j < sub_attr_len_or_instr; j++) {
                        if (c > cmd_len) {
                            return NULL;
                        }
                        uint16_t hashkeypathlen = ((uint8_t)command[c] << 8) + (uint8_t)command[c + 1];
                        c += hashkeypathlen + sizeof(hashkeypathlen);
                    }
                    if (found_cmd)
                    {
                        if (len_out)
                            *len_out = c - len_start;
                        return found_cmd;
                    }
                }
                else {
                    /* must be a string value */
                    /* ignore the CMD_value sub_attr_instr */
                    if (c > cmd_len) {
                        return NULL;
                    }
                    uint16_t str_attr_len = ((uint8_t)command[c + 4] << 8) + (uint8_t)command[c + 5];
                    /* simple string */
                    if (cmd_instr(cmd) == sub_attr_instr) {
                        if (len_out)
                            *len_out = str_attr_len;
                        return command + c + 6;
                    }
                    c += sizeof(sub_attr_instr) + sizeof(sub_attr_len_or_instr) + sizeof(str_attr_len) + str_attr_len;
                }
            }
        }
        /* jump */
        c += sizeof(attr_instr) + sizeof(attr_len) + attr_len;
    }
    return NULL;
}

static const char *commander_get_str_attribute(const uint8_t *command, int cmd_len, int cmd)
{
    int len_out = 0;
    const uint8_t *str_ptr = commander_get_attribute(command, cmd_len, cmd, &len_out);
    if (!str_ptr ) {
        return NULL;
    }
    // make sure it's null byte terminated
    if (str_ptr[len_out-1] != 0) {
        return NULL;
    }
    return (const char *)str_ptr;
}


//
//  Reporting results  //
//

void commander_clear_report(void)
{
    memset(response_report, 0, COMMANDER_REPORT_SIZE);
    response_report_current_p[0] = 0; /* unencrypted response */
    response_report_current_p = response_report+1;
    REPORT_BUF_OVERFLOW = 0;
}


const char *commander_read_report(void)
{
    return (const char *)response_report;
}

static int commander_report_len(void)
{
    return response_report_current_p-response_report;
}

static int commander_report_fits(int len)
{
    if (commander_report_len()+len+1 >= COMMANDER_REPORT_SIZE)
    {
        /* set buffer overflow error */
        commander_ser_set_err(CMD_error, DBB_ERR_IO_REPORT_BUF, -1);
        return 0;
    }
    return 1;
}

/* append a plain buffer */
void commander_ser_buf(const uint8_t *buf, int len)
{
    if (!commander_report_fits(len))
        return;
    memcpy(response_report_current_p, buf, len);
    response_report_current_p+=len;
}

/* serialize a uint16_t */
void commander_ser_u16(uint16_t c_instr)
{
    if (!commander_report_fits(sizeof(c_instr)))
        return;
    response_report_current_p++[0] = (c_instr & 0xFF00) >> 8;
    response_report_current_p++[0] = (c_instr & 0x00FF);
}

/* serialize a CMD INSTR */
static void commander_ser_cmd(enum CMD_ENUM cmd_index)
{
    /* serialize the command */
    commander_ser_u16(cmd_instr(cmd_index));
}

/* serialize a ATTR INSTR */
static void commander_ser_attr(enum CMD_ATTR_ENUM attr_index)
{
    /* serialize the attribute */
    commander_ser_u16(attr_instr(attr_index));
}


void commander_ser_cmd_attr(enum CMD_ENUM cmd_index, enum CMD_ATTR_ENUM attr_index)
{
    commander_ser_cmd(cmd_index);
    commander_ser_attr(attr_index);
}


void commander_ser_set_err(enum CMD_ENUM cmd_index, int flag, int attempts_left)
{
    commander_clear_report();
    commander_ser_cmd(CMD_error);
    commander_ser_cmd(cmd_index);
    commander_ser_u16(flag_code(flag));
    commander_ser_u16((uint16_t)attempts_left);
}


static void commander_ser_str(const char *str)
{
    if (!str)
        return;
    if (strlen(str)+1 > UINT16_MAX)
        return;
    if (!commander_report_fits(strlen(str)+1+2*sizeof(uint16_t)))
        return;
    /* serialize the string command */
    commander_ser_cmd(CMD_value_str);
    /* serialize the length + nullbyte */
    commander_ser_u16((uint16_t)strlen(str)+1);
    memcpy(response_report_current_p, str, strlen(str));
    response_report_current_p+=strlen(str);
    response_report_current_p++[0] = 0; // plus nullbyte termination
}

static void commander_ser_attr_str(enum CMD_ATTR_ENUM attr_index, const char *str)
{
    if (!str)
        return;
    if (strlen(str)+1 > UINT16_MAX)
        return;
    if (!commander_report_fits(strlen(str)+1+2*sizeof(uint16_t)))
        return;
    commander_ser_attr(attr_index);
    commander_ser_cmd(CMD_value_str);
    /* serialize the length + nullbyte */
    commander_ser_u16((uint16_t)strlen(str)+1);
    memcpy(response_report_current_p, str, strlen(str));
    response_report_current_p+=strlen(str);
    response_report_current_p++[0] = 0; // plus nullbyte termination
}


static void commander_ser_attr_bool(enum CMD_ATTR_ENUM attr_index, int state)
{
    if (state < 0 || state > 1)
        return;
    if (!commander_report_fits(1+sizeof(uint16_t)))
        return;
    commander_ser_attr(attr_index);
    commander_ser_cmd(CMD_value_bool);
    commander_ser_buf((const uint8_t *)&state, 1);
}

void commander_fill_report(const char *cmd, const char *msg, int flag)
{
    if (flag > DBB_FLAG_ERROR_START) {
        /* convert back to instr, keep commander_fill_report const char * parameter for legacy reasons */
        commander_ser_set_err(commander_get_command_idx(cmd), flag, -1);
    }
    else {
        commander_ser_cmd(commander_get_command_idx(cmd));
        commander_ser_str(msg);
        //commander_ser_attr(commander_get_attr_idx(msg));
    }
//    if (!strlens(response_report)) {
//        strncat(response_report, "{", 1);
//    } else {
//        response_report[strlens(response_report) - 1] = ','; // replace closing '}' with continuing ','
//    }

//    if (flag > DBB_FLAG_ERROR_START) {
//        if (strlens(msg)) {
//            snprintf(p + strlens(response_report), COMMANDER_REPORT_SIZE - strlens(response_report),
//                     " \"%s\":{\"message\":\"%s\", \"code\":%s, \"command\":\"%s\"}",
//                     attr_str(ATTR_error), msg, flag_code(flag), cmd);
//        } else {
//            snprintf(p + strlens(response_report), COMMANDER_REPORT_SIZE - strlens(response_report),
//                     " \"%s\":{\"message\":\"%s\", \"code\":%s, \"command\":\"%s\"}",
//                     attr_str(ATTR_error), flag_msg(flag), flag_code(flag), cmd);
//        }
//    } else if (flag == DBB_JSON_BOOL || flag == DBB_JSON_ARRAY || flag == DBB_JSON_NUMBER) {
//        snprintf(p + strlens(response_report), COMMANDER_REPORT_SIZE - strlens(response_report),
//                 " \"%s\": %s", cmd, msg);
//    } else {
//        snprintf(p + strlens(response_report), COMMANDER_REPORT_SIZE - strlens(response_report),
//                 " \"%s\": \"%s\"", cmd, msg);
//    }

//    if ((strlens(response_report) + 1) >= COMMANDER_REPORT_SIZE) {
//        if (!REPORT_BUF_OVERFLOW) {
//            commander_clear_report();
//            snprintf(response_report, COMMANDER_REPORT_SIZE,
//                     "{\"%s\":{\"message\":\"%s\", \"code\":%s, \"command\":\"%s\"}}", attr_str(ATTR_error),
//                     flag_msg(DBB_ERR_IO_REPORT_BUF), flag_code(DBB_ERR_IO_REPORT_BUF), cmd);
//            REPORT_BUF_OVERFLOW = 1;
//        }
//    } else {
//        strcat(response_report, "}");
//    }
}


void commander_force_reset(void)
{
    memory_erase();
    commander_clear_report();
    commander_fill_report(cmd_str(CMD_reset), NULL, DBB_ERR_IO_RESET);
}


static void commander_process_reset(const uint8_t *command, int cmd_len)
{
    const char *value = commander_get_str_attribute(command, cmd_len, CMD_value);
    if (!strlens(value)) {
        commander_fill_report(cmd_str(CMD_reset), NULL, DBB_ERR_IO_INVALID_CMD);
        return;
    }

    if (strncmp(value, attr_str(ATTR___ERASE__), strlens(attr_str(ATTR___ERASE__)))) {
        commander_fill_report(cmd_str(CMD_reset), NULL, DBB_ERR_IO_INVALID_CMD);
        return;
    }

    memory_erase();
    commander_clear_report();
    commander_ser_cmd_attr(CMD_reset, ATTR_success);
}


static void commander_process_name(const uint8_t *command, int cmd_len)
{
    const char *value = commander_get_str_attribute(command, cmd_len, CMD_value);
    commander_ser_cmd(CMD_name);
    commander_ser_str((char *)memory_name(value));
}


static int commander_process_aes_key(const char *message, int msg_len, PASSWORD_ID id)
{
    return (memory_write_aeskey(message, msg_len, id));
}


static int commander_process_backup_check(const char *key, const char *filename)
{
    int ret;
    HDNode node;
    uint8_t backup[MEM_PAGE_LEN];
    char *backup_hex = sd_load(filename, CMD_backup);

    if (strlens(backup_hex)) {

        if (strlens(backup_hex) < MEM_PAGE_LEN * 2) {
            commander_ser_set_err(CMD_backup, DBB_ERR_SD_NO_MATCH, -1);
            ret = DBB_ERROR;
        }

        memcpy(backup, utils_hex_to_uint8(backup_hex), sizeof(backup));

        if (!memcmp(backup, MEM_PAGE_ERASE, MEM_PAGE_LEN)) {
            commander_ser_set_err(CMD_backup, DBB_ERR_SD_NO_MATCH, -1);
            ret = DBB_ERROR;
        } else if (memcmp(backup, memory_master_entropy(NULL), MEM_PAGE_LEN)) {
            commander_ser_set_err(CMD_backup, DBB_ERR_SD_NO_MATCH, -1);
            ret = DBB_ERROR;
        } else {
            // entropy matches, check if derived master and chaincodes match
            char seed[MEM_PAGE_LEN * 2 + 1];
            snprintf(seed, sizeof(seed), "%s", utils_uint8_to_hex(backup, MEM_PAGE_LEN));
            if (wallet_generate_node(key, seed, &node) == DBB_ERROR) {
                commander_ser_set_err(CMD_backup, DBB_ERR_SD_NO_MATCH, -1);
                ret = DBB_ERROR;
            } else if (memcmp(node.private_key, wallet_get_master(), MEM_PAGE_LEN) ||
                       memcmp(node.chain_code, wallet_get_chaincode(), MEM_PAGE_LEN)) {
                commander_ser_set_err(CMD_backup, DBB_ERR_SD_NO_MATCH, -1);
                ret = DBB_ERROR;
            } else {
                commander_ser_cmd(CMD_backup);
                commander_ser_str(attr_str(ATTR_success));
                ret = DBB_OK;
            }
        }
        utils_zero(backup_hex, strlens(backup_hex));
        utils_zero(backup, sizeof(backup));
        utils_zero(&node, sizeof(HDNode));
    } else {
        /* error reported in sd_load() */
        ret = DBB_ERROR;
    }

    return ret;
}


static int commander_process_backup_create(const char *key, const char *filename)
{
    int ret;
    uint8_t backup[MEM_PAGE_LEN];
    char backup_hex[MEM_PAGE_LEN * 2 + 1];
    char *name = (char *)memory_name("");

    memcpy(backup, memory_master_entropy(NULL), MEM_PAGE_LEN);

    if (!memcmp(backup, MEM_PAGE_ERASE, MEM_PAGE_LEN)) {
        commander_ser_set_err(CMD_backup, DBB_ERR_KEY_MASTER, -1);
        return DBB_ERROR;
    }

    snprintf(backup_hex, sizeof(backup_hex), "%s", utils_uint8_to_hex(backup,
             sizeof(backup)));

    ret = sd_write(filename, backup_hex, name, DBB_SD_NO_REPLACE, CMD_backup);

    utils_zero(backup, sizeof(backup));
    utils_zero(backup_hex, sizeof(backup_hex));

    if (ret != DBB_OK) {
        /* error reported in sd_write() */
        return ret;
    }

    return commander_process_backup_check(key, filename);
}


static void commander_process_backup(const uint8_t *command, int cmd_len)
{
    const char *filename, *key, *check, *erase, *value;

    if (wallet_is_locked()) {
        commander_ser_set_err(CMD_backup, DBB_ERR_IO_LOCKED, -1);
        return;
    }

    value = commander_get_str_attribute(command, cmd_len, CMD_value);
    if (value) {
        if (strcmp(value, attr_str(ATTR_list)) == 0) {
            sd_list(CMD_backup);
            return;
        }

        if (strcmp(value, attr_str(ATTR_erase)) == 0) {
            sd_erase(CMD_backup, NULL);
            return;
        }
    }

    erase = commander_get_str_attribute(command, cmd_len, CMD_erase);
    if (erase) {
        sd_erase(CMD_backup, erase);
        return;
    }

    key = commander_get_str_attribute(command, cmd_len, CMD_key);
    if (key) {
        check = commander_get_str_attribute(command, cmd_len, CMD_check);
        if (check) {
            commander_process_backup_check(key, check);
            return;
        }

        filename = commander_get_str_attribute(command, cmd_len, CMD_filename);
        if (filename) {
            commander_process_backup_create(key, filename);
            return;
        }
    } else {
        commander_ser_set_err(CMD_seed, DBB_ERR_SD_KEY, -1);
        return;
    }

    commander_ser_set_err(CMD_seed, DBB_ERR_IO_INVALID_CMD, -1);
}


static void commander_process_seed(const uint8_t *command, int cmd_len)
{
    int ret;
    const char *key, *raw, *source, *entropy, *filename;
    key = commander_get_str_attribute(command, cmd_len, CMD_key);
    raw = commander_get_str_attribute(command, cmd_len, CMD_raw);
    source = commander_get_str_attribute(command, cmd_len, CMD_source);
    entropy = commander_get_str_attribute(command, cmd_len, CMD_entropy);
    filename = commander_get_str_attribute(command, cmd_len, CMD_filename);

    if (wallet_is_locked()) {
        commander_ser_set_err(CMD_seed, DBB_ERR_IO_LOCKED, -1);
        return;
    }

    if (!strlens(source) || !strlens(filename)) {
        commander_ser_set_err(CMD_seed, DBB_ERR_IO_INVALID_CMD, -1);
        return;
    }

    if (!strlens(key)) {
        commander_ser_set_err(CMD_seed, DBB_ERR_SD_KEY, -1);
        return;
    }

    if (sd_card_inserted() != DBB_OK) {
        commander_ser_set_err(CMD_seed, DBB_ERR_SEED_SD, -1);
        return;
    }

    if (utils_limit_alphanumeric_hyphen_underscore_period(filename) != DBB_OK) {
        commander_ser_set_err(CMD_seed, DBB_ERR_SD_BAD_CHAR, -1);
        return;
    }

    if (strcmp(source, attr_str(ATTR_create)) == 0) {
        // Generate a new wallet, optionally with entropy entered via USB
        uint8_t i, add_entropy, number[MEM_PAGE_LEN], entropy_b[MEM_PAGE_LEN];
        char entropy_c[MEM_PAGE_LEN * 2 + 1];

        memset(entropy_b, 0, sizeof(entropy_b));

        if (sd_file_exists(filename) == DBB_OK) {
            commander_ser_set_err(CMD_seed, DBB_ERR_SD_OPEN_FILE, -1);
            return;
        }

        if (random_bytes(number, sizeof(number), 1) == DBB_ERROR) {
            commander_ser_set_err(CMD_seed, DBB_ERR_MEM_ATAES, -1);
            return;
        }

        if (strlens(entropy)) {
            if (strlens(entropy) == MEM_PAGE_LEN * 2 && utils_is_hex(entropy)) {
                // Allows recover from a Digital Bitbox backup text entered via USB
                memcpy(entropy_b, utils_hex_to_uint8(entropy), sizeof(entropy_b));
            }
            sha256_Raw((const uint8_t *)entropy, strlens(entropy), entropy_b);
        }

        // add extra entropy from device unless raw is set
        add_entropy = 1;
        if (strlens(entropy) && strlens(raw)) {
            if (!strcmp(raw, attr_str(ATTR_true))) {
                add_entropy = 0;
            }
        }

        if (add_entropy) {
            for (i = 0; i < MEM_PAGE_LEN; i++) {
                entropy_b[i] ^= number[i];
            }
        }

        snprintf(entropy_c, sizeof(entropy_c), "%s", utils_uint8_to_hex(entropy_b,
                 sizeof(entropy_b)));
        ret = wallet_generate_master(key, entropy_c);
        if (ret == DBB_OK) {
            if (commander_process_backup_create(key, filename) != DBB_OK) {
                memory_erase_seed();
                return;
            }
        }

        utils_zero(entropy_b, sizeof(entropy_b));
        utils_zero(entropy_c, sizeof(entropy_c));
    } else if (strcmp(source, attr_str(ATTR_backup)) == 0) {
        char entropy_c[MEM_PAGE_LEN * 2 + 1];
        char *backup_hex = sd_load(filename, CMD_seed);
        char *name = strchr(backup_hex, BACKUP_DELIM);

        if (strlens(backup_hex) < MEM_PAGE_LEN * 2) {
            ret = DBB_ERROR;
        } else if (strlens(name) ? (name != MEM_PAGE_LEN * 2 + backup_hex) : 0) {
            ret = DBB_ERROR;
        } else if (!strlens(name) ? (strlens(backup_hex) != MEM_PAGE_LEN * 2) : 0) {
            ret = DBB_ERROR;
        } else {
            if (strlens(name) > 1) {
                memory_name(name + 1);
            }

            snprintf(entropy_c, sizeof(entropy_c), "%s", backup_hex);
            ret = wallet_generate_master(key, entropy_c);
        }

        utils_zero(backup_hex, strlens(backup_hex));
        utils_zero(entropy_c, sizeof(entropy_c));
    } else {
        commander_ser_set_err(CMD_seed, DBB_ERR_IO_INVALID_CMD, -1);
        return;
    }

    if (ret == DBB_ERROR) {
        commander_ser_set_err(CMD_seed, DBB_ERR_SEED_INVALID, -1);
    } else if (ret == DBB_ERROR_MEM) {
        commander_ser_set_err(CMD_seed, DBB_ERR_MEM_ATAES, -1);
    } else if (ret == DBB_OK) {
        commander_clear_report();
        commander_ser_cmd_attr(CMD_seed, ATTR_success);
    } else {
        commander_ser_set_err(CMD_seed, DBB_ERR_SEED_INVALID, -1);
    }
}


static int commander_process_sign(const uint8_t *command, int cmd_len)
{
    int ret = DBB_ERROR, i = 0;
    uint16_t arr_len = 0, ele_len = 0, c = 0;
    uint8_t hash[32];
    char keypath[256];

    int hashkeypath_len;
    const uint8_t *hashkeypath = commander_get_attribute(command, cmd_len, CMD_hashkeypatharray, &hashkeypath_len);

    if (!hashkeypath || hashkeypath_len < 2 || cmd_len < 4) {
        commander_ser_set_err(CMD_sign, DBB_ERR_IO_INVALID_CMD, -1);
        return DBB_ERROR;
    }
    commander_ser_cmd(CMD_sign);
    commander_ser_cmd(CMD_sigpubkeyarray);
    arr_len = (hashkeypath[c] << 8) + hashkeypath[c + 1];
    int arr_len_comparable = (int)arr_len;
    if (arr_len_comparable > COMMANDER_ARRAY_MAX) {
        commander_ser_set_err(CMD_sign, DBB_ERR_IO_INVALID_CMD, -1);
        return DBB_ERROR;
    }
    commander_ser_u16(arr_len);
    for (i = 0; i < arr_len; i++) {
        /* bounds check */
        if (hashkeypath_len < c+2+(int)sizeof(hash)) {
            goto sign_deser_error;
        }
        ele_len = (hashkeypath[c + 2] << 8) + hashkeypath[c + 3];
        memset(hash, 0, sizeof(hash));
        memset(keypath, 0, sizeof(keypath));
        memcpy(hash, hashkeypath + c + 4, sizeof(hash));
        memcpy(keypath, hashkeypath + c + 4 + sizeof(hash), MIN( sizeof(keypath), (ele_len - sizeof(hash)) ));

        if (!strlens(keypath) || (ele_len - sizeof(hash)) > sizeof(keypath) ) {
            goto sign_deser_error;
        }

        uint8_t sig[64];
        uint8_t pub_key[33];
        ret = wallet_sign(hash, keypath, sig, pub_key);
        if (ret != DBB_OK) {
            return ret;
        };
        commander_ser_buf(sig, sizeof(sig));
        commander_ser_buf(pub_key, sizeof(pub_key));

        c += sizeof(ele_len) + ele_len;
    }
    return ret;

sign_deser_error:
    commander_ser_set_err(CMD_sign, DBB_ERR_SIGN_DESERIAL, -1);
    return DBB_ERROR;
}


static void commander_process_random(const uint8_t *command, int cmd_len)
{
    int update_seed;
    uint8_t number[16];

    int encrypt_len;
    char *encoded_report;
    char echo_number[32 + 13 + 1];

    const char *value = commander_get_str_attribute(command, cmd_len, CMD_value);
    if (!strlens(value)) {
        commander_ser_set_err(CMD_random, DBB_ERR_IO_INVALID_CMD, -1);
        return;
    }

    if (strcmp(value, attr_str(ATTR_true)) == 0) {
        update_seed = 1;
    } else if (strcmp(value, attr_str(ATTR_pseudo)) == 0) {
        update_seed = 0;
    } else {
        commander_ser_set_err(CMD_random, DBB_ERR_IO_INVALID_CMD, -1);
        return;
    }

    if (random_bytes(number, sizeof(number), update_seed) == DBB_ERROR) {
        commander_ser_set_err(CMD_random, DBB_ERR_MEM_ATAES, -1);
        return;
    }

    commander_ser_cmd(CMD_random);
    commander_ser_str(utils_uint8_to_hex(number, sizeof(number)));

    snprintf(echo_number, sizeof(echo_number), "{\"random\":\"%s\"}",
             utils_uint8_to_hex(number, sizeof(number)));
    encoded_report = aes_cbc_b64_encrypt((unsigned char *)echo_number,
                                         strlens(echo_number),
                                         &encrypt_len,
                                         PASSWORD_VERIFY);
    if (encoded_report) {
        commander_ser_cmd(CMD_echo);
        commander_ser_str(encoded_report);
        free(encoded_report);
    } else {
        commander_ser_set_err(CMD_random, DBB_ERR_MEM_ENCRYPT, -1);
    }
}


static int commander_process_ecdh(int cmd, const uint8_t *pair_pubkey,
                                  uint8_t *out_pubkey)
{
    uint8_t rand_privkey[32], ecdh_secret[32], rand_led, ret, i = 0;

    if (random_bytes(rand_privkey, sizeof(rand_privkey), 0) == DBB_ERROR) {
        commander_ser_set_err(cmd, DBB_ERR_MEM_ATAES, -1);
        return DBB_ERROR;
    }

    if (ecc_ecdh(pair_pubkey, rand_privkey, ecdh_secret)) {
        commander_ser_set_err(cmd, DBB_ERR_KEY_ECDH, -1);
        return DBB_ERROR;
    }

    // Use a 'second channel' LED blink code to avoid MITM
    do {
        if (random_bytes(&rand_led, sizeof(rand_led), 0) == DBB_ERROR) {
            commander_ser_set_err(cmd, DBB_ERR_MEM_ATAES, -1);
            return DBB_ERROR;
        }

        rand_led %= LED_MAX_CODE_BLINKS;
        rand_led++; // min 1 blink
        led_code(&rand_led, sizeof(rand_led));

        // Xor ECDH secret
        ecdh_secret[i % sizeof(ecdh_secret)] ^= rand_led;
        i++;
    } while (touch_button_press(DBB_TOUCH_REJECT_TIMEOUT) == DBB_ERR_TOUCH_TIMEOUT);

    if (i == 0) {
        // While loop not entered
        commander_ser_set_err(CMD_touchbutton, DBB_ERR_TOUCH_ABORT, -1);
        return DBB_ERROR;
    }

    // Save to eeprom
    ret = commander_process_aes_key(utils_uint8_to_hex(ecdh_secret, 32), 64,
                                    PASSWORD_VERIFY);
    if (ret != DBB_OK) {
        commander_fill_report(cmd_str(cmd), NULL, ret);
        return ret;
    }

    ecc_get_public_key33(rand_privkey, out_pubkey);
    utils_zero(rand_privkey, sizeof(rand_privkey));
    utils_zero(ecdh_secret, sizeof(ecdh_secret));
    utils_clear_buffers();
    return DBB_OK;
}


static void commander_process_verifypass(const uint8_t *command, int cmd_len)
{
    uint8_t number[32] = {0};
    char *l, text[64 + 1];
    const char *value, *pair_pubkey;

    value = commander_get_str_attribute(command, cmd_len, CMD_value);
    pair_pubkey = commander_get_str_attribute(command, cmd_len, CMD_ecdh);

    if (wallet_is_locked()) {
        commander_ser_set_err(CMD_verifypass, DBB_ERR_IO_LOCKED, -1);
        return;
    }

    if (strlens(value)) {
        if (strcmp(value, attr_str(ATTR_export)) == 0) {
            memcpy(text, utils_uint8_to_hex(memory_report_aeskey(PASSWORD_VERIFY), 32), 64 + 1);
            utils_clear_buffers();
            int ret = sd_write(VERIFYPASS_FILENAME, text, NULL,
                               DBB_SD_REPLACE, CMD_verifypass);

            if (ret == DBB_OK) {
                l = sd_load(VERIFYPASS_FILENAME, CMD_verifypass);
                if (l) {
                    if (memcmp(text, l, strlens(text))) {
                        commander_ser_set_err(CMD_verifypass, DBB_ERR_SD_CORRUPT_FILE, -1);
                    } else {
                        commander_ser_cmd_attr(CMD_verifypass, ATTR_success);
                    }
                    utils_zero(l, strlens(l));
                }
            }
            utils_zero(text, sizeof(text));
            return;
        }
    }

    if (strlens(value)) {
        if (strcmp(value, attr_str(ATTR_create)) == 0) {
            int status = touch_button_press(DBB_TOUCH_LONG);
            if (status != DBB_TOUCHED) {
                commander_fill_report(cmd_str(CMD_verifypass), NULL, status);
                return;
            }

            if (random_bytes(number, sizeof(number), 1) == DBB_ERROR) {
                commander_ser_set_err(CMD_verifypass, DBB_ERR_MEM_ATAES, -1);
                return;
            }
            status = commander_process_aes_key(utils_uint8_to_hex(number, sizeof(number)),
                                               sizeof(number) * 2, PASSWORD_VERIFY);
            if (status != DBB_OK) {
                commander_fill_report(cmd_str(CMD_verifypass), NULL, status);
                return;
            }
            commander_ser_cmd_attr(CMD_verifypass, ATTR_success);
            return;
        }
    }

    if (strlens(pair_pubkey)) {
        if (strlens(pair_pubkey) != 66) {
            commander_ser_set_err(CMD_verifypass, DBB_ERR_KEY_ECDH_LEN, -1);
            return;
        }

        uint8_t out_pubkey[33];
        if (commander_process_ecdh(CMD_verifypass, utils_hex_to_uint8(pair_pubkey),
                                   out_pubkey) == DBB_OK) {
            char msg[256];
            int encrypt_len;
            char *enc = aes_cbc_b64_encrypt((const unsigned char *)VERIFYPASS_CRYPT_TEST,
                                            strlens(VERIFYPASS_CRYPT_TEST),
                                            &encrypt_len,
                                            PASSWORD_VERIFY);
            if (enc) {
                snprintf(msg, sizeof(msg), "{\"%s\":\"%s\", \"%s\":\"%s\"}",
                         cmd_str(CMD_ecdh), utils_uint8_to_hex(out_pubkey, sizeof(out_pubkey)),
                         cmd_str(CMD_ciphertext), enc);
                commander_fill_report(cmd_str(CMD_verifypass), msg, DBB_JSON_ARRAY);
                free(enc);
            } else {
                commander_ser_set_err(CMD_ecdh, DBB_ERR_MEM_ENCRYPT, -1);
            }
        }
        return;
    }

    commander_fill_report(cmd_str(CMD_verifypass), NULL, DBB_ERR_IO_INVALID_CMD);
}


static void commander_process_xpub(const uint8_t *command, int cmd_len)
{
    char xpub[112] = {0};
    const char *value = commander_get_str_attribute(command, cmd_len, CMD_value);
    if (!strlens(value)) {
        commander_ser_set_err(CMD_xpub, DBB_ERR_IO_INVALID_CMD, -1);
        return;
    }

    wallet_report_xpub(value, xpub);

    if (xpub[0]) {
        commander_ser_cmd(CMD_xpub);
        commander_ser_str(xpub);

        int encrypt_len;
        char *encoded_report;
        encoded_report = aes_cbc_b64_encrypt((unsigned char *)xpub,
                                             strlens(xpub),
                                             &encrypt_len,
                                             PASSWORD_VERIFY);
        if (encoded_report) {
            commander_ser_cmd(CMD_echo);
            commander_ser_str(encoded_report);
            free(encoded_report);
        } else {
            commander_ser_set_err(CMD_xpub, DBB_ERR_MEM_ENCRYPT, -1);
        }
    } else {
        commander_ser_set_err(CMD_xpub, DBB_ERR_KEY_CHILD, -1);
    }
}


static uint8_t commander_bootloader_unlocked(void)
{
#ifdef TESTING
    return 0;
#else
    uint8_t sig[FLASH_SIG_LEN];
    memcpy(sig, (uint8_t *)(FLASH_SIG_START), FLASH_SIG_LEN);
    return sig[FLASH_BOOT_LOCK_BYTE];
#endif
}


static void commander_process_device(const uint8_t *command, int cmd_len)
{
    const char *value = commander_get_str_attribute(command, cmd_len, CMD_value);
    if (!strlens(value)) {
        commander_ser_set_err(CMD_device, DBB_ERR_IO_INVALID_CMD, -1);
        return;
    }

    if (strcmp(value, attr_str(ATTR_lock)) == 0) {
        if (wallet_seeded() == DBB_OK) {
            int status = touch_button_press(DBB_TOUCH_LONG);
            if (status == DBB_TOUCHED) {
                char msg[256];
                memory_write_unlocked(0);
                snprintf(msg, sizeof(msg), "{\"%s\":%s}", attr_str(ATTR_lock), attr_str(ATTR_true));
                commander_ser_cmd(CMD_device);
                commander_ser_str(msg);
            } else {
                commander_fill_report(cmd_str(CMD_device), NULL, status);
            }
        } else {
            commander_ser_set_err(CMD_device, DBB_ERR_KEY_MASTER, -1);
        }
        return;
    }

    if (!strcmp(value, attr_str(ATTR_info))) {
        char id[65] = {0};
        uint8_t lock = 0;
        uint8_t seeded = 0;
        uint8_t sdcard = 0;
        uint8_t bootlock = 0;
        uint32_t serial[4] = {0};

        flash_read_unique_id(serial, 4);

        lock = wallet_is_locked();
        if (wallet_seeded() == DBB_OK) {
            seeded = 1;
            wallet_report_id(id);
        }
        bootlock = commander_bootloader_unlocked();
        sdcard= (sd_card_inserted() == DBB_OK);

        int tfa_len;
        char *tfa = aes_cbc_b64_encrypt((const unsigned char *)VERIFYPASS_CRYPT_TEST,
                                        strlens(VERIFYPASS_CRYPT_TEST),
                                        &tfa_len,
                                        PASSWORD_VERIFY);
        if (!tfa) {
            commander_ser_set_err(CMD_device, DBB_ERR_MEM_ENCRYPT, -1);
            return;
        }

        commander_clear_report();
        commander_ser_cmd(CMD_device);
        commander_ser_cmd(CMD_valuearray);
        commander_ser_u16(9);
        commander_ser_attr_str(ATTR_serial, utils_uint8_to_hex((uint8_t *)serial, sizeof(serial)));
        commander_ser_attr_str(ATTR_version, DIGITAL_BITBOX_VERSION);
        commander_ser_attr_str(ATTR_name, (char *)memory_name(""));
        commander_ser_attr_str(ATTR_id, id);
        commander_ser_attr_bool(ATTR_seeded, seeded);
        commander_ser_attr_bool(ATTR_lock, lock);
        commander_ser_attr_bool(ATTR_bootlock, bootlock);
        commander_ser_attr_bool(ATTR_sdcard, sdcard);
        commander_ser_attr_str(ATTR_TFA, tfa);
        free(tfa);
        return;
    }

    commander_ser_set_err(CMD_device, DBB_ERR_IO_INVALID_CMD, -1);
}


static void commander_process_aes256cbc(const uint8_t *command, int cmd_len)
{
    const char *type, *data;
    char *crypt;
    int crypt_len;
    PASSWORD_ID id;

    type = commander_get_str_attribute(command, cmd_len, CMD_type);
    data = commander_get_str_attribute(command, cmd_len, CMD_data);

    if (!type || !data) {
        commander_ser_set_err(CMD_aes256cbc, DBB_ERR_IO_INVALID_CMD, -1);
        return;
    }

    if (strncmp(type, attr_str(ATTR_password), strlens(attr_str(ATTR_password))) == 0) {
        int ret = commander_process_aes_key(data, strlens(data), PASSWORD_CRYPT);
        if (ret == DBB_OK) {
            commander_ser_cmd_attr(CMD_aes256cbc, ATTR_success);
        } else {
            commander_fill_report(cmd_str(CMD_aes256cbc), NULL, ret);
        }
        return;
    }

    if (strncmp(type, attr_str(ATTR_xpub), strlens(attr_str(ATTR_xpub))) == 0) {
        char xpub[112] = {0};
        wallet_report_xpub(data, xpub);
        if (xpub[0]) {
            int ret = commander_process_aes_key(xpub, 112, PASSWORD_CRYPT);
            if (ret == DBB_OK) {
                commander_ser_cmd_attr(CMD_aes256cbc, ATTR_success);
            } else {
                commander_fill_report(cmd_str(CMD_aes256cbc), NULL, ret);
            }
        } else {
            commander_ser_set_err(CMD_aes256cbc, DBB_ERR_KEY_MASTER, -1);
        }
        return;
    }

    if (strncmp(type, attr_str(ATTR_verify), strlens(attr_str(ATTR_verify))) == 0) {
        id = PASSWORD_VERIFY;
    } else if (memory_aeskey_is_erased(PASSWORD_CRYPT) == DBB_MEM_ERASED) {
        commander_ser_set_err(CMD_aes256cbc, DBB_ERR_IO_NO_PASSWORD, -1);
        return;
    } else {
        id = PASSWORD_CRYPT;
    }

    if (strncmp(type, attr_str(ATTR_encrypt), strlens(attr_str(ATTR_encrypt))) == 0 ||
            strncmp(type, attr_str(ATTR_verify), strlens(attr_str(ATTR_verify))) == 0) {
        if (strlens(data) > AES_DATA_LEN_MAX) {
            commander_ser_set_err(CMD_aes256cbc, DBB_ERR_IO_DATA_LEN, -1);
        } else {
            crypt = aes_cbc_b64_encrypt((const unsigned char *)data, strlens(data), &crypt_len, id);
            if (crypt) {
                commander_ser_cmd(CMD_aes256cbc);
                commander_ser_str(crypt);
            } else {
                commander_ser_set_err(CMD_aes256cbc, DBB_ERR_MEM_ENCRYPT, -1);
            }
            free(crypt);
        }
        return;
    }

    if (strncmp(type, attr_str(ATTR_decrypt), strlens(attr_str(ATTR_decrypt))) == 0) {
        crypt = aes_cbc_b64_decrypt((const unsigned char *)data, strlens(data), &crypt_len, id);
        if (crypt) {
            commander_ser_cmd(CMD_aes256cbc);
            commander_ser_str(crypt);
        } else {
            commander_ser_set_err(CMD_aes256cbc, DBB_ERR_IO_DECRYPT, -1);
        }
        free(crypt);
        return;
    }
    commander_ser_set_err(CMD_aes256cbc, DBB_ERR_IO_INVALID_CMD, -1);
}


static void commander_process_led(const uint8_t *command, int cmd_len)
{
    const char *value = commander_get_str_attribute(command, cmd_len, CMD_value);
    if (!strlens(value)) {
        commander_ser_set_err(CMD_led, DBB_ERR_IO_INVALID_CMD, -1);
        return;
    }
    if (!strncmp(value, attr_str(ATTR_blink), strlens(attr_str(ATTR_blink)))) {
        led_blink();
        commander_ser_cmd_attr(CMD_led, ATTR_success);
    } else if (!strncmp(value, attr_str(ATTR_abort), strlens(attr_str(ATTR_abort)))) {
        led_abort();
        commander_ser_cmd_attr(CMD_led, ATTR_success);
    } else {
        commander_ser_set_err(CMD_led, DBB_ERR_IO_INVALID_CMD, -1);
    }
}


static void commander_process_bootloader(const uint8_t *command, int cmd_len)
{
    const char *value = commander_get_str_attribute(command, cmd_len, CMD_value);
    if (!strlens(value)) {
        commander_ser_set_err(CMD_bootloader, DBB_ERR_IO_INVALID_CMD, -1);
        return;
    }

#ifdef TESTING
    commander_fill_report(cmd_str(CMD_bootloader), flag_msg(DBB_WARN_NO_MCU), DBB_OK);
#else
    uint8_t sig[FLASH_SIG_LEN];
    memcpy(sig, (uint8_t *)(FLASH_SIG_START), FLASH_SIG_LEN);

    if (!strncmp(value, attr_str(ATTR_lock), strlens(attr_str(ATTR_lock)))) {
        sig[FLASH_BOOT_LOCK_BYTE] = 0;
    } else if (!strncmp(value, attr_str(ATTR_unlock), strlens(attr_str(ATTR_unlock)))) {
        sig[FLASH_BOOT_LOCK_BYTE] = 0xFF;
    } else {
        commander_ser_set_err(CMD_bootloader, DBB_ERR_IO_INVALID_CMD, -1);
        return;
    }

    if (flash_erase_page(FLASH_SIG_START, IFLASH_ERASE_PAGES_8) != FLASH_RC_OK) {
        goto err;
    }

    if (flash_write(FLASH_SIG_START, sig, FLASH_SIG_LEN, 0) != FLASH_RC_OK) {
        goto err;
    }

    commander_ser_cmd(CMD_bootloader);
    commander_ser_str(value);
    return;

err:
    commander_fill_report(cmd_str(CMD_bootloader), NULL, DBB_ERR_MEM_FLASH);
#endif
}


static void commander_process_password(const uint8_t *command, int cmd_len, PASSWORD_ID id)
{
    int ret;
    const char *value = commander_get_str_attribute(command, cmd_len, CMD_value);

    if (wallet_is_locked() && id == PASSWORD_HIDDEN) {
        commander_ser_set_err(CMD_password, DBB_ERR_IO_LOCKED, -1);
        return;
    }

    if (wallet_is_hidden() && id == PASSWORD_STAND) {
        id = PASSWORD_HIDDEN;
    }

    ret = commander_process_aes_key(value, strlens(value), id);

    if (!memcmp(memory_report_aeskey(PASSWORD_STAND), memory_report_aeskey(PASSWORD_HIDDEN),
                MEM_PAGE_LEN)) {
        memory_erase_hidden_password();
        commander_ser_set_err(CMD_password, DBB_ERR_IO_PW_COLLIDE, -1);
        return;
    }

    if (ret != DBB_OK) {
        commander_fill_report(cmd_str(CMD_password), NULL, ret);
        return;
    }

    commander_ser_cmd_attr(CMD_password, ATTR_success);
    commander_ser_str(value);
}


static int commander_process(int cmd, const uint8_t *command, int cmd_len)
{
    switch (cmd) {
        case CMD_reset:
            commander_process_reset(command, cmd_len);
            return DBB_RESET;

        case CMD_hidden_password:
            commander_process_password(command, cmd_len, PASSWORD_HIDDEN);
            break;

        case CMD_password:
            commander_process_password(command, cmd_len, PASSWORD_STAND);
            break;

        case CMD_verifypass:
            commander_process_verifypass(command, cmd_len);
            break;

        case CMD_led:
            commander_process_led(command, cmd_len);
            break;

        case CMD_name:
            commander_process_name(command, cmd_len);
            break;

        case CMD_seed:
            commander_process_seed(command, cmd_len);
            break;

        case CMD_backup:
            commander_process_backup(command, cmd_len);
            break;

        case CMD_random:
            commander_process_random(command, cmd_len);
            break;

        case CMD_xpub:
            commander_process_xpub(command, cmd_len);
            break;

        case CMD_device:
            commander_process_device(command, cmd_len);
            break;

        case CMD_aes256cbc:
            commander_process_aes256cbc(command, cmd_len);
            break;

        case CMD_bootloader:
            commander_process_bootloader(command, cmd_len);
            break;

        default: {
            /* never reached */
        }
    }
    return DBB_OK;
}


//
//  Handle API input (preprocessing) //
//

static int commander_tfa_append_pin(void)
{
    if (wallet_is_locked()) {
        // Create one-time PIN
        uint8_t pin_b[VERIFYPASS_LOCK_CODE_LEN];
        memset(TFA_PIN, 0, sizeof(TFA_PIN));
        if (random_bytes(pin_b, VERIFYPASS_LOCK_CODE_LEN, 0) == DBB_ERROR) {
            commander_ser_set_err(CMD_random, DBB_ERR_MEM_ATAES, -1);
            return DBB_ERROR;
        }

#ifdef TESTING
        snprintf(TFA_PIN, sizeof(TFA_PIN), "0001");
#else
        snprintf(TFA_PIN, sizeof(TFA_PIN), "%s",
                 utils_uint8_to_hex(pin_b, VERIFYPASS_LOCK_CODE_LEN));
#endif

        // Append PIN to echo
        commander_ser_cmd(CMD_pin);
        commander_ser_str(TFA_PIN);

    }
    return DBB_OK;
}


static int commander_tfa_check_pin(const uint8_t *command, int cmd_len)
{
    const char *pin = commander_get_str_attribute(command, cmd_len, CMD_pin);

    if (!strlens(pin)) {
        return DBB_ERROR;
    }

    if (strncmp(pin, TFA_PIN, sizeof(TFA_PIN))) {
        return DBB_ERROR;
    }

    return DBB_OK;
}


static int commander_echo_command(const uint8_t *command, int cmd_len)
{
    uint16_t arr_len, ele_len, c = 0;
    int i=0, ret = -1;
    uint8_t hash[32]; //256 bit hash (sha256)
    uint8_t pubkey[33]; //compact ECpubkey
    char keypath[256];

    if (!command || cmd_len <= 0)
        return DBB_ERROR;

    commander_clear_report();
    commander_ser_cmd(CMD_echo);
    commander_ser_cmd(CMD_valuearray);

    const char *meta = commander_get_str_attribute(command, cmd_len, CMD_meta);
    int hashkeypath_len = 0, checkpubkey_len = 0;
    const uint8_t *hashkeypath = commander_get_attribute(command, cmd_len, CMD_hashkeypatharray, &hashkeypath_len);
    const uint8_t *checkpubkey = commander_get_attribute(command, cmd_len, CMD_pubkeykeypatharray, &checkpubkey_len);
    if (meta && (checkpubkey && checkpubkey_len >= 2)) {
        commander_ser_u16(3); //3 elements (checkpubkey, meta, hashkeypath)
        commander_ser_attr_str(ATTR_meta, meta);
    }
    else if (meta) {
        commander_ser_u16(2); //hashkeypath and meta
        commander_ser_attr_str(ATTR_meta, meta);
    }
    else if ((checkpubkey && checkpubkey_len >= 2)) {
        commander_ser_u16(2); //hashkeypath and checkpubkey
    }
    else {
        commander_ser_u16(1); //single hashkeypath element
    }

    if (!hashkeypath || hashkeypath_len < 2) {
        commander_clear_report();
        commander_fill_report(cmd_str(CMD_sign), NULL, DBB_ERR_IO_INVALID_CMD);
        return DBB_ERROR;
    } else {
        arr_len = (hashkeypath[c] << 8) + hashkeypath[c + 1];
        int arr_len_comparable = (int)arr_len;
        if (arr_len == 0 || arr_len_comparable > COMMANDER_ARRAY_MAX) {
            commander_clear_report();
            commander_fill_report(cmd_str(CMD_sign), NULL, DBB_ERR_IO_INVALID_CMD);
            return DBB_ERROR;
        }
        commander_ser_cmd(CMD_hashkeypatharray);
        commander_ser_u16(arr_len);
        for (i = 0; i < arr_len; i++) {
            /* bounds check */
            if (hashkeypath_len < c+2+(int)sizeof(hash)) {
                goto deser_error;
            }
            ele_len = (hashkeypath[c + 2] << 8) + hashkeypath[c + 3];
            memset(hash, 0, sizeof(hash));
            memset(keypath, 0, sizeof(keypath));
            memcpy(hash, hashkeypath + c + 4, sizeof(hash));
            memcpy(keypath, hashkeypath + c + 4 + sizeof(hash), MIN( sizeof(keypath), (ele_len - sizeof(hash)) ));

            if (!strlens(keypath) || (ele_len - sizeof(hash)) > sizeof(keypath) ) {
                goto deser_error;
            }

            commander_ser_u16(ele_len);
            commander_ser_buf(hash, sizeof(hash));
            commander_ser_buf((uint8_t*)keypath, ele_len-sizeof(hash));
            c += sizeof(ele_len) + ele_len;
        }
    }

    if (checkpubkey && checkpubkey_len >= 2) {
        arr_len=0; ele_len=0; c = 0;
        arr_len = (checkpubkey[c] << 8) + checkpubkey[c + 1];
        int arr_len_comparable = (int)arr_len;
        if (arr_len_comparable > COMMANDER_ARRAY_MAX) {
            commander_clear_report();
            commander_fill_report(cmd_str(CMD_sign), NULL, DBB_ERR_IO_INVALID_CMD);
            return DBB_ERROR;
        }

        commander_ser_cmd(CMD_pubkeystatusarray);
        commander_ser_u16(arr_len);
        for (i = 0; i < arr_len; i++) {
            ele_len = (checkpubkey[c + 2] << 8) + checkpubkey[c + 3];
            if (checkpubkey_len < c+(int)sizeof(pubkey)) {
                goto deser_error;
            }
            memset(pubkey, 0, sizeof(pubkey));
            memset(keypath, 0, sizeof(keypath));
            memcpy(pubkey, checkpubkey + c + 4, sizeof(pubkey));
            memcpy(keypath, checkpubkey + c + 4 + sizeof(pubkey), MIN( sizeof(keypath), (ele_len - sizeof(pubkey)) ));

            if (!strlens(keypath) || (ele_len - sizeof(pubkey)) > sizeof(keypath)) {
                goto deser_error;
            }

            ret = wallet_check_pubkey(pubkey, keypath);
            if (ret != DBB_KEY_PRESENT && ret != DBB_KEY_ABSENT) {
                return DBB_ERROR;
            }

            int state = (ret == DBB_KEY_PRESENT);
            commander_ser_buf(pubkey, sizeof(pubkey));
            commander_ser_buf((uint8_t*)&state, 1);
            c += sizeof(ele_len) + ele_len;
        }
        if (ret == -1) {
            /* report error in case of an empty checkpub array */
            goto deser_error;
        }
    }

    if (commander_tfa_append_pin() != DBB_OK) {
        return DBB_ERROR;
    }

    int encrypt_len;
    uint8_t *encoded_report;
    encoded_report = aes_cbc_encrypt_pad(&response_report[1],
                                         response_report_current_p-response_report-1,
                                         &encrypt_len,
                                         PASSWORD_VERIFY);
    commander_clear_report();
    if (encoded_report) {
        response_report[0] = 0;
        response_report[0] |= DBB_RESPONSE_FLAG_ENCRYPTED_VERIFYKEY;
        memcpy(response_report_current_p, encoded_report, encrypt_len);
        response_report_current_p+=encrypt_len;
    } else {
        commander_fill_report(cmd_str(CMD_echo), NULL, DBB_ERR_MEM_ENCRYPT);
    }
    free(encoded_report);
    return DBB_OK;

deser_error:
    commander_clear_report();
    commander_fill_report(cmd_str(CMD_sign), NULL, DBB_ERR_SIGN_DESERIAL);
    return DBB_ERROR;
}


static int commander_touch_button(int found_cmd)
{
    if (found_cmd == CMD_seed && wallet_seeded() != DBB_OK) {
        // Do not require touch if not yet seeded
        return DBB_OK;
    } else if (found_cmd < CMD_REQUIRE_TOUCH) {
        return touch_button_press(DBB_TOUCH_LONG);
    } else {
        return DBB_OK;
    }
}


static void commander_access_err(uint8_t err_msg, uint16_t err_count)
{
    char msg[256];
    uint8_t warn_msg = (err_count < COMMANDER_TOUCH_ATTEMPTS) ? DBB_WARN_RESET :
                       DBB_WARN_RESET_TOUCH;
    snprintf(msg, sizeof(msg), "%s %i %s",
             flag_msg(err_msg),
             COMMANDER_MAX_ATTEMPTS - err_count,
             flag_msg(warn_msg));

    commander_ser_set_err(CMD_input, err_msg, COMMANDER_MAX_ATTEMPTS - err_count);
}

static void commander_parse(const uint8_t *command, int cmd_len)
{
    uint8_t *encoded_report;
    int status, found_cmd_instr_idx = 0xFF, encrypt_len;

    found_cmd_instr_idx = commander_get_command(command);

    // Process commands
    if (!found_cmd_instr_idx) {
        commander_ser_set_err(CMD_input, DBB_ERR_IO_INVALID_CMD, -1);
    } else {
        memory_access_err_count(DBB_ACCESS_INITIALIZE);

        // Signing
        if (TFA_VERIFY) {
            TFA_VERIFY = 0;

            if (found_cmd_instr_idx != CMD_sign) {
                goto other;
            }

            if (wallet_is_locked()) {
                if (commander_tfa_check_pin(command, cmd_len) != DBB_OK) {
                    memset(TFA_PIN, 0, sizeof(TFA_PIN));
                    commander_access_err(DBB_ERR_SIGN_TFA_PIN, memory_read_pin_err_count() + 1);
                    memory_pin_err_count(DBB_ACCESS_ITERATE);
                    memset(sign_command, 0, COMMANDER_REPORT_SIZE);
                    sign_command_len = 0;
                    return;
                } else {
                    memory_pin_err_count(DBB_ACCESS_INITIALIZE);
                    memset(TFA_PIN, 0, sizeof(TFA_PIN));
                }
            }
            status = touch_button_press(DBB_TOUCH_LONG_BLINK);
            if (status == DBB_TOUCHED) {
                commander_process_sign((const uint8_t*)sign_command, sign_command_len);
            } else {
                commander_fill_report(cmd_str(CMD_sign), NULL, status);
            }
            memset(sign_command, 0, COMMANDER_REPORT_SIZE);
            sign_command_len = 0;
            return;
        }

        // Verification 'echo' for signing
        if (found_cmd_instr_idx == CMD_sign) {
            if (commander_echo_command(command, cmd_len) == DBB_OK) {
                TFA_VERIFY = 1;
                memset(sign_command, 0, COMMANDER_REPORT_SIZE);
                memcpy(sign_command, command, cmd_len);
                sign_command_len = cmd_len;
            }
            return;
        }

    other:
        // Other commands
        status = commander_touch_button(found_cmd_instr_idx);
        if (status == DBB_TOUCHED || status == DBB_OK) {
            if (commander_process(found_cmd_instr_idx, command, cmd_len) == DBB_RESET) {
                return;
            }
        } else {
            commander_fill_report(cmd_str(found_cmd_instr_idx), NULL, status);
        }
    }

    encoded_report = aes_cbc_encrypt_pad(&response_report[1],
                                         response_report_current_p-response_report-1,
                                         &encrypt_len,
                                         wallet_is_hidden() ? PASSWORD_HIDDEN : PASSWORD_STAND);
    commander_clear_report();
    if (encoded_report) {
        response_report[0] = 0;
        response_report[0] |= DBB_RESPONSE_FLAG_ENCRYPTED;
        memcpy(response_report_current_p, encoded_report, encrypt_len);
        response_report_current_p+=encrypt_len;
    } else {
        commander_ser_set_err(CMD_ciphertext, DBB_ERR_MEM_ENCRYPT, -1);
    }
    free(encoded_report);
}


static uint8_t *commander_decrypt(const uint8_t *encrypted_command, int enc_len, int *command_len_out)
{
    uint8_t *command;
    int err = 0;
    uint16_t err_count = 0, err_iter = 0;

    wallet_set_hidden(0);


    command = aes_cbc_decrypt_pad((const unsigned char *)encrypted_command,
                                  enc_len,
                                  command_len_out,
                                  PASSWORD_STAND);


    err_count = memory_read_access_err_count();     // Reads over TWI introduce additional
    err_iter = memory_read_access_err_count() + 1;  // temporal jitter in code execution.

    if (!*command_len_out) {
        err++;
    } else {
        err_iter--;
    }

    if (!command || err) {
        if (*command_len_out) {
            free(command);
        }

        // Check if hidden wallet is requested
        command = aes_cbc_decrypt_pad((const unsigned char *)encrypted_command,
                                      enc_len,
                                      command_len_out,
                                      PASSWORD_HIDDEN);
        if (*command_len_out) {
            wallet_set_hidden(1);
            return command;
        }

        // Incorrect input
        err_iter = memory_access_err_count(DBB_ACCESS_ITERATE);
        commander_access_err(DBB_ERR_IO_JSON_PARSE, err_iter);
        commander_ser_cmd(CMD_value_str);
        commander_ser_u16(32);
        uint8_t *test = memory_report_aeskey(PASSWORD_STAND);
        commander_ser_buf(test, 32);
    }

    if (err_iter - err_count == 0 && err == 0) {
        return command;
    }

    if (err_iter - err_count == err) {
        return NULL;
    }

    // Corrupted data
    commander_force_reset();
    return NULL;
}


static int commander_check_init(const uint8_t *encrypted_command_compl, int enc_cmd_len)
{
    if (memory_read_access_err_count() >= COMMANDER_TOUCH_ATTEMPTS) {
         int status = touch_button_press(DBB_TOUCH_LONG);
         if (status != DBB_TOUCHED) {
             commander_fill_report(cmd_str(CMD_input), NULL, status);
             return DBB_ERROR;
         }
     }

    if (enc_cmd_len < 2) {
        commander_access_err(DBB_ERR_IO_NO_INPUT, memory_access_err_count(DBB_ACCESS_ITERATE));
        return DBB_ERROR;
    }

    uint8_t flags = encrypted_command_compl[0];
    const uint8_t *encrypted_command = &encrypted_command_compl[1];
    if (!(flags & DBB_RESPONSE_FLAG_ENCRYPTED) && commander_get_command(encrypted_command) == CMD_ping) {
        if (memory_report_erased()) {
            commander_ser_cmd_attr(CMD_ping, ATTR_false);
        } else {
            commander_ser_cmd_attr(CMD_ping, ATTR_password);
        }
        return DBB_ERROR;
    }

    // Force setting a password before processing any other command.
    if (!memory_report_erased()) {
        return DBB_OK;
    }

    if (!(flags & DBB_RESPONSE_FLAG_ENCRYPTED) && commander_get_command(encrypted_command) == CMD_password) {
        const char *value = commander_get_str_attribute(encrypted_command, enc_cmd_len, CMD_value);
        if (strlens(value)) {
            int ret = commander_process_aes_key(value, strlens(value), PASSWORD_STAND);
            if (ret == DBB_OK) {
                memory_write_erased(0);
                commander_ser_cmd_attr(CMD_password, ATTR_success);
                uint8_t *test = memory_report_aeskey(PASSWORD_STAND);
                commander_ser_str(utils_uint8_to_hex(test, 32));
//                commander_ser_cmd(CMD_value_str);
//                commander_ser_u16(31);
//                memory_write_aeskey("0000", 4, PASSWORD_STAND);
//                uint8_t *test = memory_report_aeskey(PASSWORD_STAND);
//                commander_ser_buf(test, 32);
//                commander_ser_u16(30);
            } else {
                commander_fill_report(cmd_str(CMD_password), NULL, ret);
            }
            return DBB_ERROR;
        }
        else {
            commander_ser_set_err(CMD_input, DBB_ERR_IO_PASSWORD_LEN, -1);
            return DBB_ERROR;
        }
    }

    commander_ser_set_err(CMD_input, DBB_ERR_IO_NO_PASSWORD, -1);
    return DBB_ERROR;
}


//
//  Gateway to the MCU code //
//
const uint8_t *commander(const uint8_t *command, int cmd_len, int *len_out)
{
    commander_clear_report();
    if (commander_check_init(command, cmd_len) == DBB_OK) {
        int cmd_dec_len = 0;
        uint8_t *command_dec = commander_decrypt(command+1, cmd_len-1, &cmd_dec_len);
        if (command_dec && cmd_dec_len >= 2) {
            commander_parse(command_dec, cmd_dec_len);
            free(command_dec);
        }
    }
    if (len_out)
        *len_out = response_report_current_p-response_report;
    memory_clear();
    return response_report;
}
