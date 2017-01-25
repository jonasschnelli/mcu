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


#ifndef _COMMANDER_H_
#define _COMMANDER_H_


#include <stdint.h>
#include "memory.h"

#include "flags.h"


char *aes_cbc_b64_encrypt(const unsigned char *in, int inlen, int *out_b64len,
                          PASSWORD_ID id);
uint8_t *aes_cbc_encrypt_pad(const unsigned char *in, int inlen, int *out_len,
                          PASSWORD_ID id);
char *aes_cbc_b64_decrypt(const unsigned char *in, int inlen, int *decrypt_len,
                          PASSWORD_ID id);
uint8_t *aes_cbc_decrypt_pad(const unsigned char *in, int inlen, int *decrypt_len,
                          PASSWORD_ID id);
void commander_clear_report(void);

/* serialize functions */
void commander_ser_set_err(enum CMD_ENUM cmd_index, int flag, int attempts_left);
void commander_ser_cmd_attr(enum CMD_ENUM cmd_index, enum CMD_ATTR_ENUM attr_index);
void commander_ser_buf(const uint8_t *buf, int len);
void commander_ser_u16(uint16_t c_instr);

const char *commander_read_report(void);
void commander_ser_to_report(enum CMD_ENUM cmd_instr, enum CMD_ATTR_ENUM attr_instr, int flag);
void commander_fill_report(const char *attr, const char *val, int err);
void commander_force_reset(void);
void commander_create_verifypass(void);
const uint8_t *commander(const uint8_t *command, int cmd_len, int *len_out);


#endif
