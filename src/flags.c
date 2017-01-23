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
#include <stdint.h>
#include "flags.h"


struct dbb_str_instr
{
    const char *const str; //the command/attribute string
    uint16_t ins; //instruction, limited to uint16, DBB offers up to 256*256 commands.
};

#define X(a, b) {#a,b},
const struct dbb_str_instr CMD_ENUM_TBL[] = { CMD_TABLE };
#undef X

#define X(a, b) {#a,b},
const struct dbb_str_instr ATTR_ENUM_TBL[] = { ATTR_TABLE };
#undef X

#define X(a, b, c) b,
const uint16_t FLAG_CODE[] = { FLAG_TABLE };
#undef X

#define X(a, b, c) c,
const char *const FLAG_MSG[] = { FLAG_TABLE };
#undef X


const char *cmd_str(int cmd)
{
    return CMD_ENUM_TBL[cmd].str;
}


uint16_t cmd_instr(enum CMD_ENUM enum_index)
{
    return CMD_ENUM_TBL[enum_index].ins;
}


const char *attr_str(int attr)
{
    return ATTR_ENUM_TBL[attr].str;
}


uint16_t attr_instr(enum CMD_ATTR_ENUM enum_index)
{
    return ATTR_ENUM_TBL[enum_index].ins;
}


uint16_t flag_code(int flag)
{
    return FLAG_CODE[flag];
}


const char *flag_msg(int flag)
{
    return FLAG_MSG[flag];
}
