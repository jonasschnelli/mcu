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


#ifndef _API_H_
#define _API_H_


#include <arpa/inet.h>
#include "flags.h"
#include "yajl/src/api/yajl_tree.h"
#include "u2f/u2f_hid.h"
#include "u2f/u2f.h"
#include "u2f_device.h"
#include "usb.h"


#define HWW_CID 0xff000000
#define HID_REPORT_SIZE   COMMANDER_REPORT_SIZE


#ifndef CONTINUOUS_INTEGRATION
// http://www.signal11.us/oss/hidapi/
#include <hidapi.h>

static hid_device *HID_HANDLE;
#endif


static const char tests_pwd[] = "0000";
static const char hidden_pwd[] = "hide";
static char command_sent[COMMANDER_REPORT_SIZE] = {0};
static int TEST_LIVE_DEVICE = 0;

static unsigned char HID_REPORT[HID_REPORT_SIZE] = {0};

static int api_hid_send_frame(USB_FRAME *f)
{
    int res = 0;
    uint8_t d[sizeof(USB_FRAME) + 1];
    memset(d, 0, sizeof(d));
    d[0] = 0;  // un-numbered report
    f->cid = htonl(f->cid);  // cid is in network order on the wire
    memcpy(d + 1, f, sizeof(USB_FRAME));
    f->cid = ntohl(f->cid);

    if (TEST_LIVE_DEVICE) {
#ifndef CONTINUOUS_INTEGRATION
        res = hid_write(HID_HANDLE, d, sizeof(d));
#endif
    } else {
        u2f_device_run(f);
        res = sizeof(d);
    }

    if (res == sizeof(d)) {
        return 0;
    }
    return 1;
}


static int api_hid_send_frames(uint32_t cid, uint8_t cmd, const void *data, size_t size)
{
    USB_FRAME frame;
    int res;
    size_t frameLen;
    uint8_t seq = 0;
    const uint8_t *pData = (const uint8_t *) data;

    frame.cid = cid;
    frame.init.cmd = TYPE_INIT | cmd;
    frame.init.bcnth = (size >> 8) & 255;
    frame.init.bcntl = (size & 255);

    frameLen = MIN(size, sizeof(frame.init.data));
    memset(frame.init.data, 0xEE, sizeof(frame.init.data));
    memcpy(frame.init.data, pData, frameLen);

    do {
        res = api_hid_send_frame(&frame);
        if (res != 0) {
            return res;
        }

        size -= frameLen;
        pData += frameLen;

        frame.cont.seq = seq++;
        frameLen = MIN(size, sizeof(frame.cont.data));
        memset(frame.cont.data, 0xEE, sizeof(frame.cont.data));
        memcpy(frame.cont.data, pData, frameLen);
    } while (size);

    return 0;
}


static int api_hid_read_frame(USB_FRAME *r)
{

    memset((int8_t *)r, 0xEE, sizeof(USB_FRAME));

    int res = 0;
    if (TEST_LIVE_DEVICE) {
#ifndef CONTINUOUS_INTEGRATION
        res = hid_read(HID_HANDLE, (uint8_t *) r, sizeof(USB_FRAME));
#endif
    } else {
        static uint8_t *data;
        data = usb_reply_queue_read();
        if (data) {
            memcpy(r, data, sizeof(USB_FRAME));
            res = sizeof(USB_FRAME);
        } else {
            res = 0;
        }
    }


    if (res == sizeof(USB_FRAME)) {
        if (TEST_LIVE_DEVICE) {
            r->cid = ntohl(r->cid);
        }
        return 0;
    }
    return 1;
}


static int api_hid_read_frames(uint32_t cid, uint8_t cmd, void *data, int max)
{
    USB_FRAME frame;
    int res, result;
    size_t totalLen, frameLen;
    uint8_t seq = 0;
    uint8_t *pData = (uint8_t *) data;

    (void) cmd;

    do {
        res = api_hid_read_frame(&frame);
        if (res != 0) {
            return res;
        }

    } while (frame.cid != cid || FRAME_TYPE(frame) != TYPE_INIT);

    if (frame.init.cmd == U2FHID_ERROR) {
        return -frame.init.data[0];
    }

    totalLen = MIN(max, MSG_LEN(frame));
    frameLen = MIN(sizeof(frame.init.data), totalLen);

    result = totalLen;

    memcpy(pData, frame.init.data, frameLen);
    totalLen -= frameLen;
    pData += frameLen;

    while (totalLen) {
        res = api_hid_read_frame(&frame);
        if (res != 0) {
            return res;
        }

        if (frame.cid != cid) {
            continue;
        }
        if (FRAME_TYPE(frame) != TYPE_CONT) {
            return -ERR_INVALID_SEQ;
        }
        if (FRAME_SEQ(frame) != seq++) {
            return -ERR_INVALID_SEQ;
        }

        frameLen = MIN(sizeof(frame.cont.data), totalLen);

        memcpy(pData, frame.cont.data, frameLen);
        totalLen -= frameLen;
        pData += frameLen;
    }

    return result;
}


#ifndef CONTINUOUS_INTEGRATION
static int api_hid_init(void)
{
    HID_HANDLE = hid_open(0x03eb, 0x2402, NULL);
    if (!HID_HANDLE) {
        return DBB_ERROR;
    }
    return DBB_OK;
}
static void api_hid_close(void)
{
    if (HID_HANDLE)
        hid_close(HID_HANDLE);
    hid_exit();
}
#endif


static void api_hid_read(PASSWORD_ID id)
{
    memset(HID_REPORT, 0, HID_REPORT_SIZE);
    int res = api_hid_read_frames(HWW_CID, HWW_COMMAND, HID_REPORT, HID_REPORT_SIZE);
    if (res < 0) {
        printf("ERROR: Unable to read report.\n");
        return;
    }
    utils_decrypt_report((char *)HID_REPORT, id);
}


static void api_hid_send_len(const uint8_t *cmd, int cmdlen)
{
    api_hid_send_frames(HWW_CID, HWW_COMMAND, cmd, cmdlen);
}


static void api_hid_send_encrypt(const uint8_t *cmd, uint16_t len, PASSWORD_ID id)
{
    int enc_len;
    uint8_t *enc = (uint8_t*)aes_cbc_b64_encrypt((const unsigned char *)cmd, len, &enc_len, id);
    api_hid_send_len(enc, enc_len);
    free(enc);
}

static uint16_t api_ser_cmd(const char *command)
{
    int id;
    for (id = 0; id < CMD_NUM; id++) {
        if (strcmp(cmd_str(id), command) == 0) {
            return cmd_instr(id);
        }
    }
    return 0;
}

static uint16_t api_serialize_json(const char *command, uint8_t *buffer)
{
    uint16_t b_len = 0, ser_cmd;
    yajl_val json_node = yajl_tree_parse(command, NULL, 0);
    if (!json_node)
        return 0;
    const char *cmd_parent = json_node->u.object.keys[0];
    yajl_val args = json_node->u.object.values[0];
    size_t args_len = args->u.object.len;
    // allow maximal 100 arguments in array
    if (args_len > 100)
    {
        goto exit_and_free;
    }

    // main command
    ser_cmd = api_ser_cmd(cmd_parent);
    buffer[b_len++] = (ser_cmd & 0xFF00) >> 8;
    buffer[b_len++] = (ser_cmd & 0x00FF);

    if (!args_len) {
        /* at this point, we very likely have a single string argument */
        const char *cmd_val = json_node->u.object.values[0]->u.string;
        uint16_t val_len = strlens(cmd_val) + 1;// add 1 for null

        if (strlens(cmd_val)) {
            /* add child command if the string is valid (>0) */
            ser_cmd = cmd_instr(CMD_value);
            buffer[b_len++] = (ser_cmd & 0xFF00) >> 8;
            buffer[b_len++] = (ser_cmd & 0x00FF);
            // Child command value
            buffer[b_len++] = (val_len & 0xFF00) >> 8;
            buffer[b_len++] = (val_len & 0x00FF);
            memcpy(buffer + b_len, cmd_val, val_len);
            b_len += val_len;
        }
        else {
            // set a null instruction
            buffer[b_len++] = 0x00;
            buffer[b_len++] = 0x00;
        }

    } else {
        /* we are parsing an argument array */
        ser_cmd = cmd_instr(CMD_valuearray);
        buffer[b_len++] = (ser_cmd & 0xFF00) >> 8;
        buffer[b_len++] = (ser_cmd & 0x00FF);

        uint16_t val_len_ary = args_len;
        uint8_t *ary_size_ptr = buffer + b_len;
        buffer[b_len++] = (val_len_ary & 0xFF00) >> 8;
        buffer[b_len++] = (val_len_ary & 0x00FF);

        int array_count = 0;
        for (size_t i = 0; i < args_len; i++) {
            const char *arg_key = args->u.object.keys[i];
            yajl_val arg_val = args->u.object.values[i];


            /* Child command value */
            if (YAJL_IS_STRING(arg_val)) {
                /* a single string */

                /* serialize the command instruction by a given command string in the json key */
                /* key must be known */
                ser_cmd = api_ser_cmd(arg_key);
                if (!ser_cmd)
                    continue;
                buffer[b_len++] = (ser_cmd & 0xFF00) >> 8;
                buffer[b_len++] = (ser_cmd & 0x00FF);

                const char *cmd_val = arg_val->u.string;
                uint16_t val_len = strlens(cmd_val) + 1;// add 1 for null

                /* add child command if the string is valid (>0) */
                ser_cmd = cmd_instr(CMD_value);
                buffer[b_len++] = (ser_cmd & 0xFF00) >> 8;
                buffer[b_len++] = (ser_cmd & 0x00FF);
                /* size */
                buffer[b_len++] = (val_len & 0xFF00) >> 8;
                buffer[b_len++] = (val_len & 0x00FF);
                memcpy(buffer + b_len, cmd_val, val_len);
                b_len += val_len;

                array_count++;
            } else if (YAJL_IS_ARRAY(arg_val)) {
                // case - data:[hash, keypath]
                if (arg_key && strcmp(arg_key, "data") == 0 && arg_val->u.array.len > 0)
                {
                    uint16_t subarray_cnt = 0;

                    /* write hash/keypath array instr */
                    ser_cmd = cmd_instr(CMD_hashkeypatharray);
                    buffer[b_len++] = (ser_cmd & 0xFF00) >> 8;
                    buffer[b_len++] = (ser_cmd & 0x00FF);

                    /* write subarray length, keep pointer to update length later */
                    uint16_t val_len_sub_ary = arg_val->u.array.len;
                    uint8_t *subary_size_ptr = buffer + b_len;
                    buffer[b_len++] = (val_len_sub_ary  & 0xFF00) >> 8;
                    buffer[b_len++] = (val_len_sub_ary  & 0x00FF);

                    for (size_t j = 0; j < arg_val->u.array.len; j++) {
                        /* loop true array with {"hash":x, "keypath": y} objects */
                        yajl_val obj = arg_val->u.array.values[j];
                        const char *keypath_path[] = { cmd_str(CMD_keypath), NULL };
                        const char *hash_path[] = { cmd_str(CMD_hash), NULL };
                        const char *keypath = YAJL_GET_STRING(yajl_tree_get(obj, keypath_path, yajl_t_string));
                        const char *hash = YAJL_GET_STRING(yajl_tree_get(obj, hash_path, yajl_t_string));
                        uint8_t hash_d[32];
                        if (hash && keypath) {
                            /* write hash/keypath length */
                            uint16_t len = sizeof(hash_d) + strlens(keypath) + 1;// add 1s for null
                            buffer[b_len++] = (len & 0xFF00) >> 8;
                            buffer[b_len++] = len & 0x00FF;

                            /* convert hash-hex to bin */
                            memset(hash_d, 0, sizeof(hash_d));
                            memcpy(hash_d, utils_hex_to_uint8(hash), sizeof(hash_d));

                            /* write hash to buffer */
                            memcpy(buffer + b_len, hash_d, sizeof(hash_d));
                            b_len += sizeof(hash_d);

                            /* write keypath to buffer */
                            memcpy(buffer + b_len, keypath, strlens(keypath) + 1);
                            b_len += strlens(keypath) + 1;
                            subarray_cnt++;
                        }
                    }
                    /* finish main arguments array, write final array size */
                    subary_size_ptr[0] = (subarray_cnt & 0xFF00) >> 8;
                    subary_size_ptr[1] = (subarray_cnt & 0x00FF);
                    array_count++;
                }
                /* checkpub {"pubkey":x, "keypath":y} case */
                else if (arg_key && strcmp(arg_key, "checkpub") == 0 && arg_val->u.array.len > 0)
                {
                    uint16_t subarray_cnt = 0;

                    /* write hash/keypath array instr */
                    ser_cmd = cmd_instr(CMD_pubkeykeypatharray);
                    buffer[b_len++] = (ser_cmd & 0xFF00) >> 8;
                    buffer[b_len++] = (ser_cmd & 0x00FF);

                    /* write subarray length, keep pointer to update length later */
                    uint16_t val_len_sub_ary = arg_val->u.array.len;
                    uint8_t *subary_size_ptr = buffer + b_len;
                    buffer[b_len++] = (val_len_sub_ary  & 0xFF00) >> 8;
                    buffer[b_len++] = (val_len_sub_ary  & 0x00FF);

                    for (size_t j = 0; j < arg_val->u.array.len; j++) {
                        yajl_val obj = arg_val->u.array.values[j];
                        const char *pubkey_path[] = { cmd_str(CMD_pubkey), NULL };
                        const char *keypath_path[] = { cmd_str(CMD_keypath), NULL };
                        const char *pubkey = YAJL_GET_STRING(yajl_tree_get(obj, pubkey_path, yajl_t_string));
                        const char *keypath = YAJL_GET_STRING(yajl_tree_get(obj, keypath_path, yajl_t_string));

                        /* only compressed pubkeys are supported */
                        uint8_t comp_pubkey_bin[33];
                        if (pubkey && keypath && strlen(pubkey) == 66) {
                            uint16_t len = sizeof(comp_pubkey_bin) + strlens(keypath) + 1;// add 1s for null
                            buffer[b_len++] = (len & 0xFF00) >> 8;
                            buffer[b_len++] = len & 0x00FF;

                            /* convert pubkey-hex to bin */
                            memset(comp_pubkey_bin, 0, sizeof(comp_pubkey_bin));
                            memcpy(comp_pubkey_bin, utils_hex_to_uint8(pubkey), sizeof(comp_pubkey_bin));

                            memcpy(buffer + b_len, comp_pubkey_bin, sizeof(comp_pubkey_bin));
                            b_len += sizeof(comp_pubkey_bin);

                            memcpy(buffer + b_len, keypath, strlens(keypath) + 1);
                            b_len += strlens(keypath) + 1;
                            subarray_cnt++;
                        }
                        else {
                            /* be strict */
                            b_len = 0;
                            goto exit_and_free;
                        }
                    }
                    /* finish main arguments array, write final array size */
                    subary_size_ptr[0] = (subarray_cnt & 0xFF00) >> 8;
                    subary_size_ptr[1] = (subarray_cnt & 0x00FF);
                    array_count++;
                } /* end if checkpub */
            }
            else {
                /* set a null instruction if there is no value string */
                buffer[b_len++] = 0x00;
                buffer[b_len++] = 0x00;
            }
        }

        /* finish main arguments array, write final array size */
        ary_size_ptr[0] = (val_len_ary & 0xFF00) >> 8;
        ary_size_ptr[1] = (val_len_ary & 0x00FF);
    }
exit_and_free:
    yajl_tree_free(json_node);
    return b_len;
}

static int api_send_cmd(const char *command, PASSWORD_ID id)
{
    uint16_t len = 0;
    uint8_t command_ser[COMMANDER_REPORT_SIZE];
    memset(command_ser, 0, COMMANDER_REPORT_SIZE);

    if (strlens(command)) {
        len = api_serialize_json(command, command_ser);
    }

    if (!len) {
        return 0;
    }

    if (len > COMMANDER_REPORT_SIZE) {
        printf("\n\nError: Buffer too long.\n\n");
        exit(1);
    }

    memset(command_sent, 0, sizeof(command_sent));
    if (command) {
        memcpy(command_sent, command_ser, len);
    }
    if (!TEST_LIVE_DEVICE) {
        utils_send_cmd(command_ser, len, id);
    }
#ifndef CONTINUOUS_INTEGRATION
    else if (id == PASSWORD_NONE) {
        api_hid_send_len(command_ser, len);
        api_hid_read(id);
    } else {
        api_hid_send_encrypt(command_ser, len, id);
        api_hid_read(id);
    }
#endif
    return 1;
}


static int api_format_send_cmd(const char *cmd, const char *val, PASSWORD_ID id)
{
    char command[COMMANDER_REPORT_SIZE] = {0};
    strcpy(command, "{\"");
    strcat(command, cmd);
    strcat(command, "\": ");
    if (val[0] == '{') {
        strcat(command, val);
    } else {
        strcat(command, "\"");
        strcat(command, val);
        strcat(command, "\"");
    }
    strcat(command, "}");
    return api_send_cmd(command, id);
}


static void api_reset_device(void)
{
    api_format_send_cmd(cmd_str(CMD_password), tests_pwd, PASSWORD_NONE); // if not set
    api_format_send_cmd(cmd_str(CMD_reset), attr_str(ATTR___ERASE__), PASSWORD_STAND);
}


static const char *api_read_value(int cmd)
{
    static char value[HID_REPORT_SIZE];
    memset(value, 0, sizeof(value));

    yajl_val json_node = yajl_tree_parse(utils_read_decrypted_report(), NULL, 0);
    if (json_node && YAJL_IS_OBJECT(json_node)) {
        const char *path[] = { cmd_str(cmd), NULL };
        yajl_val v = yajl_tree_get(json_node, path, yajl_t_string);
        snprintf(value, sizeof(value), "%s", v->u.string);
    }

    yajl_tree_free(json_node);
    return value;
}


static char *api_read_value_decrypt(int cmd, PASSWORD_ID id)
{
    const char *val = api_read_value(cmd);
    static char val_dec[HID_REPORT_SIZE];
    memset(val_dec, 0, sizeof(val_dec));

    int decrypt_len;
    char *dec = aes_cbc_b64_decrypt((const unsigned char *)val, strlens(val),
                                    &decrypt_len, id);

    snprintf(val_dec, HID_REPORT_SIZE, "%.*s", decrypt_len, dec);
    free(dec);
    return val_dec;
}

#endif

