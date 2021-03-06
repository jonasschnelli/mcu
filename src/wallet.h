/*

 The MIT License (MIT)

 Copyright (c) 2015 Douglas J. Bakkum

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



#ifndef _WALLET_H_
#define _WALLET_H_


#include <stdint.h>
#include "bip32.h"


#define BIP39_PBKDF2_ROUNDS 2048
#define MAX_SEED_WORDS      25// 24 mnemonic words + 1 for NULL ending
#define SALT_LEN_MAX        256// 24 mnemonic words + 1 for NULL ending


/* BIP32 */
int wallet_split_seed(char **seed_words, const char *message);
const char **wallet_mnemonic_wordlist(void);
uint16_t *wallet_index_from_mnemonic(const char *mnemo);
char *wallet_mnemonic_from_index(const uint16_t *index);
int wallet_master_from_mnemonic(char *mnemo, int m_len, const char *salt, int s_len);
int wallet_check_pubkey(const char *pubkeyhash, const char *keypath, int keypath_len);
int wallet_sign(const char *message, int msg_len, const char *keypath, int keypath_len);
void wallet_report_xpub(const char *keypath, int keypath_len, char *xpub);
int wallet_generate_key(HDNode *node, const char *keypath, int keypath_len,
                        const uint8_t *privkeymaster, const uint8_t *chaincode);
char *wallet_mnemonic_from_data(const uint8_t *data, int len);
int wallet_mnemonic_check(const char *mnemo);
void wallet_mnemonic_to_seed(const char *mnemo, const char *passphrase,
                             uint8_t s[512 / 8],
                             void (*progress_callback)(uint32_t current, uint32_t total));
/* Bitcoin formats */
void wallet_get_pubkeyhash(const uint8_t *pub_key, uint8_t *pubkeyhash);
void wallet_get_address_raw(const uint8_t *pub_key, uint8_t version, uint8_t *addr_raw);
void wallet_get_address(const uint8_t *pub_key, uint8_t version, char *addr,
                        int addrsize);
void wallet_get_wif(const uint8_t *priv_key, uint8_t version, char *wif, int wifsize);



#endif
