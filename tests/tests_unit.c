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


#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "commander.h"
#include "wallet.h"
#include "random.h"
#include "base64.h"
#include "base58.h"
#include "pbkdf2.h"
#include "base64.h"
#include "flags.h"
#include "bip32.h"
#include "utils.h"
#include "utest.h"
#include "uECC.h"
#include "sha2.h"
#include "aes.h"


int U_TESTS_RUN = 0;
int U_TESTS_FAIL = 0;


// Most tests taken from:
// https://github.com/trezor/trezor-crypto/blob/master/tests.c


// test vector 1 from https://en.bitcoin.it/wiki/BIP_0032_TestVectors
static void test_bip32_vector_1(void)
{
    HDNode node, node2, node3;
    char str[112];
    int r;
    uint8_t private_key_master[32];
    uint8_t chain_code_master[32];

    // init m
    hdnode_from_seed(utils_hex_to_uint8("000102030405060708090a0b0c0d0e0f"), 16, &node);

    // [Chain m]
    memcpy(private_key_master,
           utils_hex_to_uint8("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"),
           32);
    memcpy(chain_code_master,
           utils_hex_to_uint8("873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"),
           32);
    u_assert_int_eq(node.fingerprint, 0x00000000);
    u_assert_mem_eq(node.chain_code,  chain_code_master, 32);
    u_assert_mem_eq(node.private_key, private_key_master, 32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"),
                    33);
    hdnode_serialize_private(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    u_assert_mem_eq(&node, &node2, sizeof(HDNode));
    hdnode_serialize_public(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    memcpy(&node3, &node, sizeof(HDNode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(HDNode));


    // [Chain m/0']
    char path0[] = "m/0'";
    wallet_generate_key(&node, path0, strlen(path0), private_key_master, chain_code_master);
    u_assert_int_eq(node.fingerprint, 0x3442193e);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"),
                    33);
    hdnode_serialize_private(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    u_assert_mem_eq(&node, &node2, sizeof(HDNode));
    hdnode_serialize_public(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    memcpy(&node3, &node, sizeof(HDNode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(HDNode));


    // [Chain m/0'/1]
    char path1[] = "m/0'/1";
    wallet_generate_key(&node, path1, strlen(path1), private_key_master, chain_code_master);
    u_assert_int_eq(node.fingerprint, 0x5c1bd648);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"),
                    33);
    hdnode_serialize_private(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    u_assert_mem_eq(&node, &node2, sizeof(HDNode));
    hdnode_serialize_public(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    memcpy(&node3, &node, sizeof(HDNode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(HDNode));

    // [Chain m/0'/1/2']
    char path2[] = "m/0'/1/2'";
    wallet_generate_key(&node, path2, strlen(path2), private_key_master, chain_code_master);
    u_assert_int_eq(node.fingerprint, 0xbef5a2f9);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2"),
                    33);
    hdnode_serialize_private(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    u_assert_mem_eq(&node, &node2, sizeof(HDNode));
    hdnode_serialize_public(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    memcpy(&node3, &node, sizeof(HDNode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(HDNode));

    // [Chain m/0'/1/2'/2]
    char path3[] = "m/0'/1/2'/2";
    wallet_generate_key(&node, path3, strlen(path3), private_key_master, chain_code_master);
    u_assert_int_eq(node.fingerprint, 0xee7ab90c);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29"),
                    33);
    hdnode_serialize_private(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    u_assert_mem_eq(&node, &node2, sizeof(HDNode));
    hdnode_serialize_public(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    memcpy(&node3, &node, sizeof(HDNode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(HDNode));

    // [Chain m/0'/1/2'/2/1000000000]
    char path4[] = "m/0'/1/2'/2/1000000000";
    wallet_generate_key(&node, path4, strlen(path4), private_key_master, chain_code_master);
    u_assert_int_eq(node.fingerprint, 0xd880d7d8);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011"),
                    33);
    hdnode_serialize_private(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    u_assert_mem_eq(&node, &node2, sizeof(HDNode));
    hdnode_serialize_public(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    memcpy(&node3, &node, sizeof(HDNode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(HDNode));
}


// test vector 2 from https://en.bitcoin.it/wiki/BIP_0032_TestVectors
static void test_bip32_vector_2(void)
{
    HDNode node, node2, node3;
    char str[112];
    int r;
    uint8_t private_key_master[32];
    uint8_t chain_code_master[32];

    // init m
    hdnode_from_seed(
        utils_hex_to_uint8("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"),
        64, &node);

    // [Chain m]
    memcpy(private_key_master,
           utils_hex_to_uint8("4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e"),
           32);
    memcpy(chain_code_master,
           utils_hex_to_uint8("60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689"),
           32);
    u_assert_int_eq(node.fingerprint, 0x00000000);
    u_assert_mem_eq(node.chain_code,  chain_code_master, 32);
    u_assert_mem_eq(node.private_key, private_key_master, 32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7"),
                    33);
    hdnode_serialize_private(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    u_assert_mem_eq(&node, &node2, sizeof(HDNode));
    hdnode_serialize_public(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    memcpy(&node3, &node, sizeof(HDNode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(HDNode));

    // [Chain m/0]
    char path0[] = "m/0";
    wallet_generate_key(&node, path0, strlen(path0), private_key_master, chain_code_master);
    u_assert_int_eq(node.fingerprint, 0xbd16bee5);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"),
                    33);
    hdnode_serialize_private(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    u_assert_mem_eq(&node, &node2, sizeof(HDNode));
    hdnode_serialize_public(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    memcpy(&node3, &node, sizeof(HDNode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(HDNode));

    // [Chain m/0/2147483647']
    char path1[] = "m/0/2147483647'";
    wallet_generate_key(&node, path1, strlen(path1), private_key_master, chain_code_master);
    u_assert_int_eq(node.fingerprint, 0x5a61ff8e);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b"),
                    33);
    hdnode_serialize_private(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    u_assert_mem_eq(&node, &node2, sizeof(HDNode));
    hdnode_serialize_public(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    memcpy(&node3, &node, sizeof(HDNode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(HDNode));

    // [Chain m/0/2147483647'/1]
    char path2[] = "m/0/2147483647'/1";
    wallet_generate_key(&node, path2, strlen(path2), private_key_master, chain_code_master);
    u_assert_int_eq(node.fingerprint, 0xd8ab4937);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9"),
                    33);
    hdnode_serialize_private(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    u_assert_mem_eq(&node, &node2, sizeof(HDNode));
    hdnode_serialize_public(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    memcpy(&node3, &node, sizeof(HDNode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(HDNode));

    // [Chain m/0/2147483647'/1/2147483646']
    char path3[] = "m/0/2147483647'/1/2147483646'";
    wallet_generate_key(&node, path3, strlen(path3), private_key_master, chain_code_master);
    u_assert_int_eq(node.fingerprint, 0x78412e3a);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0"),
                    33);
    hdnode_serialize_private(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    u_assert_mem_eq(&node, &node2, sizeof(HDNode));
    hdnode_serialize_public(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    memcpy(&node3, &node, sizeof(HDNode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(HDNode));

    // [Chain m/0/2147483647'/1/2147483646'/2]
    char path4[] = "m/0/2147483647'/1/2147483646'/2";
    wallet_generate_key(&node, path4, strlen(path4), private_key_master, chain_code_master);
    u_assert_int_eq(node.fingerprint, 0x31a507b8);
    u_assert_mem_eq(node.chain_code,
                    utils_hex_to_uint8("9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271"),
                    32);
    u_assert_mem_eq(node.private_key,
                    utils_hex_to_uint8("bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23"),
                    32);
    u_assert_mem_eq(node.public_key,
                    utils_hex_to_uint8("024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"),
                    33);
    hdnode_serialize_private(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    u_assert_mem_eq(&node, &node2, sizeof(HDNode));
    hdnode_serialize_public(&node, str, sizeof(str));
    u_assert_str_eq(str,
                    "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt");
    r = hdnode_deserialize(str, &node2);
    u_assert_int_eq(r, STATUS_SUCCESS);
    memcpy(&node3, &node, sizeof(HDNode));
    memset(&node3.private_key, 0, 32);
    u_assert_mem_eq(&node2, &node3, sizeof(HDNode));

    /*
    // init m
    hdnode_from_seed(utils_hex_to_uint8("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"), 64, &node);

    // test public derivation
    // [Chain m/0]
    r = hdnode_public_ckd(&node, 0);
    u_assert_int_eu_assert_int_eq(r, 1);
    u_assert_int_eq(node.fingerprint, 0xbd16bee5);
    u_assert_mem_eq(node.chain_code,  fromhex("f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c"), 32);
    u_assert_mem_eq(node.private_key, fromhex("0000000000000000000000000000000000000000000000000000000000000000"), 32);
    u_assert_mem_eq(node.public_key,  fromhex("02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea"), 33);
    */
}


#define test_deterministic(KEY, MSG, K) do { \
    sha256_Raw((const uint8_t *)MSG, strlen(MSG), buf); \
    res = generate_k_rfc6979_test(k, utils_hex_to_uint8(KEY), buf); \
    u_assert_int_eq(res, 0); \
    u_assert_mem_eq(k, utils_hex_to_uint8(K), 32); \
} while (0)

static void test_rfc6979(void)
{
    int res;
    uint8_t buf[32];
    uint8_t k[32];

    test_deterministic("cca9fbcc1b41e5a95d369eaa6ddcff73b61a4efaa279cfc6567e8daa39cbaf50",
                       "sample", "2df40ca70e639d89528a6b670d9d48d9165fdc0febc0974056bdce192b8e16a3");
    test_deterministic("0000000000000000000000000000000000000000000000000000000000000001",
                       "Satoshi Nakamoto", "8f8a276c19f4149656b280621e358cce24f5f52542772691ee69063b74f15d15");
    test_deterministic("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                       "Satoshi Nakamoto", "33a19b60e25fb6f4435af53a3d42d493644827367e6453928554f43e49aa6f90");
    test_deterministic("f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181",
                       "Alan Turing", "525a82b70e67874398067543fd84c83d30c175fdc45fdeee082fe13b1d7cfdf1");
    test_deterministic("0000000000000000000000000000000000000000000000000000000000000001",
                       "All those moments will be lost in time, like tears in rain. Time to die...",
                       "38aa22d72376b4dbc472e06c3ba403ee0a394da63fc58d88686c611aba98d6b3");
    test_deterministic("e91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2",
                       "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!",
                       "1f4b84c23a86a221d233f2521be018d9318639d5b8bbd6374a8a59232d16ad3d");
}


static void test_sign_speed(void)
{
    uint8_t sig[64], priv_key[32], msg[256];
    size_t i, N = 250;
    int res;
    for (i = 0; i < sizeof(msg); i++) {
        msg[i] = i * 1103515245;
    }

    clock_t t = clock();

    memcpy(priv_key,
           utils_hex_to_uint8("c55ece858b0ddd5263f96810fe14437cd3b5e1fbd7c6a2ec1e031f05e86d8bd5"),
           32);
    for (i = 0 ; i < N; i++) {
        res = uECC_sign(priv_key, msg, sizeof(msg), sig);
        u_assert_int_eq(res, 0);
    }

    memcpy(priv_key,
           utils_hex_to_uint8("509a0382ff5da48e402967a671bdcde70046d07f0df52cff12e8e3883b426a0a"),
           32);
    for (i = 0 ; i < N; i++) {
        res = uECC_sign(priv_key, msg, sizeof(msg), sig);
        u_assert_int_eq(res, 0);
    }

    printf("  Signing speed: %0.2f sig/s\n", N * 2 / ((float)(clock() - t) / CLOCKS_PER_SEC));
}


static void test_verify_speed(void)
{
    uint8_t sig[64], pub_key33[33], pub_key65[65], msg[256];
    size_t i;
    int res;

    for (i = 0; i < sizeof(msg); i++) {
        msg[i] = i * 1103515245;
    }

    clock_t t = clock();

    memcpy(sig,
           utils_hex_to_uint8("88dc0db6bc5efa762e75fbcc802af69b9f1fcdbdffce748d403f687f855556e610ee8035414099ac7d89cff88a3fa246d332dfa3c78d82c801394112dda039c2"),
           64);
    memcpy(pub_key33,
           utils_hex_to_uint8("024054fd18aeb277aeedea01d3f3986ff4e5be18092a04339dcf4e524e2c0a0974"),
           33);
    memcpy(pub_key65,
           utils_hex_to_uint8("044054fd18aeb277aeedea01d3f3986ff4e5be18092a04339dcf4e524e2c0a09746c7083ed2097011b1223a17a644e81f59aa3de22dac119fd980b36a8ff29a244"),
           65);

    for (i = 0 ; i < 25; i++) {
        res = uECC_verify(pub_key65, sig, msg, sizeof(msg));
        u_assert_int_eq(res, 0);
        res = uECC_verify(pub_key33, sig, msg, sizeof(msg));
        u_assert_int_eq(res, 0);
    }

    memcpy(sig,
           utils_hex_to_uint8("067040a2adb3d9deefeef95dae86f69671968a0b90ee72c2eab54369612fd524eb6756c5a1bb662f1175a5fa888763cddc3a07b8a045ef6ab358d8d5d1a9a745"),
           64);
    memcpy(pub_key33,
           utils_hex_to_uint8("03ff45a5561a76be930358457d113f25fac790794ec70317eff3b97d7080d45719"),
           33);
    memcpy(pub_key65,
           utils_hex_to_uint8("04ff45a5561a76be930358457d113f25fac790794ec70317eff3b97d7080d457196235193a15778062ddaa44aef7e6901b781763e52147f2504e268b2d572bf197"),
           65);

    for (i = 0 ; i < 25; i++) {
        res = uECC_verify(pub_key65, sig, msg, sizeof(msg));
        u_assert_int_eq(res, 0);
        res = uECC_verify(pub_key33, sig, msg, sizeof(msg));
        u_assert_int_eq(res, 0);
    }

    printf("  Verifying speed: %0.2f sig/s\n",
           100.0f / ((float)(clock() - t) / CLOCKS_PER_SEC));
}


// test vectors from http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors
static void test_aes_cbc(void)
{
    aes_context ctx[1];
    uint8_t ibuf[16], obuf[16], iv[16];
    const char **ivp, **plainp, **cipherp;

    static const char *cbc_vector[] = {
        // iv                               plain                               cipher
        "000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a", "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
        "f58c4c04d6e5f1ba779eabfb5f7bfbd6", "ae2d8a571e03ac9c9eb76fac45af8e51", "9cfc4e967edb808d679f777bc6702c7d",
        "9cfc4e967edb808d679f777bc6702c7d", "30c81c46a35ce411e5fbc1191a0a52ef", "39f23369a9d9bacfa530e26304231461",
        "39f23369a9d9bacfa530e26304231461", "f69f2445df4f9b17ad2b417be66c3710", "b2eb05e2c39be9fcda6c19078c6a9d1b",
        0, 0, 0,
    };
    ivp = cbc_vector;
    plainp = cbc_vector + 1;
    cipherp = cbc_vector + 2;
    while (*plainp && *cipherp) {
        memset(ctx, 0, sizeof(ctx));
        aes_set_key(
            utils_hex_to_uint8("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
            32, ctx);

        // encrypt
        memcpy(iv, utils_hex_to_uint8(*ivp), 16);
        memcpy(ibuf, utils_hex_to_uint8(*plainp), 16);
        aes_cbc_encrypt(ibuf, obuf, 1, iv, ctx);
        u_assert_mem_eq(obuf, utils_hex_to_uint8(*cipherp), 16);

        // decrypt
        memcpy(iv, utils_hex_to_uint8(*ivp), 16);
        memcpy(ibuf, utils_hex_to_uint8(*cipherp), 16);
        aes_cbc_decrypt(ibuf, obuf, 1, iv, ctx);
        u_assert_mem_eq(obuf, utils_hex_to_uint8(*plainp), 16);

        ivp += 3;
        plainp += 3;
        cipherp += 3;
    }
}



// test vectors from https://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors
static void test_pbkdf2_hmac_sha256(void)
{
    uint8_t k[40], s[40];

    strcpy((char *)s, "salt");
    pbkdf2_hmac_sha256((const uint8_t *)"password", 8, s, 4, 1, k, 32, 0);
    u_assert_mem_eq(k,
                    utils_hex_to_uint8("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
                    32);

    strcpy((char *)s, "salt");
    pbkdf2_hmac_sha256((const uint8_t *)"password", 8, s, 4, 2, k, 32, 0);
    u_assert_mem_eq(k,
                    utils_hex_to_uint8("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
                    32);

    strcpy((char *)s, "salt");
    pbkdf2_hmac_sha256((const uint8_t *)"password", 8, s, 4, 4096, k, 32, 0);
    u_assert_mem_eq(k,
                    utils_hex_to_uint8("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"),
                    32);

    strcpy((char *)s, "saltSALTsaltSALTsaltSALTsaltSALTsalt");
    pbkdf2_hmac_sha256((const uint8_t *)"passwordPASSWORDpassword", 3 * 8, s, 9 * 4, 4096, k,
                       64,
                       0);
    u_assert_mem_eq(k,
                    utils_hex_to_uint8("348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"),
                    40);
}

// test vectors from http://stackoverflow.com/questions/15593184/pbkdf2-hmac-sha-512-test-vectors
static void test_pbkdf2_hmac_sha512(void)
{
    uint8_t k[64], s[40];

    strcpy((char *)s, "salt");
    pbkdf2_hmac_sha512((const uint8_t *)"password", 8, s, 4, 1, k, 64, 0);
    u_assert_mem_eq(k,
                    utils_hex_to_uint8("867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"),
                    64);

    strcpy((char *)s, "salt");
    pbkdf2_hmac_sha512((const uint8_t *)"password", 8, s, 4, 2, k, 64, 0);
    u_assert_mem_eq(k,
                    utils_hex_to_uint8("e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e"),
                    64);

    strcpy((char *)s, "salt");
    pbkdf2_hmac_sha512((const uint8_t *)"password", 8, s, 4, 4096, k, 64, 0);
    u_assert_mem_eq(k,
                    utils_hex_to_uint8("d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5"),
                    64);

    strcpy((char *)s, "saltSALTsaltSALTsaltSALTsaltSALTsalt");
    pbkdf2_hmac_sha512((const uint8_t *)"passwordPASSWORDpassword", 3 * 8, s, 9 * 4, 4096, k,
                       64,
                       0);
    u_assert_mem_eq(k,
                    utils_hex_to_uint8("8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71115b59f9e60cd9532fa33e0f75aefe30225c583a186cd82bd4daea9724a3d3b8"),
                    64);
}

static void test_mnemonic(void)
{
    static const char *vectors[] = {
        "00000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
        "80808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
        "ffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
        "000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
        "808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
        "ffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
        "8080808080808080808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
        "77c2b00716cec7213839159e404db50d",
        "jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge",
        "b5b6d0127db1a9d2226af0c3346031d77af31e918dba64287a1b44b8ebf63cdd52676f672a290aae502472cf2d602c051f3e6f18055e84e4c43897fc4e51a6ff",
        "b63a9c59a6e641f288ebc103017f1da9f8290b3da6bdef7b",
        "renew stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
        "9248d83e06f4cd98debf5b6f010542760df925ce46cf38a1bdb4e4de7d21f5c39366941c69e1bdbf2966e0f6e6dbece898a0e2f0a4c2b3e640953dfe8b7bbdc5",
        "3e141609b97933b66a060dcddc71fad1d91677db872031e85f4c015c5e7e8982",
        "dignity pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
        "ff7f3184df8696d8bef94b6c03114dbee0ef89ff938712301d27ed8336ca89ef9635da20af07d4175f2bf5f3de130f39c9d9e8dd0472489c19b1a020a940da67",
        "0460ef47585604c5660618db2e6a7e7f",
        "afford alter spike radar gate glance object seek swamp infant panel yellow",
        "65f93a9f36b6c85cbe634ffc1f99f2b82cbb10b31edc7f087b4f6cb9e976e9faf76ff41f8f27c99afdf38f7a303ba1136ee48a4c1e7fcd3dba7aa876113a36e4",
        "72f60ebac5dd8add8d2a25a797102c3ce21bc029c200076f",
        "indicate race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
        "3bbf9daa0dfad8229786ace5ddb4e00fa98a044ae4c4975ffd5e094dba9e0bb289349dbe2091761f30f382d4e35c4a670ee8ab50758d2c55881be69e327117ba",
        "2c85efc7f24ee4573d2b81a6ec66cee209b2dcbd09d8eddc51e0215b0b68e416",
        "clutch control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
        "fe908f96f46668b2d5b37d82f558c77ed0d69dd0e7e043a5b0511c48c2f1064694a956f86360c93dd04052a8899497ce9e985ebe0c8c52b955e6ae86d4ff4449",
        "eaebabb2383351fd31d703840b32e9e2",
        "turtle front uncle idea crush write shrug there lottery flower risk shell",
        "bdfb76a0759f301b0b899a1e3985227e53b3f51e67e3f2a65363caedf3e32fde42a66c404f18d7b05818c95ef3ca1e5146646856c461c073169467511680876c",
        "7ac45cfe7722ee6c7ba84fbc2d5bd61b45cb2fe5eb65aa78",
        "kiss carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
        "ed56ff6c833c07982eb7119a8f48fd363c4a9b1601cd2de736b01045c5eb8ab4f57b079403485d1c4924f0790dc10a971763337cb9f9c62226f64fff26397c79",
        "4fa1a8bc3e6d80ee1316050e862c1812031493212b7ec3f3bb1b08f168cabeef",
        "exile ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
        "095ee6f817b4c2cb30a5a797360a81a40ab0f9a4e25ecd672a3f58a0b5ba0687c096a6b14d2c0deb3bdefce4f61d01ae07417d502429352e27695163f7447a8c",
        "18ab19a9f54a9274f03e5209a2ac8a91",
        "board flee heavy tunnel powder denial science ski answer betray cargo cat",
        "6eff1bb21562918509c73cb990260db07c0ce34ff0e3cc4a8cb3276129fbcb300bddfe005831350efd633909f476c45c88253276d9fd0df6ef48609e8bb7dca8",
        "18a2e1d81b8ecfb2a333adcb0c17a5b9eb76cc5d05db91a4",
        "board blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
        "f84521c777a13b61564234bf8f8b62b3afce27fc4062b51bb5e62bdfecb23864ee6ecf07c1d5a97c0834307c5c852d8ceb88e7c97923c0a3b496bedd4e5f88a9",
        "15da872c95a13dd738fbf50e427583ad61f18fd99f628c417a61cf8343c90419",
        "beyond stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
        "b15509eaa2d09d3efd3e006ef42151b30367dc6e3aa5e44caba3fe4d3e352e65101fbdb86a96776b91946ff06f8eac594dc6ee1d3e82a42dfe1b40fef6bcc3fd",
        0,
        0,
        0,
    };

    const char **a, **b, **c, *m;
    uint8_t seed[64];

    a = vectors;
    b = vectors + 1;
    c = vectors + 2;
    while (*a && *b && *c) {
        m = wallet_mnemonic_from_data(utils_hex_to_uint8(*a), strlen(*a) / 2);
        u_assert_str_eq(m, *b);
        wallet_mnemonic_to_seed(m, "TREZOR", seed, 0);
        u_assert_mem_eq(seed, utils_hex_to_uint8(*c), strlen(*c) / 2);
        u_assert_str_eq(wallet_mnemonic_from_index(wallet_index_from_mnemonic(*b)), *b);
        a += 3;
        b += 3;
        c += 3;
    }
}


static void test_mnemonic_check(void)
{
    static const char *vectors_ok[] = {
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge",
        "renew stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
        "dignity pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
        "afford alter spike radar gate glance object seek swamp infant panel yellow",
        "indicate race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
        "clutch control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
        "turtle front uncle idea crush write shrug there lottery flower risk shell",
        "kiss carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
        "exile ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
        "board flee heavy tunnel powder denial science ski answer betray cargo cat",
        "board blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
        "beyond stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
        0,
    };
    static const char *vectors_fail[] = {
        "above abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "above winner thank year wave sausage worth useful legal winner thank yellow",
        "above advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "above zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "above abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "above winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        "above advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        "above zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "above abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "above winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "above advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "above zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "above better achieve collect unaware mountain thought cargo oxygen act hood bridge",
        "above stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
        "above pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
        "above alter spike radar gate glance object seek swamp infant panel yellow",
        "above race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
        "above control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
        "above front uncle idea crush write shrug there lottery flower risk shell",
        "above carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
        "above ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
        "above flee heavy tunnel powder denial science ski answer betray cargo cat",
        "above blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
        "above stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "winner thank year wave sausage worth useful legal winner thank yellow",
        "advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        "advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "better achieve collect unaware mountain thought cargo oxygen act hood bridge",
        "stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
        "pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
        "alter spike radar gate glance object seek swamp infant panel yellow",
        "race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
        "control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
        "front uncle idea crush write shrug there lottery flower risk shell",
        "carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
        "ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
        "flee heavy tunnel powder denial science ski answer betray cargo cat",
        "blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
        "stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
        0,
    };

    const char **m;
    int r;
    m = vectors_ok;
    while (*m) {
        r = wallet_mnemonic_check(*m);
        u_assert_int_eq(r, STATUS_SUCCESS);
        m++;
    }
    m = vectors_fail;
    while (*m) {
        r = wallet_mnemonic_check(*m);
        u_assert_int_eq(r, STATUS_ERROR);
        m++;
    }
}


static void test_address(void)
{
    char address[36];
    uint8_t pub_key[65];

    memcpy(pub_key,
           utils_hex_to_uint8("0226659c1cf7321c178c07437150639ff0c5b7679c7ea195253ed9abda2e081a37"),
           33);
    wallet_get_address(pub_key,   0, address, sizeof(address));
    u_assert_str_eq(address, "139MaMHp3Vjo8o4x8N1ZLWEtovLGvBsg6s");
    wallet_get_address(pub_key, 111, address, sizeof(address));
    u_assert_str_eq(address, "mhfJsQNnrXB3uuYZqvywARTDfuvyjg4RBh");
    wallet_get_address(pub_key,  52, address, sizeof(address));
    u_assert_str_eq(address, "MxiimznnxsqMfLKTQBL8Z2PoY9jKpjgkCu");
    wallet_get_address(pub_key,  48, address, sizeof(address));
    u_assert_str_eq(address, "LMNJqZbe89yrPbm7JVzrcXJf28hZ1rKPaH");

    memcpy(pub_key,
           utils_hex_to_uint8("025b1654a0e78d28810094f6c5a96b8efb8a65668b578f170ac2b1f83bc63ba856"),
           33);
    wallet_get_address(pub_key,   0, address, sizeof(address));
    u_assert_str_eq(address, "19Ywfm3witp6C1yBMy4NRYHY2347WCRBfQ");
    wallet_get_address(pub_key, 111, address, sizeof(address));
    u_assert_str_eq(address, "mp4txp8vXvFLy8So5Y2kFTVrt2epN6YzdP");
    wallet_get_address(pub_key,  52, address, sizeof(address));
    u_assert_str_eq(address, "N58JsQYveGueiZDgdnNwe4SSkGTAToutAY");
    wallet_get_address(pub_key,  48, address, sizeof(address));
    u_assert_str_eq(address, "LTmtvyMmoZ49SpfLY73fhZMJEFRPdyohKh");

    memcpy(pub_key,
           utils_hex_to_uint8("03433f246a12e6486a51ff08802228c61cf895175a9b49ed4766ea9a9294a3c7fe"),
           33);
    wallet_get_address(pub_key,   0, address, sizeof(address));
    u_assert_str_eq(address, "1FWE2bn3MWhc4QidcF6AvEWpK77sSi2cAP");
    wallet_get_address(pub_key, 111, address, sizeof(address));
    u_assert_str_eq(address, "mv2BKes2AY8rqXCFKp4Yk9j9B6iaMfWRLN");
    wallet_get_address(pub_key,  52, address, sizeof(address));
    u_assert_str_eq(address, "NB5bEFH2GtoAawy8t4Qk8kfj3LWvQs3MhB");
    wallet_get_address(pub_key,  48, address, sizeof(address));
    u_assert_str_eq(address, "LZjBHp5sSAwfKDQnnP5UCFaaXKV9YheGxQ");

    memcpy(pub_key,
           utils_hex_to_uint8("03aeb03abeee0f0f8b4f7a5d65ce31f9570cef9f72c2dd8a19b4085a30ab033d48"),
           33);
    wallet_get_address(pub_key,   0, address, sizeof(address));
    u_assert_str_eq(address, "1yrZb8dhdevoqpUEGi2tUccUEeiMKeLcs");
    wallet_get_address(pub_key, 111, address, sizeof(address));
    u_assert_str_eq(address, "mgVoreDcWf6BaxJ5wqgQiPpwLEFRLSr8U8");
    wallet_get_address(pub_key,  52, address, sizeof(address));
    u_assert_str_eq(address, "MwZDmEdcd1kVLP4yW62c6zmXCU3mNbveDo");
    wallet_get_address(pub_key,  48, address, sizeof(address));
    u_assert_str_eq(address, "LLCopoSTnHtz4eWdQQhLAVgNgT1zTi4QBK");

    memcpy(pub_key,
           utils_hex_to_uint8("0496e8f2093f018aff6c2e2da5201ee528e2c8accbf9cac51563d33a7bb74a016054201c025e2a5d96b1629b95194e806c63eb96facaedc733b1a4b70ab3b33e3a"),
           65);
    wallet_get_address(pub_key,   0, address, sizeof(address));
    u_assert_str_eq(address, "194SZbL75xCCGBbKtMsyWLE5r9s2V6mhVM");
    wallet_get_address(pub_key, 111, address, sizeof(address));
    u_assert_str_eq(address, "moaPreR5tydT3J4wbvrMLFSQi9TjPCiZc6");
    wallet_get_address(pub_key,  52, address, sizeof(address));
    u_assert_str_eq(address, "N4domEq61LHkniqqABCYirNzaPG5NRU8GH");
    wallet_get_address(pub_key,  48, address, sizeof(address));
    u_assert_str_eq(address, "LTHPpodwAcSFWzHV4VsGnMHr4NEJajMnKX");

    memcpy(pub_key,
           utils_hex_to_uint8("0498010f8a687439ff497d3074beb4519754e72c4b6220fb669224749591dde416f3961f8ece18f8689bb32235e436874d2174048b86118a00afbd5a4f33a24f0f"),
           65);
    wallet_get_address(pub_key,   0, address, sizeof(address));
    u_assert_str_eq(address, "1A2WfBD4BJFwYHFPc5KgktqtbdJLBuVKc4");
    wallet_get_address(pub_key, 111, address, sizeof(address));
    u_assert_str_eq(address, "mpYTxEJ2zKhCKPj1KeJ4ap4DTcu39T3uzD");
    wallet_get_address(pub_key,  52, address, sizeof(address));
    u_assert_str_eq(address, "N5bsrpi36gMW4pVtsteFyQzoKrhPE7nkxK");
    wallet_get_address(pub_key,  48, address, sizeof(address));
    u_assert_str_eq(address, "LUFTvPWtFxVzo5wYnDJz2uueoqfcMYiuxH");

    memcpy(pub_key,
           utils_hex_to_uint8("04f80490839af36d13701ec3f9eebdac901b51c362119d74553a3c537faff31b17e2a59ebddbdac9e87b816307a7ed5b826b8f40b92719086238e1bebf19b77a4d"),
           65);
    wallet_get_address(pub_key,   0, address, sizeof(address));
    u_assert_str_eq(address, "19J81hrPnQxg9UGx45ibTieCkb2ttm8CLL");
    wallet_get_address(pub_key, 111, address, sizeof(address));
    u_assert_str_eq(address, "mop5JkwNbSPvvakZmegyHdrXcadbjLazww");
    wallet_get_address(pub_key,  52, address, sizeof(address));
    u_assert_str_eq(address, "N4sVDMMNho4Eg1XTKu3AgEo7UpRwq3aNbn");
    wallet_get_address(pub_key,  48, address, sizeof(address));
    u_assert_str_eq(address, "LTX5GvADs5CjQGy7EDhtjjhxxoQB2Uhicd");
}


static void test_wif(void)
{
    uint8_t priv_key[32];
    char wif[53];

    memcpy(priv_key,
           utils_hex_to_uint8("1111111111111111111111111111111111111111111111111111111111111111"),
           32);
    wallet_get_wif(priv_key, 0x80, wif, sizeof(wif));
    u_assert_str_eq(wif, "KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp");
    wallet_get_wif(priv_key, 0xEF, wif, sizeof(wif));
    u_assert_str_eq(wif, "cN9spWsvaxA8taS7DFMxnk1yJD2gaF2PX1npuTpy3vuZFJdwavaw");

    memcpy(priv_key,
           utils_hex_to_uint8("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
           32);
    wallet_get_wif(priv_key, 0x80, wif, sizeof(wif));
    u_assert_str_eq(wif, "L4ezQvyC6QoBhxB4GVs9fAPhUKtbaXYUn8YTqoeXwbevQq4U92vN");
    wallet_get_wif(priv_key, 0xEF, wif, sizeof(wif));
    u_assert_str_eq(wif, "cV1ysqy3XUVSsPeKeugH2Utm6ZC1EyeArAgvxE73SiJvfa6AJng7");

    memcpy(priv_key,
           utils_hex_to_uint8("47f7616ea6f9b923076625b4488115de1ef1187f760e65f89eb6f4f7ff04b012"),
           32);
    wallet_get_wif(priv_key, 0x80, wif, sizeof(wif));
    u_assert_str_eq(wif, "KydbzBtk6uc7M6dXwEgTEH2sphZxSPbmDSz6kUUHi4eUpSQuhEbq");
    wallet_get_wif(priv_key, 0xEF, wif, sizeof(wif));
    u_assert_str_eq(wif, "cPzbT6tbXyJNWY6oKeVabbXwSvsN6qhTHV8ZrtvoDBJV5BRY1G5Q");
}


// from https://github.com/bitcoin/bitcoin/blob/master/src/test/data/base58_keys_valid.json
static void test_base58(void)
{
    static const char *base58_vector[] = {
        "0065a16059864a2fdbc7c99a4723a8395bc6f188eb", "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
        "0574f209f6ea907e2ea48f74fae05782ae8a665257", "3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou",
        "6f53c0307d6851aa0ce7825ba883c6bd9ad242b486", "mo9ncXisMeAoXwqcV5EWuyncbmCcQN4rVs",
        "c46349a418fc4578d10a372b54b45c280cc8c4382f", "2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br",
        "80eddbdc1168f1daeadbd3e44c1e3f8f5a284c2029f78ad26af98583a499de5b19", "5Kd3NBUAdUnhyzenEwVLy9pBKxSwXvE9FMPyR4UKZvpe6E3AgLr",
        "8055c9bccb9ed68446d1b75273bbce89d7fe013a8acd1625514420fb2aca1a21c401", "Kz6UJmQACJmLtaQj5A3JAge4kVTNQ8gbvXuwbmCj7bsaabudb3RD",
        "ef36cb93b9ab1bdabf7fb9f2c04f1b9cc879933530ae7842398eef5a63a56800c2", "9213qJab2HNEpMpYNBa7wHGFKKbkDn24jpANDs2huN3yi4J11ko",
        "efb9f4892c9e8282028fea1d2667c4dc5213564d41fc5783896a0d843fc15089f301", "cTpB4YiyKiBcPxnefsDpbnDxFDffjqJob8wGCEDXxgQ7zQoMXJdH",
        "006d23156cbbdcc82a5a47eee4c2c7c583c18b6bf4", "1Ax4gZtb7gAit2TivwejZHYtNNLT18PUXJ",
        "05fcc5460dd6e2487c7d75b1963625da0e8f4c5975", "3QjYXhTkvuj8qPaXHTTWb5wjXhdsLAAWVy",
        "6ff1d470f9b02370fdec2e6b708b08ac431bf7a5f7", "n3ZddxzLvAY9o7184TB4c6FJasAybsw4HZ",
        "c4c579342c2c4c9220205e2cdc285617040c924a0a", "2NBFNJTktNa7GZusGbDbGKRZTxdK9VVez3n",
        "80a326b95ebae30164217d7a7f57d72ab2b54e3be64928a19da0210b9568d4015e", "5K494XZwps2bGyeL71pWid4noiSNA2cfCibrvRWqcHSptoFn7rc",
        "807d998b45c219a1e38e99e7cbd312ef67f77a455a9b50c730c27f02c6f730dfb401", "L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi",
        "efd6bca256b5abc5602ec2e1c121a08b0da2556587430bcf7e1898af2224885203", "93DVKyFYwSN6wEo3E2fCrFPUp17FtrtNi2Lf7n4G3garFb16CRj",
        "efa81ca4e8f90181ec4b61b6a7eb998af17b2cb04de8a03b504b9e34c4c61db7d901", "cTDVKtMGVYWTHCb1AFjmVbEbWjvKpKqKgMaR3QJxToMSQAhmCeTN",
        "007987ccaa53d02c8873487ef919677cd3db7a6912", "1C5bSj1iEGUgSTbziymG7Cn18ENQuT36vv",
        "0563bcc565f9e68ee0189dd5cc67f1b0e5f02f45cb", "3AnNxabYGoTxYiTEZwFEnerUoeFXK2Zoks",
        "6fef66444b5b17f14e8fae6e7e19b045a78c54fd79", "n3LnJXCqbPjghuVs8ph9CYsAe4Sh4j97wk",
        "c4c3e55fceceaa4391ed2a9677f4a4d34eacd021a0", "2NB72XtkjpnATMggui83aEtPawyyKvnbX2o",
        "80e75d936d56377f432f404aabb406601f892fd49da90eb6ac558a733c93b47252", "5KaBW9vNtWNhc3ZEDyNCiXLPdVPHCikRxSBWwV9NrpLLa4LsXi9",
        "808248bd0375f2f75d7e274ae544fb920f51784480866b102384190b1addfbaa5c01", "L1axzbSyynNYA8mCAhzxkipKkfHtAXYF4YQnhSKcLV8YXA874fgT",
        "ef44c4f6a096eac5238291a94cc24c01e3b19b8d8cef72874a079e00a242237a52", "927CnUkUbasYtDwYwVn2j8GdTuACNnKkjZ1rpZd2yBB1CLcnXpo",
        "efd1de707020a9059d6d3abaf85e17967c6555151143db13dbb06db78df0f15c6901", "cUcfCMRjiQf85YMzzQEk9d1s5A4K7xL5SmBCLrezqXFuTVefyhY7",
        "00adc1cc2081a27206fae25792f28bbc55b831549d", "1Gqk4Tv79P91Cc1STQtU3s1W6277M2CVWu",
        "05188f91a931947eddd7432d6e614387e32b244709", "33vt8ViH5jsr115AGkW6cEmEz9MpvJSwDk",
        "6f1694f5bc1a7295b600f40018a618a6ea48eeb498", "mhaMcBxNh5cqXm4aTQ6EcVbKtfL6LGyK2H",
        "c43b9b3fd7a50d4f08d1a5b0f62f644fa7115ae2f3", "2MxgPqX1iThW3oZVk9KoFcE5M4JpiETssVN",
        "80091035445ef105fa1bb125eccfb1882f3fe69592265956ade751fd095033d8d0", "5HtH6GdcwCJA4ggWEL1B3jzBBUB8HPiBi9SBc5h9i4Wk4PSeApR",
        "80ab2b4bcdfc91d34dee0ae2a8c6b6668dadaeb3a88b9859743156f462325187af01", "L2xSYmMeVo3Zek3ZTsv9xUrXVAmrWxJ8Ua4cw8pkfbQhcEFhkXT8",
        "efb4204389cef18bbe2b353623cbf93e8678fbc92a475b664ae98ed594e6cf0856", "92xFEve1Z9N8Z641KQQS7ByCSb8kGjsDzw6fAmjHN1LZGKQXyMq",
        "efe7b230133f1b5489843260236b06edca25f66adb1be455fbd38d4010d48faeef01", "cVM65tdYu1YK37tNoAyGoJTR13VBYFva1vg9FLuPAsJijGvG6NEA",
        "00c4c1b72491ede1eedaca00618407ee0b772cad0d", "1JwMWBVLtiqtscbaRHai4pqHokhFCbtoB4",
        "05f6fe69bcb548a829cce4c57bf6fff8af3a5981f9", "3QCzvfL4ZRvmJFiWWBVwxfdaNBT8EtxB5y",
        "6f261f83568a098a8638844bd7aeca039d5f2352c0", "mizXiucXRCsEriQCHUkCqef9ph9qtPbZZ6",
        "c4e930e1834a4d234702773951d627cce82fbb5d2e", "2NEWDzHWwY5ZZp8CQWbB7ouNMLqCia6YRda",
        "80d1fab7ab7385ad26872237f1eb9789aa25cc986bacc695e07ac571d6cdac8bc0", "5KQmDryMNDcisTzRp3zEq9e4awRmJrEVU1j5vFRTKpRNYPqYrMg",
        "80b0bbede33ef254e8376aceb1510253fc3550efd0fcf84dcd0c9998b288f166b301", "L39Fy7AC2Hhj95gh3Yb2AU5YHh1mQSAHgpNixvm27poizcJyLtUi",
        "ef037f4192c630f399d9271e26c575269b1d15be553ea1a7217f0cb8513cef41cb", "91cTVUcgydqyZLgaANpf1fvL55FH53QMm4BsnCADVNYuWuqdVys",
        "ef6251e205e8ad508bab5596bee086ef16cd4b239e0cc0c5d7c4e6035441e7d5de01", "cQspfSzsgLeiJGB2u8vrAiWpCU4MxUT6JseWo2SjXy4Qbzn2fwDw",
        "005eadaf9bb7121f0f192561a5a62f5e5f54210292", "19dcawoKcZdQz365WpXWMhX6QCUpR9SY4r",
        "053f210e7277c899c3a155cc1c90f4106cbddeec6e", "37Sp6Rv3y4kVd1nQ1JV5pfqXccHNyZm1x3",
        "6fc8a3c2a09a298592c3e180f02487cd91ba3400b5", "myoqcgYiehufrsnnkqdqbp69dddVDMopJu",
        "c499b31df7c9068d1481b596578ddbb4d3bd90baeb", "2N7FuwuUuoTBrDFdrAZ9KxBmtqMLxce9i1C",
        "80c7666842503db6dc6ea061f092cfb9c388448629a6fe868d068c42a488b478ae", "5KL6zEaMtPRXZKo1bbMq7JDjjo1bJuQcsgL33je3oY8uSJCR5b4",
        "8007f0803fc5399e773555ab1e8939907e9badacc17ca129e67a2f5f2ff84351dd01", "KwV9KAfwbwt51veZWNscRTeZs9CKpojyu1MsPnaKTF5kz69H1UN2",
        "efea577acfb5d1d14d3b7b195c321566f12f87d2b77ea3a53f68df7ebf8604a801", "93N87D6uxSBzwXvpokpzg8FFmfQPmvX4xHoWQe3pLdYpbiwT5YV",
        "ef0b3b34f0958d8a268193a9814da92c3e8b58b4a4378a542863e34ac289cd830c01", "cMxXusSihaX58wpJ3tNuuUcZEQGt6DKJ1wEpxys88FFaQCYjku9h",
        "001ed467017f043e91ed4c44b4e8dd674db211c4e6", "13p1ijLwsnrcuyqcTvJXkq2ASdXqcnEBLE",
        "055ece0cadddc415b1980f001785947120acdb36fc", "3ALJH9Y951VCGcVZYAdpA3KchoP9McEj1G",
        0, 0,
    };
    const char **raw = base58_vector;
    const char **str = base58_vector + 1;
    uint8_t rawn[34];
    char strn[53];
    while (*raw && *str) {
        int len = strlen(*raw) / 2;

        memcpy(rawn, utils_hex_to_uint8(*raw), len);
        int r = base58_encode_check(rawn, len, strn, sizeof(strn));
        u_assert_int_eq(r, strlen(*str) + 1);
        u_assert_str_eq(strn, *str);

        r = base58_decode_check(strn, rawn, len);
        u_assert_int_eq(r, len);
        u_assert_mem_eq(rawn,  utils_hex_to_uint8(*raw), len);

        raw += 2;
        str += 2;
    }
}


// test vectors from:
// https://tools.ietf.org/html/rfc4648
// https://commons.apache.org/proper/commons-codec/xref-test/org/apache/commons/codec/binary/Base64Test.html
static void test_base64(void)
{
    const char **plainp, **base64p;
    static const char *base64_vector[] = {
        // plain    base64
        "",         "",
        "f",        "Zg==",
        "fo",       "Zm8=",
        "foo",      "Zm9v",
        "foob",     "Zm9vYg==",
        "fooba",    "Zm9vYmE=",
        "foobar",   "Zm9vYmFy",
        "The quick brown fox jumped over the lazy dogs.", "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wZWQgb3ZlciB0aGUgbGF6eSBkb2dzLg==",
        "It was the best of times, it was the worst of times.", "SXQgd2FzIHRoZSBiZXN0IG9mIHRpbWVzLCBpdCB3YXMgdGhlIHdvcnN0IG9mIHRpbWVzLg==",
        "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz", "QWFCYkNjRGRFZUZmR2dIaElpSmpLa0xsTW1Obk9vUHBRcVJyU3NUdFV1VnZXd1h4WXlaeg==",
        "{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }", "eyAwLCAxLCAyLCAzLCA0LCA1LCA2LCA3LCA4LCA5IH0=",
        "xyzzy!",   "eHl6enkh",
        0, 0,
    };
    plainp = base64_vector;
    base64p = base64_vector + 1;
    while (*plainp && *base64p) {
        // encode
        int b64len;
        char *b64 = base64(*plainp, strlen(*plainp), &b64len);
        u_assert_mem_eq(b64, *base64p, b64len);
        free(b64);

        // decode
        int ub64len;
        unsigned char *ub64 = unbase64(*base64p, strlen(*base64p), &ub64len);
        u_assert_mem_eq(ub64, *plainp, ub64len);
        free(ub64);

        plainp += 2;
        base64p += 2;
    }
}


static void test_commander_static_functions(void)
{
    u_assert_int_eq(commander_test_static_functions(), 0);
}

static void test_checkkey(void)
{
	const char mnemo[] = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
	int suc = wallet_master_from_mnemonic((char *)&mnemo, strlen(mnemo), NULL, 0);
	u_assert_int_eq(suc, STATUS_SUCCESS);
	suc = wallet_check_pubkey("e1b311d4dc2ef8fc4eb7c18f6f14de56a2ab7855", "m/0'/1'", 7);
	u_assert_int_eq(suc, STATUS_KEY_PRESENT);
}

int main(void)
{
    u_run_test(test_sign_speed);
    u_run_test(test_verify_speed);
    u_run_test(test_bip32_vector_1);
    u_run_test(test_bip32_vector_2);
    u_run_test(test_base58);
    u_run_test(test_base64);
    u_run_test(test_rfc6979);
    u_run_test(test_address);
    u_run_test(test_wif);
    u_run_test(test_aes_cbc);
    u_run_test(test_pbkdf2_hmac_sha256);
    u_run_test(test_pbkdf2_hmac_sha512);
    u_run_test(test_mnemonic);
    u_run_test(test_mnemonic_check);
    u_run_test(test_commander_static_functions);
	
	
	u_run_test(test_checkkey);


    if (!U_TESTS_FAIL) {
        printf("\nALL %i TESTS PASSED\n\n", U_TESTS_RUN);
    }

    return U_TESTS_FAIL;
}


