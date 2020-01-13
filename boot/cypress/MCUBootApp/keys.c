/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
*/

#include <bootutil/sign_key.h>
#include <mcuboot_config/mcuboot_config.h>

#if defined(MCUBOOT_SIGN_RSA)
const unsigned char rsa_pub_key[] = {
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xd1, 0x06, 0x08,
    0x1a, 0x18, 0x44, 0x2c, 0x18, 0xe8, 0xfb, 0xfd, 0xf7, 0x0d, 0xa3, 0x4f,
    0x1f, 0xbb, 0xee, 0x5e, 0xf9, 0xaa, 0xd2, 0x4b, 0x18, 0xd3, 0x5a, 0xe9,
    0x6d, 0x18, 0x80, 0x19, 0xf9, 0xf0, 0x9c, 0x34, 0x1b, 0xcb, 0xf3, 0xbc,
    0x74, 0xdb, 0x42, 0xe7, 0x8c, 0x7f, 0x10, 0x53, 0x7e, 0x43, 0x5e, 0x0d,
    0x57, 0x2c, 0x44, 0xd1, 0x67, 0x08, 0x0f, 0x0d, 0xbb, 0x5c, 0xee, 0xec,
    0xb3, 0x99, 0xdf, 0xe0, 0x4d, 0x84, 0x0b, 0xaa, 0x77, 0x41, 0x60, 0xed,
    0x15, 0x28, 0x49, 0xa7, 0x01, 0xb4, 0x3c, 0x10, 0xe6, 0x69, 0x8c, 0x2f,
    0x5f, 0xac, 0x41, 0x4d, 0x9e, 0x5c, 0x14, 0xdf, 0xf2, 0xf8, 0xcf, 0x3d,
    0x1e, 0x6f, 0xe7, 0x5b, 0xba, 0xb4, 0xa9, 0xc8, 0x88, 0x7e, 0x47, 0x3c,
    0x94, 0xc3, 0x77, 0x67, 0x54, 0x4b, 0xaa, 0x8d, 0x38, 0x35, 0xca, 0x62,
    0x61, 0x7e, 0xb7, 0xe1, 0x15, 0xdb, 0x77, 0x73, 0xd4, 0xbe, 0x7b, 0x72,
    0x21, 0x89, 0x69, 0x24, 0xfb, 0xf8, 0x65, 0x6e, 0x64, 0x3e, 0xc8, 0x0e,
    0xd7, 0x85, 0xd5, 0x5c, 0x4a, 0xe4, 0x53, 0x0d, 0x2f, 0xff, 0xb7, 0xfd,
    0xf3, 0x13, 0x39, 0x83, 0x3f, 0xa3, 0xae, 0xd2, 0x0f, 0xa7, 0x6a, 0x9d,
    0xf9, 0xfe, 0xb8, 0xce, 0xfa, 0x2a, 0xbe, 0xaf, 0xb8, 0xe0, 0xfa, 0x82,
    0x37, 0x54, 0xf4, 0x3e, 0xe1, 0x2b, 0xd0, 0xd3, 0x08, 0x58, 0x18, 0xf6,
    0x5e, 0x4c, 0xc8, 0x88, 0x81, 0x31, 0xad, 0x5f, 0xb0, 0x82, 0x17, 0xf2,
    0x8a, 0x69, 0x27, 0x23, 0xf3, 0xab, 0x87, 0x3e, 0x93, 0x1a, 0x1d, 0xfe,
    0xe8, 0xf8, 0x1a, 0x24, 0x66, 0x59, 0xf8, 0x1c, 0xab, 0xdc, 0xce, 0x68,
    0x1b, 0x66, 0x64, 0x35, 0xec, 0xfa, 0x0d, 0x11, 0x9d, 0xaf, 0x5c, 0x3a,
    0xa7, 0xd1, 0x67, 0xc6, 0x47, 0xef, 0xb1, 0x4b, 0x2c, 0x62, 0xe1, 0xd1,
    0xc9, 0x02, 0x03, 0x01, 0x00, 0x01
};
const unsigned int rsa_pub_key_len = 270;
#elif defined(MCUBOOT_SIGN_EC)
/* Format of PEM :
 * -----BEGIN PUBLIC KEY-----
 * base64encode(DER)
 * -----END PUBLIC KEY----- */
#if defined(ECC224_KEY_FILE)
#include ECC224_KEY_FILE
#else
#warning "Used default ECC224 ecdsa_pub_key"
/* It is OEM_PUB_KEY at this moment for debug purposes */
/* Autogenerated by imgtool.py, do not edit. */
const unsigned char ecdsa_pub_key[] = {
    0x30, 0x4e, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x21, 0x03, 0x3a, 0x00, 0x04,
    0xa5, 0x8b, 0x18, 0xa4, 0x60, 0x37, 0xf7, 0x0d,
    0x2b, 0x06, 0xba, 0x4b, 0x4c, 0xd7, 0x8d, 0xec,
    0x2a, 0x32, 0x5a, 0x0e, 0x52, 0xf4, 0x1b, 0x7c,
    0x99, 0xec, 0x68, 0x5d, 0x05, 0xc3, 0x6b, 0x7b,
    0x40, 0x9c, 0xaa, 0xac, 0x90, 0xf4, 0xfc, 0xbe,
    0x98, 0xe5, 0x3e, 0x86, 0x3d, 0x37, 0xbf, 0x45,
    0x78, 0x92, 0x27, 0xca, 0x69, 0xe6, 0xf2, 0xc5,
};
const unsigned int ecdsa_pub_key_len = 80;
#endif
#elif defined(MCUBOOT_SIGN_EC256)
/* Format of PEM :
 * -----BEGIN PUBLIC KEY-----
 * base64encode(DER)
 * -----END PUBLIC KEY----- */
#if defined(ECC256_KEY_FILE)
#include ECC256_KEY_FILE
#else
#warning "Used default ECC256 ecdsa_pub_key"
/* It is OEM_PUB_KEY at this moment for debug purposes */
const unsigned char ecdsa_pub_key[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04, 0xbd, 0x59, 0x9d, 0x15, 0xe0,
    0xff, 0x66, 0x12, 0x37, 0x28, 0xdf, 0x50, 0x38,
    0xb1, 0x9a, 0x73, 0x9b, 0xbd, 0xd1, 0xb3, 0x8a,
    0x6f, 0xd2, 0x70, 0xed, 0x7f, 0xdb, 0x57, 0x53,
    0xde, 0x9e, 0x77, 0x0f, 0x9c, 0x17, 0x22, 0x69,
    0xa6, 0x75, 0x48, 0x1f, 0xa4, 0xbc, 0x49, 0xe2,
    0x01, 0xe0, 0x5e, 0x3d, 0xec, 0xa8, 0xc1, 0xca,
    0xc5, 0x5c, 0xa2, 0xc6, 0xfd, 0xb0, 0x24, 0xb1,
    0x0a, 0x46, 0xf5,
};
const unsigned int ecdsa_pub_key_len = 91;
#endif
#else
#warning "No public key available for given signing algorithm."
#endif

#if defined(MCUBOOT_SIGN_RSA) || \
    defined(MCUBOOT_SIGN_EC) || \
    defined(MCUBOOT_SIGN_EC256)
const struct bootutil_key bootutil_keys[] = {
#if defined(MCUBOOT_SIGN_RSA)
    {
        .key = rsa_pub_key,
        .len = &rsa_pub_key_len,
    },
#elif defined(MCUBOOT_SIGN_EC) || \
    defined(MCUBOOT_SIGN_EC256)
    {
        .key = ecdsa_pub_key,
        .len = &ecdsa_pub_key_len,
    },
#else
    {
        .key = NULL,
        .len = 0x00,
    },
#endif
};
const int bootutil_key_cnt = 1;
#endif

unsigned char enc_priv_key[] = {
  0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
  0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
  0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
  0xf6, 0x1e, 0x51, 0x9d, 0xf8, 0xfa, 0xdd, 0xa1, 0xb7, 0xd9, 0xa9, 0x64,
  0x64, 0x3b, 0x54, 0xd0, 0x3d, 0xd0, 0x1f, 0xe5, 0x78, 0xd9, 0x17, 0x98,
  0xa5, 0x28, 0xca, 0xcc, 0x6b, 0x67, 0x9e, 0x06, 0xa1, 0x44, 0x03, 0x42,
  0x00, 0x04, 0x8a, 0x44, 0x73, 0x00, 0x94, 0xc9, 0x80, 0x27, 0x31, 0x0d,
  0x23, 0x36, 0x6b, 0xe9, 0x69, 0x9f, 0xcb, 0xc5, 0x7c, 0xc8, 0x44, 0x1a,
  0x93, 0xe6, 0xee, 0x7d, 0x86, 0xa6, 0xae, 0x5e, 0x93, 0x72, 0x74, 0xd9,
  0xe1, 0x5a, 0x1c, 0x9b, 0x65, 0x1a, 0x2b, 0x61, 0x41, 0x28, 0x02, 0x73,
  0x84, 0x12, 0x97, 0x3a, 0x2d, 0xa2, 0xa0, 0x67, 0x77, 0x02, 0xda, 0x67,
  0x1a, 0x4b, 0xdd, 0xd7, 0x71, 0xcc,
};
static unsigned int enc_priv_key_len = 138;
const struct bootutil_key bootutil_enc_key = {
    .key = enc_priv_key,
    .len = &enc_priv_key_len,
};
