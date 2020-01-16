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

#include "mcuboot_config/mcuboot_config.h"

#if defined(MCUBOOT_ENC_IMAGES)
#include <assert.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>

#include "hal/hal_flash.h"

#include "mbedtls/sha256.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/md.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/oid.h"
#include "mbedtls/asn1.h"
#include "mbedtls/cmac.h"

#include "bootutil/image.h"
#include "bootutil/enc_key.h"
#include "bootutil/sign_key.h"

#include "bootutil_priv.h"

#include "bootutil/bootutil_log.h"

#include "mcuboot_config/mcuboot_config.h"

static const uint8_t ec_pubkey_oid[] = MBEDTLS_OID_EC_ALG_UNRESTRICTED;
static const uint8_t ec_secp256r1_oid[] = MBEDTLS_OID_EC_GRP_SECP256R1;

/*
 * Parses the output of `imgtool keygen`, which produces a PKCS#8 elliptic
 * curve keypair. See RFC5208 and RFC5915.
 */
static int
parse_ec256_enckey(uint8_t **p, uint8_t *end, uint8_t *pk)
{
    int rc;
    size_t len;
    int version;
    mbedtls_asn1_buf alg;
    mbedtls_asn1_buf param;

    if ((rc = mbedtls_asn1_get_tag(p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return -1;
    }

    if (*p + len != end) {
        return -2;
    }

    version = 0;
    if (mbedtls_asn1_get_int(p, end, &version) || version != 0) {
        return -3;
    }

    if ((rc = mbedtls_asn1_get_alg(p, end, &alg, &param)) != 0) {
        return -5;
    }

    if (alg.len != sizeof(ec_pubkey_oid) - 1 ||
        memcmp(alg.p, ec_pubkey_oid, sizeof(ec_pubkey_oid) - 1)) {
        return -6;
    }
    if (param.len != sizeof(ec_secp256r1_oid) - 1 ||
        memcmp(param.p, ec_secp256r1_oid, sizeof(ec_secp256r1_oid) - 1)) {
        return -7;
    }

    if ((rc = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return -8;
    }

    /* RFC5915 - ECPrivateKey */

    if ((rc = mbedtls_asn1_get_tag(p, end, &len,
                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return -9;
    }

    version = 0;
    if (mbedtls_asn1_get_int(p, end, &version) || version != 1) {
        return -10;
    }

    /* privateKey */

    if ((rc = mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return -11;
    }

    if (len != NUM_ECC_BYTES) {
        return -12;
    }

    memcpy(pk, *p, len);

    /* publicKey usually follows but is not parsed here */

    return 0;
}

int
boot_enc_set_key(struct enc_key_data *enc_state, uint8_t slot, uint8_t *enckey)
{
    int rc;

    mbedtls_aes_init(&enc_state[slot].aes);
    rc = mbedtls_aes_setkey_enc(&enc_state[slot].aes, enckey, BOOT_ENC_KEY_SIZE_BITS);
    if (rc) {
        mbedtls_aes_free(&enc_state[slot].aes);
        return -1;
    }

    enc_state[slot].valid = 1;

    return 0;
}

#define EXPECTED_ENC_TLV    IMAGE_TLV_ENC_EC256
#define EXPECTED_ENC_LEN    (65 + 32 + 16)
#define EC_PUBK_INDEX       (1)
#define EC_TAG_INDEX        (65)
#define EC_CIPHERKEY_INDEX  (65 + 32)

/*
 * Load encryption key.
 */
int
boot_enc_load(struct enc_key_data *enc_state, int image_index,
        const struct image_header *hdr, const struct flash_area *fap,
        uint8_t *enckey)
{
    mbedtls_aes_context aes_ctx;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point P;
    mbedtls_mpi z, d;
    uint8_t tag[MBEDTLS_SHA256_DIGEST_SIZE];
    uint8_t shared[NUM_ECC_BYTES];
    uint8_t derived_key[MBEDTLS_AES_KEY_SIZE + MBEDTLS_SHA256_DIGEST_SIZE];
    uint8_t *cp;
    uint8_t *cpend;
    uint8_t pk[NUM_ECC_BYTES];
    uint8_t counter[MBEDTLS_AES_BLOCK_SIZE];
    unsigned char stream_block[MBEDTLS_AES_KEY_SIZE];
    size_t nc_off = 0;
    uint32_t off;
    uint16_t len;

    struct image_tlv_iter it;
    uint8_t buf[EXPECTED_ENC_LEN];
    uint8_t slot;
    int rc;
    

    rc = flash_area_id_to_multi_image_slot(image_index, fap->fa_id);
    if (rc < 0) {
        return rc;
    }
    slot = rc;

    /* Already loaded... */
    if (enc_state[slot].valid) {
        return 1;
    }

    rc = bootutil_tlv_iter_begin(&it, hdr, fap, EXPECTED_ENC_TLV, false);
    if (rc != 0) {
        return -1;
    }

    rc = bootutil_tlv_iter_next(&it, &off, &len, NULL);
    if (rc != 0) {
        return rc;
    }

    if (len != EXPECTED_ENC_LEN) {
        return -1;
    }

    rc = flash_area_read(fap, off, buf, EXPECTED_ENC_LEN);
    if (rc != 0) {
        return -1;
    }

    cp = (uint8_t *)bootutil_enc_key.key;
    cpend = cp + *bootutil_enc_key.len;

    /*
     * Load the stored EC256 decryption private key
     */
    rc = parse_ec256_enckey(&cp, cpend, pk);
    if (rc != 0) {
        return rc;
    }

    /* is EC point uncompressed? */
    if (buf[0] != 0x04) {
        return -1;
    }

    /*
     * First "element" in the TLV is the curve point (public key)
     */
    mbedtls_ecp_group_init( &grp );
    mbedtls_ecp_point_init( &P );

    rc = mbedtls_ecp_group_load( &grp, MBEDTLS_ECP_DP_SECP256R1 );
    if (rc != 0) {
        mbedtls_ecp_group_free( &grp );
        mbedtls_ecp_point_free( &P );
        return -1;
    }
    
    rc = mbedtls_ecp_point_read_binary( &grp, &P, buf, EC_TAG_INDEX );
    if (rc != 0) {
        mbedtls_ecp_group_free( &grp );
        mbedtls_ecp_point_free( &P );
        return -1;
    }

    rc = mbedtls_ecp_check_pubkey( &grp, &P );
    if (rc != 0) {
        mbedtls_ecp_group_free( &grp );
        mbedtls_ecp_point_free( &P );
        return -1;
    }

    mbedtls_mpi_init(&z);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_read_binary( &d, pk, NUM_ECC_BYTES );

    rc = mbedtls_ecdh_compute_shared( &grp, &z, &P, &d, NULL, NULL );
    if (rc != 0) {
    	mbedtls_mpi_free( &z );
    	mbedtls_mpi_free( &d );
    	mbedtls_ecp_group_free( &grp );
        mbedtls_ecp_point_free( &P );
        return -1;
    }

	mbedtls_mpi_free( &d );
    mbedtls_mpi_write_binary( &z, shared, NUM_ECC_BYTES );

  	mbedtls_mpi_free( &z );
    mbedtls_ecp_group_free( &grp );
    mbedtls_ecp_point_free( &P );

    /*
     * Expand shared secret to create keys for AES-128-CTR + HMAC-SHA256
     */

    len = MBEDTLS_AES_KEY_SIZE + MBEDTLS_SHA256_DIGEST_SIZE;

    rc = mbedtls_hkdf( mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
					  NULL, 0,
                      shared, NUM_ECC_BYTES,
                      (uint8_t *)"MCUBoot_ECIES_v1", 16,
                      derived_key, len );

    if (rc != 0) {
        return -1;
    }


    /*
     * HMAC the key and check that our received MAC matches the generated tag
     */
    rc = mbedtls_md_hmac(mbedtls_md_info_from_string("SHA256"),
    		&derived_key[16], 32,
			&buf[EC_CIPHERKEY_INDEX], 16,
			tag);
	if (rc != 0) {
		return -1;
	}

    if (memcmp( tag, &buf[EC_TAG_INDEX], 32) != 0) {
        return -1;
    }

    
    /*
     * Finally decrypt the received ciphered key
     */
    mbedtls_aes_init( &aes_ctx );

    rc = mbedtls_aes_setkey_dec( &aes_ctx, derived_key, 128 );
    if (rc != 0) {
        return -1;
    }

    memset( counter, 0, MBEDTLS_AES_BLOCK_SIZE);

    memset( stream_block, 0, MBEDTLS_AES_KEY_SIZE );
    rc = mbedtls_aes_crypt_ctr( &aes_ctx, MBEDTLS_AES_KEY_SIZE, &nc_off, counter, stream_block,
						   &buf[EC_CIPHERKEY_INDEX], enckey );
    if (rc != 0) {
        mbedtls_aes_free( &aes_ctx );
        return -1;
    }

    mbedtls_aes_free( &aes_ctx );
    
    rc = 0;
    return rc;
}

bool
boot_enc_valid(struct enc_key_data *enc_state, int image_index,
        const struct flash_area *fap)
{
    int rc;

    rc = flash_area_id_to_multi_image_slot( image_index, fap->fa_id );
    if (rc < 0) {
        /* can't get proper slot number - skip encryption, */
        /* postpone the error for a upper layer */
        return false;
    }

    return enc_state[rc].valid;
}

void
boot_encrypt(struct enc_key_data *enc_state, int image_index,
        const struct flash_area *fap, uint32_t off, uint32_t sz,
        uint32_t blk_off, uint8_t *buf)
{
    struct enc_key_data *enc;
    uint32_t i, j;
    uint8_t u8;
    uint8_t nonce[16];
    uint8_t blk[16];
    int rc;

    memset( nonce, 0, 12);
    off >>= 4;
    nonce[12] = (uint8_t)(off >> 24);
    nonce[13] = (uint8_t)(off >> 16);
    nonce[14] = (uint8_t)(off >> 8);
    nonce[15] = (uint8_t)off;

    rc = flash_area_id_to_multi_image_slot( image_index, fap->fa_id );
    if (rc < 0) {
        assert(0);
        return;
    }

    enc = &enc_state[rc];
    assert( enc->valid == 1);
    for (i = 0; i < sz; i++) {
        if (i == 0 || blk_off == 0) {
            mbedtls_aes_crypt_ecb( &enc->aes, MBEDTLS_AES_ENCRYPT, nonce, blk );

            for (j = 16; j > 0; --j) {
                if (++nonce[j - 1] != 0) {
                    break;
                }
            }
        }

        u8 = *buf;
        *buf++ = u8 ^ blk[blk_off];
        blk_off = (blk_off + 1) & 0x0f;
    }
}

/**
 * Clears encrypted state after use.
 */
void
boot_enc_zeroize(struct enc_key_data *enc_state)
{
    memset( enc_state, 0, sizeof(struct enc_key_data) * BOOT_NUM_SLOTS );
}

#endif /* MCUBOOT_ENC_IMAGES */
