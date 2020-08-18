/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2019 JUUL Labs
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "bootutil/bootutil.h"
#include "bootutil_priv.h"
#include "swap_priv.h"
#include "bootutil/bootutil_log.h"

#include "swap_status.h"

#include "mcuboot_config/mcuboot_config.h"

MCUBOOT_LOG_MODULE_DECLARE(mcuboot);

#if defined(MCUBOOT_SWAP_USING_STATUS)

#define BOOT_MAGIC_ARR_SZ \
    (sizeof boot_img_magic / sizeof boot_img_magic[0])

static int
boot_magic_decode(const uint32_t *magic)
{
    if (memcmp(magic, boot_img_magic, BOOT_MAGIC_SZ) == 0) {
        return BOOT_MAGIC_GOOD;
    }
    return BOOT_MAGIC_BAD;
}

static int
boot_flag_decode(uint8_t flag)
{
    if (flag != BOOT_FLAG_SET) {
        return BOOT_FLAG_BAD;
    }
    return BOOT_FLAG_SET;
}

static inline size_t
boot_status_sector_size(const struct boot_loader_state *state, size_t sector)
{
    return state->status.sectors[sector].fs_size;
}

static inline uint32_t
boot_status_sector_off(const struct boot_loader_state *state,
                    size_t sector)
{
    return state->status.sectors[sector].fs_off -
           state->status.sectors[0].fs_off;
}


/* MISC - section, early development */
/* Offset Section */

static inline uint32_t
boot_magic_off(const struct flash_area *fap)
{
    (void)fap;
    return BOOT_SWAP_STATUS_D_SIZE_RAW - BOOT_MAGIC_SZ;
}

static inline uint32_t
boot_image_ok_off(const struct flash_area *fap)
{
    return boot_magic_off(fap) - 1;
}

static inline uint32_t
boot_copy_done_off(const struct flash_area *fap)
{
    return boot_image_ok_off(fap) - 1;
}

uint32_t
boot_swap_info_off(const struct flash_area *fap)
{
    return boot_copy_done_off(fap) - 1;
}

static inline uint32_t
boot_swap_size_off(const struct flash_area *fap)
{
    return boot_swap_info_off(fap) - 4;
}

uint32_t
boot_status_off(const struct flash_area *fap)
{   
    /* this offset is equal to 0, because swap status fields
       in this implementation count from the start of partion */
    return 0;
}

#ifdef MCUBOOT_ENC_IMAGES
static inline uint32_t
boot_enc_key_off(const struct flash_area *fap, uint8_t slot)
{
//#if MCUBOOT_SWAP_SAVE_ENCTLV
//    return boot_swap_size_off(fap) - ((slot + 1) *
//            ((((BOOT_ENC_TLV_SIZE - 1) / BOOT_MAX_ALIGN) + 1) * BOOT_MAX_ALIGN));
//#else
    return boot_swap_size_off(fap) - ((slot + 1) * BOOT_ENC_KEY_SIZE);
//#endif
}
#endif

/**
 * Write trailer data; status bytes, swap_size, etc
 *
 * @returns 0 on success, != 0 on error.
 */
#ifdef MCUBOOT_SWAP_USING_STATUS
int
boot_write_trailer(const struct flash_area *fap, uint32_t off,
        const uint8_t *inbuf, uint8_t inlen)
{
    int rc;

    rc = swap_status_update(fap->fa_id, off, (uint8_t *)inbuf, inlen);

    if (rc != 0) {
        return BOOT_EFLASH;
    }
    return rc;
}
#endif

#endif /* MCUBOOT_SWAP_USING_STATUS */

#ifdef MCUBOOT_ENC_IMAGES
int
boot_write_enc_key(const struct flash_area *fap, uint8_t slot,
        const struct boot_status *bs)
{
    uint32_t off;
    int rc;

    off = boot_enc_key_off(fap, slot);
//#if MCUBOOT_SWAP_SAVE_ENCTLV
//    rc = flash_area_write(fap, off, bs->enctlv[slot], BOOT_ENC_TLV_ALIGN_SIZE);
//#else
    rc = swap_status_update(fap->fa_id, off,
                            (uint8_t *) bs->enckey[slot], BOOT_ENC_KEY_SIZE);
//#endif
   if (rc != 0) {
       return BOOT_EFLASH;
   }

    return 0;
}
#endif

//#endif


// TODO: implement it for SWAP status
/* Write Section */
int
boot_write_magic(const struct flash_area *fap)
{
    uint32_t off;
    int rc;

    off = boot_magic_off(fap);

    rc = swap_status_update(fap->fa_id, off,
                            (uint8_t *) boot_img_magic, BOOT_MAGIC_SZ);

    if (rc != 0) {
        return BOOT_EFLASH;
    }
    return 0;
}

int boot_status_num_sectors(const struct boot_loader_state *state)
{
    return (int)(BOOT_SWAP_STATUS_SIZE / boot_status_sector_size(state, 0));
}

/**
 * Writes the supplied boot status to the flash file system.  The boot status
 * contains the current state of an in-progress image copy operation.
 *
 * @param bs                    The boot status to write.
 *
 * @return                      0 on success; nonzero on failure.
 */
int
boot_write_status(const struct boot_loader_state *state, struct boot_status *bs)
{
    const struct flash_area *fap;
    uint32_t off;
    int area_id;
    int rc;

    /* NOTE: The first sector copied (that is the last sector on slot) contains
     *       the trailer. Since in the last step the primary slot is erased, the
     *       first two status writes go to the scratch which will be copied to
     *       the primary slot!
     */

#if MCUBOOT_SWAP_USING_SCRATCH
    if (bs->use_scratch) {
        /* Write to scratch. */
        area_id = FLASH_AREA_IMAGE_SCRATCH;
    } else {
#endif
        /* Write to the primary slot. */
        area_id = FLASH_AREA_IMAGE_PRIMARY(BOOT_CURR_IMG(state));
#if MCUBOOT_SWAP_USING_SCRATCH
    }
#endif

    rc = flash_area_open(area_id, &fap);
    if (rc != 0) {
        rc = BOOT_EFLASH;
        goto done;
    }

    off = boot_status_off(fap)
             + boot_status_internal_off(bs, 1);
    // align = flash_area_align(fap);
    // erased_val = flash_area_erased_val(fap);
    // memset(buf, erased_val, BOOT_MAX_ALIGN);
    // buf[0] = bs->state;

    rc = swap_status_update(fap->fa_id, off, &(bs->state), 1);
    //rc = flash_area_write(fap, off, buf, align);
    if (rc != 0) {
        rc = BOOT_EFLASH;
        goto done;
    }

done:
    flash_area_close(fap);

    return rc;
}

int
boot_read_data_empty(const struct flash_area *fap, void *data, uint32_t len)
{
    uint8_t *buf;

    buf = (uint8_t *)data;
    for (uint8_t i = 0; i < len; i++) {
        if (buf[i] != flash_area_erased_val(fap)) {
            return 0;
        }
    }
    return 1;
}

// TODO: implement it for SWAP status
int
boot_read_swap_state(const struct flash_area *fap,
                     struct boot_swap_state *state)
{
    uint32_t magic[BOOT_MAGIC_ARR_SZ];
    uint32_t off;
    uint8_t swap_info;
    int rc;

    const struct flash_area *fap_stat;

    rc = flash_area_open(FLASH_AREA_IMAGE_SWAP_STATUS, &fap_stat);
    assert (rc == 0);

    off = boot_magic_off(fap);
    /* retrieve value for magic field from status partition area */
    rc = swap_status_retrieve(fap->fa_id, off, magic, BOOT_MAGIC_SZ);
    if (rc < 0) {
        return BOOT_EFLASH;
    }
//    rc = flash_area_read_is_empty(fap, off, magic, BOOT_MAGIC_SZ);
    rc = boot_read_data_empty(fap_stat, magic, BOOT_MAGIC_SZ);
    if (rc < 0) {
        return BOOT_EFLASH;
    }
    /* fill magic number value if equal to expected */
    if (rc == 1) {
        state->magic = BOOT_MAGIC_UNSET;
    } else {
        state->magic = boot_magic_decode(magic);
    }

    // TODO: debug workaround
    state->magic = BOOT_MAGIC_GOOD;

    off = boot_swap_info_off(fap);
    rc = swap_status_retrieve(fap->fa_id, off, &swap_info, sizeof swap_info);
    if (rc < 0) {
        return BOOT_EFLASH;
    }
    //rc = flash_area_read_is_empty(fap, off, &swap_info, sizeof swap_info);
    rc = boot_read_data_empty(fap_stat, &swap_info, sizeof swap_info);
    if (rc < 0) {
        return BOOT_EFLASH;
    }
    /* Extract the swap type and image number */
    state->swap_type = BOOT_GET_SWAP_TYPE(swap_info);
    state->image_num = BOOT_GET_IMAGE_NUM(swap_info);

    if (rc == 1 || state->swap_type > BOOT_SWAP_TYPE_REVERT) {
        state->swap_type = BOOT_SWAP_TYPE_NONE;
        state->image_num = 0;
    }

    off = boot_copy_done_off(fap);
    rc = swap_status_retrieve(fap->fa_id, off, &state->copy_done, sizeof state->copy_done);
    if (rc < 0) {
        return BOOT_EFLASH;
    }
//    rc = flash_area_read_is_empty(fap, off, &state->copy_done,
//            sizeof state->copy_done);
    rc = boot_read_data_empty(fap_stat, &state->copy_done, sizeof state->copy_done);
    // TODO: needs to check swap_info was empty !!!
   if (rc < 0) {
       return BOOT_EFLASH;
   }

//   /* check if copy_done is set */
//   if (rc == 0) {
//       rc = 1;
//       for (uint8_t i = 0; i < sizeof state->copy_done; i++) {
//           /* compare with erased_val */
//           if (((uint8_t *)&state->copy_done)[i] != flash_area_erased_val(fap)) {
//               rc = 0;
//               break;
//           }
//       }
//   }

   if (rc == 1) {
       state->copy_done = BOOT_FLAG_UNSET;
   } else {
       state->copy_done = boot_flag_decode(state->copy_done);
   }

   off = boot_image_ok_off(fap);
   rc = swap_status_retrieve(fap->fa_id, off, &state->image_ok, sizeof state->image_ok);
   if (rc < 0) {
       return BOOT_EFLASH;
   }
//    rc = flash_area_read_is_empty(fap, off, &state->image_ok,
//                                  sizeof state->image_ok);
   rc = boot_read_data_empty(fap_stat, &state->image_ok, sizeof state->image_ok);
   // TODO: needs to check swap_info was empty !!!
   if (rc < 0) {
       return BOOT_EFLASH;
   }
   /* check if image_ok is set */
//   if (rc == 0) {
//       rc = 1;
//       for (uint8_t i = 0; i < sizeof state->image_ok; i++) {
//           /* compare with erased_val */
//           if (((uint8_t *)&state->image_ok)[i] != flash_area_erased_val(fap)) {
//               rc = 0;
//               break;
//           }
//       }
//   }

   if (rc == 1) {
       state->image_ok = BOOT_FLAG_UNSET;
   } else {
       state->image_ok = boot_flag_decode(state->image_ok);
   }

    return 0;
}

int32_t swap_status_init_offset(uint32_t area_id)
{
    int32_t offset;
    /* calculate an offset caused by area type: primary_x/secondary_x */
    switch (area_id) {
    case FLASH_AREA_IMAGE_0:
        offset = 0x00;
        break;
    case FLASH_AREA_IMAGE_1:
        offset = BOOT_SWAP_STATUS_SIZE;
        break;
    // TODO: add multi-image conditional compilation here
    case FLASH_AREA_IMAGE_2:
        offset = 2*BOOT_SWAP_STATUS_SIZE;
        break;
    case FLASH_AREA_IMAGE_3:
        offset = 3*BOOT_SWAP_STATUS_SIZE;
        break;
    default:
        offset = -1;
        break;
    }
    return offset;
}

int
swap_erase_trailer_sectors(const struct boot_loader_state *state,
                           const struct flash_area *fap)
{
    uint32_t sector;
    uint32_t trailer_sz;
    uint32_t total_sz;
    uint32_t off, sub_offs;
    uint32_t sz;
    int fa_id_primary;
    int fa_id_secondary;
    uint8_t image_index;
    int rc;

    // TODO: add initialization of CRC ?
    BOOT_LOG_DBG("Erasing trailer; fa_id=%d", fap->fa_id);
    /* trailer is located in status-partition */
    const struct flash_area *fap_stat;

    rc = flash_area_open(FLASH_AREA_IMAGE_SWAP_STATUS, &fap_stat);
    assert (rc == 0);

    image_index = BOOT_CURR_IMG(state);
    fa_id_primary = flash_area_id_from_multi_image_slot(image_index,
            BOOT_PRIMARY_SLOT);
    fa_id_secondary = flash_area_id_from_multi_image_slot(image_index,
            BOOT_SECONDARY_SLOT);

    /* skip if Flash Area is not recognizable */
    if ((fap->fa_id != fa_id_primary) && (fap->fa_id != fa_id_secondary)) {
        return BOOT_EFLASH;
    }

    sub_offs = swap_status_init_offset(fap->fa_id);

    /* delete starting from last sector and moving to beginning */
    /* calculate last sector of status sub-area */
    sector = boot_status_num_sectors(state) - 1;
    /* whole status area size to be erased */
    trailer_sz = BOOT_SWAP_STATUS_SIZE;
    total_sz = 0;
    do {
        sz = boot_status_sector_size(state, sector);
        off = boot_status_sector_off(state, sector) + sub_offs;
        rc = boot_erase_region(fap_stat, off, sz);
        assert(rc == 0);

        sector--;
        total_sz += sz;
    } while (total_sz < trailer_sz);

    flash_area_close(fap_stat);

    return rc;
}

int
swap_status_init(const struct boot_loader_state *state,
                 const struct flash_area *fap,
                 const struct boot_status *bs)
{
    struct boot_swap_state swap_state;
    uint8_t image_index;
    int rc;

#if (BOOT_IMAGE_NUMBER == 1)
    (void)state;
#endif

    image_index = BOOT_CURR_IMG(state);

    BOOT_LOG_DBG("initializing status; fa_id=%d", fap->fa_id);

    rc = boot_read_swap_state_by_id(FLASH_AREA_IMAGE_SECONDARY(image_index),
            &swap_state);
    assert(rc == 0);

    if (bs->swap_type != BOOT_SWAP_TYPE_NONE) {
        rc = boot_write_swap_info(fap, bs->swap_type, image_index);
        assert(rc == 0);
    }

    if (swap_state.image_ok == BOOT_FLAG_SET) {
        rc = boot_write_image_ok(fap);
        assert(rc == 0);
    }

    rc = boot_write_swap_size(fap, bs->swap_size);
    assert(rc == 0);

//#ifdef MCUBOOT_ENC_IMAGES
//    rc = boot_write_enc_key(fap, 0, bs);
//    assert(rc == 0);
//
//    rc = boot_write_enc_key(fap, 1, bs);
//    assert(rc == 0);
//#endif

    rc = boot_write_magic(fap);
    assert(rc == 0);

    return 0;
}

int
swap_read_status(struct boot_loader_state *state, struct boot_status *bs)
{
    const struct flash_area *fap;
    const struct flash_area *fap_stat;
    uint32_t off;
    uint8_t swap_info;
    int area_id;
    int rc = 0;

    // TODO: uncomment when ready
    bs->source = swap_status_source(state);
    switch (bs->source) {
    case BOOT_STATUS_SOURCE_NONE:
        return 0;

    case BOOT_STATUS_SOURCE_PRIMARY_SLOT:
        area_id = FLASH_AREA_IMAGE_PRIMARY(BOOT_CURR_IMG(state));
        break;

    default:
        assert(0);
        return BOOT_EBADARGS;
    }

    rc = flash_area_open(area_id, &fap);
    if (rc != 0) {
        return BOOT_EFLASH;
    }

    rc = flash_area_open(FLASH_AREA_IMAGE_SWAP_STATUS, &fap_stat);
    if (rc != 0) {
        return BOOT_EFLASH;
    }

    // TODO: uncomment when ready
    rc = swap_read_status_bytes(fap, state, bs);
    if (rc == 0) {
        off = boot_swap_info_off(fap);
        rc = swap_status_retrieve(area_id, off, &swap_info, sizeof swap_info);

        rc = boot_read_data_empty(fap_stat, &swap_info, sizeof swap_info);
        if (rc < 0) {
            return BOOT_EFLASH;
        }

        if (rc == 1) {
            BOOT_SET_SWAP_INFO(swap_info, 0, BOOT_SWAP_TYPE_NONE);
            rc = 0;
        }

        /* Extract the swap type info */
        bs->swap_type = BOOT_GET_SWAP_TYPE(swap_info);
    }

    flash_area_close(fap);
    flash_area_close(fap_stat);

    return rc;
}
