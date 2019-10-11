/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 * Copyright (c) 2015 Runtime Inc
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __FLASH_MAP_BACKEND_H__
#define __FLASH_MAP_BACKEND_H__

#include <mcuboot_config/mcuboot_config.h>

/*< Opens the area for use. id is one of the `fa_id`s */
int     flash_area_open(uint8_t id, const struct flash_area **);
void    flash_area_close(const struct flash_area *);
/*< Reads `len` bytes of flash memory at `off` to the buffer at `dst` */
int     flash_area_read(const struct flash_area *, uint32_t off, void *dst,
                     uint32_t len);
/*< Writes `len` bytes of flash memory at `off` from the buffer at `src` */
int     flash_area_write(const struct flash_area *, uint32_t off,
                     const void *src, uint32_t len);
/*< Erases `len` bytes of flash memory at `off` */
int     flash_area_erase(const struct flash_area *, uint32_t off, uint32_t len);
/*< Returns this `flash_area`s alignment */
uint8_t flash_area_align(const struct flash_area *);
/*< Initializes an array of flash_area elements for the slot's sectors */
int     flash_area_to_sectors(int idx, int *cnt, struct flash_area *ret);
/*< Returns the `fa_id` for slot, where slot is 0 (primary) or 1 (secondary) */
int     flash_area_id_from_image_slot(int slot);
/*< Returns the slot, for the `fa_id` supplied */
int     flash_area_id_to_image_slot(int area_id);

//int flash_area_id_from_multi_image_slot(int image_index, int slot);
//int flash_area_id_to_multi_image_slot(int image_index, int area_id);

#endif /* __FLASH_MAP_BACKEND_H__ */
