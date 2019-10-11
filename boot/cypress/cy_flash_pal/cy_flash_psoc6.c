/***************************************************************************//**
* \file flash_psoc6.c
* \version 1.0
*
* \brief
*  This is the source file of flash driver adoption layer between PSoC6 
*  and standard MCUBoot code.
*
********************************************************************************
* \copyright
*
* (c) 2018, Cypress Semiconductor Corporation
* or a subsidiary of Cypress Semiconductor Corporation. All rights
* reserved.
*
* This software, including source code, documentation and related
* materials ("Software"), is owned by Cypress Semiconductor
* Corporation or one of its subsidiaries ("Cypress") and is protected by
* and subject to worldwide patent protection (United States and foreign),
* United States copyright laws and international treaty provisions.
* Therefore, you may use this Software only as provided in the license
* agreement accompanying the software package from which you
* obtained this Software ("EULA").
*
* If no EULA applies, Cypress hereby grants you a personal, non-
* exclusive, non-transferable license to copy, modify, and compile the
* Software source code solely for use in connection with Cypress?s
* integrated circuit products. Any reproduction, modification, translation,
* compilation, or representation of this Software except as specified
* above is prohibited without the express written permission of Cypress.
*
* Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO
* WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING,
* BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
* PARTICULAR PURPOSE. Cypress reserves the right to make
* changes to the Software without notice. Cypress does not assume any
* liability arising out of the application or use of the Software or any
* product or circuit described in the Software. Cypress does not
* authorize its products for use in any products where a malfunction or
* failure of the Cypress product may reasonably be expected to result in
* significant property damage, injury or death ("High Risk Product"). By
* including Cypress's product in a High Risk Product, the manufacturer
* of such system or application assumes all risk of such use and in doing
* so agrees to indemnify Cypress against all liability.
*
******************************************************************************/
#include "string.h"
#include "stdlib.h"
#include "stdbool.h"
#ifdef MCUBOOT_HAVE_ASSERT_H
#include "mcuboot_config/mcuboot_assert.h"
#else
#include <assert.h>
#endif


#include "cy_device_headers.h"

#include "device.h"

#include "util.h"
#include "flash.h"
#include "flash_map.h"
#include "flash_psoc6.h"

#include "cy_flash.h"
#include "cy_syspm.h"

#define PSOC6_WR_SUCCESS 0
#define PSOC6_WR_ERROR_INVALID_PARAMETER 1
#define PSOC6_WR_ERROR_FLASH_WRITE 2

#define PSOC6_FLASH_ERASE_BLOCK_SIZE	CY_FLASH_SIZEOF_ROW /* PSoC6 Flash erases by Row */
#define PSOC6_CONFIG_FLASH_SIZE         16384*16

#if defined(CONFIG_FLASH_PAGE_LAYOUT)
static const struct flash_pages_layout dev_layout = {
	.pages_count = KB(PSOC6_CONFIG_FLASH_SIZE) / PSOC6_FLASH_ERASE_BLOCK_SIZE,
	.pages_size = PSOC6_FLASH_ERASE_BLOCK_SIZE,
};

static void psoc6_flash_pages_layout(const struct flash_pages_layout **layout,
									size_t *layout_size)
{
	*layout = &dev_layout;
	*layout_size = 1;
}
#endif /* CONFIG_FLASH_PAGE_LAYOUT */

int psoc6_flash_init(struct device *device)
{
	(void)device;
	/* Nothing to do here */
	return 0;
}

int psoc6_flash_read(off_t addr,
			   void *data, size_t len)
{
	uint32_t address;

	address = FLASH_DEVICE_BASE + addr;
	/* flash read by simple memory copying */
	memcpy((void *)data, (const void*)address, (size_t)len);

	return 0;
}

int psoc6_flash_write(off_t addr,
			    const void *data, size_t len)
{
	int rc;
	uint32_t address;

	address = FLASH_DEVICE_BASE + addr;

	rc = psoc6_flash_write_hal((uint8_t *)data, address, len);

	return rc;
}

int psoc6_flash_erase(off_t addr, size_t size)
{
	int rc = 0;

	uint32_t addrStart, addrEnd, address;
	uint32_t remStart, remEnd;
	uint32_t rowIdxStart, rowIdxEnd, rowNum;
	uint8_t  buff[CY_FLASH_SIZEOF_ROW];

	addrStart = FLASH_DEVICE_BASE + addr;
	addrEnd   = addrStart + size;

	/* find if area bounds are aligned to rows */
	remStart = addrStart%CY_FLASH_SIZEOF_ROW;
	remEnd   = addrEnd%CY_FLASH_SIZEOF_ROW;

	/* find which row numbers are affected for full Erase */
	rowIdxStart = addrStart/CY_FLASH_SIZEOF_ROW;
	rowIdxEnd   = addrEnd/CY_FLASH_SIZEOF_ROW;

	if(remStart != 0)
	{/* first row is fragmented, move to next */
		rowIdxStart++;
	}

	/* total number of rows for full erase */
	rowNum = rowIdxEnd - rowIdxStart;
	address = rowIdxStart*CY_FLASH_SIZEOF_ROW;

	while(rowNum>0)
	{
		rc = Cy_Flash_EraseRow(address);
		assert(rc == 0);
		address += CY_FLASH_SIZEOF_ROW;
		rowNum--;
	}

	/* if Start of erase area is unaligned */
	if(remStart != 0)
	{
		/* first row is fragmented, shift left by one*/
		rowIdxStart--;

		/* find start address of fragmented row */
		address = rowIdxStart*CY_FLASH_SIZEOF_ROW;

		/* store fragmented row contents first */
		memcpy((void *)buff, (const void*)address, remStart);

		/* erase fragmented row */
		rc = Cy_Flash_EraseRow(address);
		assert(rc == 0);

		/* write stored back */
		rc = psoc6_flash_write_hal(buff, address, remStart);
		assert(rc == 0);
	}
	/* if End of erase area is unaligned */
	if(remEnd != 0)
	{
		/* find start address of fragmented row */
		address = rowIdxEnd*CY_FLASH_SIZEOF_ROW;

		/* store fragmented row contents first */
		memcpy((void *)buff, (const void*)addrEnd, CY_FLASH_SIZEOF_ROW-remEnd);

		/* erase fragmented row */
		rc = Cy_Flash_EraseRow(address);
		assert(rc == 0);

		/* write stored back */
		rc = psoc6_flash_write_hal(buff, addrEnd, CY_FLASH_SIZEOF_ROW-remEnd);
		assert(rc == 0);
	}
	return rc;
}

int psoc6_flash_write_protection_set(bool enable)
{
	(void)(enable);
	/* N/A in PSoC6 Flash Driver */
	return 0;
}

int psoc6_flash_pm_ctl(u32_t command, void *context)
{
	(void)(command);
	(void)(context);
	/* Nothing to do here */
	return 0;
}

const struct flash_driver_api psoc6_flash_api =
{
	.read 				= psoc6_flash_read,
	.write 				= psoc6_flash_write,
	.erase 				= psoc6_flash_erase,
	.write_protection 	= psoc6_flash_write_protection_set,
#if defined(CONFIG_FLASH_PAGE_LAYOUT)
	.page_layout 		= (flash_api_pages_layout)psoc6_flash_pages_layout,
#endif
	.write_block_size = 4,
};

/*******************************************************************************
* Function Name: psoc6_flash_write_hal
****************************************************************************//**
*
*  This function writes the data to the PSOC6's Flash. It will check the
*  appropriate alignment of a start address and also perform an address range
*  check based on the length before performing the write operation.
*  This function performs memory compare and writes only row where there are new
*  data to write.
*
*  \param addr:   Pointer to the buffer containing the data to be stored.
*  \param data:   Pointer to the array or variable in the flash.
*  \param len:    The length of the data in bytes.
*
* \return
*  PSOC6_WR_SUCCESS                     A successful write
*  PSOC6_WR_ERROR_INVALID_PARAMETER     At least one of the input parameters is invalid
*  PSOC6_WR__ERROR_FLASH_WRITE          Error in flash Write
*
*******************************************************************************/
int psoc6_flash_write_hal(uint8_t data[],
							 uint32_t address,
							 uint32_t len)
{
    int retCode;
    cy_en_flashdrv_status_t rc = CY_FLASH_DRV_SUCCESS;

    uint32_t writeBuffer[CY_FLASH_SIZEOF_ROW / sizeof(uint32_t)];
    uint32_t rowId;
    uint32_t dstIndex;
    uint32_t srcIndex = 0u;
    uint32_t eeOffset;
    uint32_t byteOffset;
    uint32_t rowsNotEqual;
    uint8_t *writeBufferPointer;

    eeOffset = (uint32_t)address;
    writeBufferPointer = (uint8_t*)writeBuffer;

    bool cond1, cond2, cond3;

    /* Make sure, that varFlash[] points to Flash or WFlash */
    cond1 = ((eeOffset >= CY_FLASH_BASE) &&
    		((eeOffset + len) <= (CY_FLASH_BASE + CY_FLASH_SIZE)));

    cond2 = ((eeOffset >= CY_EM_EEPROM_BASE) &&
    		((eeOffset + len) <= (CY_EM_EEPROM_BASE + CY_EM_EEPROM_SIZE)));

	cond3 = ((eeOffset >= (uint32_t)SFLASH->BLE_DEVICE_ADDRESS) &&
			((eeOffset + len) <= ((uint32_t)SFLASH->BLE_DEVICE_ADDRESS + CY_FLASH_SIZEOF_ROW)));

    if(cond1 || cond2 || cond3)
    {
        eeOffset -= CY_FLASH_BASE;
        rowId = eeOffset / CY_FLASH_SIZEOF_ROW;
        byteOffset = CY_FLASH_SIZEOF_ROW * rowId;

        while((srcIndex < len) && (rc == CY_FLASH_DRV_SUCCESS))
        {
            rowsNotEqual = 0u;
            /* Copy data to the write buffer either from the source buffer or from the flash */
            for(dstIndex = 0u; dstIndex < CY_FLASH_SIZEOF_ROW; dstIndex++)
            {
                if((byteOffset >= eeOffset) && (srcIndex < len))
                {
                    writeBufferPointer[dstIndex] = data[srcIndex];
                    /* Detect that row programming is required */
                    if((rowsNotEqual == 0u) && (CY_GET_REG8(CY_FLASH_BASE + byteOffset) != data[srcIndex]))
                    {
                        rowsNotEqual = 1u;
                    }
                    srcIndex++;
                }
                else
                {
                    writeBufferPointer[dstIndex] = CY_GET_REG8(CY_FLASH_BASE + byteOffset);
                }
                byteOffset++;
            }

            if(rowsNotEqual != 0u)
            {
                /* Write flash row */
            	rc = Cy_Flash_WriteRow((rowId * CY_FLASH_SIZEOF_ROW) + CY_FLASH_BASE, writeBuffer);
            }

            /* Go to the next row */
            rowId++;
        }
    }
    else
    {
        rc = CY_FLASH_DRV_INVALID_INPUT_PARAMETERS;
    }

    /* Return BLE error code */
    switch(rc)
    {
        case CY_FLASH_DRV_SUCCESS:
            retCode = PSOC6_WR_SUCCESS;
            break;

        case CY_FLASH_DRV_INVALID_INPUT_PARAMETERS:
        case CY_FLASH_DRV_INVALID_FLASH_ADDR:
            retCode = PSOC6_WR_ERROR_INVALID_PARAMETER;
            break;

        default:
            retCode = PSOC6_WR_ERROR_FLASH_WRITE;
            break;
    }
    return(retCode);
}
