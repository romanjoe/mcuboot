/***************************************************************************//**
* \file main.c
* \version 1.0
*
* \brief
* Demonstrates blinking an LED under firmware control. The Cortex-M4 toggles
* the Red LED. The Cortex-M0+ starts the Cortex-M4 and enters sleep.
*
* Compatible Kits:
*   CY8CKIT-062-BLE
*   CY8CKIT-062-WIFI-BT
*
* Migration to CY8CPROTO-062-4343W kit (ModusToolbox IDE):
*   1. Create this project targeting the CY8CPROTO-062-4343W kit.
*   2. Open design.modus file and replicate P0[3] configuration on P13[7]. Give
*      this pin the alias "LED_RED". Disable P0[3].
*   3. Build and Program
*
* Migration to CY8CPROTO-062-4343W kit (command line make):
*   1. Launch the Device Configurator tool from
*      ModusToolbox_1.0\tools\device-configurator-1.0\
*   2. In Device Configurator, open design.modus file
*      (ModusToolbox_1.0\libraries\psoc6sw-1.0\examples\BlinkyLED\design.modus)
*      and replicate P0[3] configuration on P13[7].
*      Give this pin the alias "LED_RED". Disable P0[3].
*   3. Perform "make clean"
*   4. Build and Program the device with "make DEVICE=CY8C624ABZI-D44 program"
*      Note that depending on the method used to program the device, you may
*      need to manually reset it by pressing the SW1 RESET button on the kit.
*   4. Observe the red blinking LED.
*   5. To switch back to CY8CKIT-062-BLE or CY8CKIT-062-WIFI-BT,
*      perform steps 1 through 3 to reconfigure the "LED_RED" to P0[3].
*      Then use "make program".
*
********************************************************************************
* \copyright
* Copyright 2017-2019 Cypress Semiconductor Corporation
* SPDX-License-Identifier: Apache-2.0
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
*******************************************************************************/

/* Cypress pdl/bsp headers */
#include "cy_pdl.h"
#include "cyhal.h"
#include "cybsp.h"
#include "cy_retarget_io.h"

#include "flash_map_backend/flash_map_backend.h"

#define BLINKY_PERIOD_OK    (1000u)
#define BLINKY_PERIOD_ERROR (100u)

#define BUFF_SIZE           (128u)

uint32_t read_buff[BUFF_SIZE];

void print_mem(uint32_t *addr, uint32_t len)
{
    while(len-- > 0)
    {
        printf("0x%08lX ", *addr++);
        if(len % 8 == 0)
        {
            printf("\n\r");
        }
    }
}

int main(void)
{
    uint32_t blinky_period = BLINKY_PERIOD_OK;

    /* Initialize the device and board peripherals */
    int result = cybsp_init();

typedef struct
{
    unsigned char *buf;
    size_t length;
} rnd_buf_info;

    /* Initialize retarget-io to use the debug UART port */
    cy_retarget_io_init(CYBSP_DEBUG_UART_TX, CYBSP_DEBUG_UART_RX, CY_RETARGET_IO_BAUDRATE);

    /* enable interrupts */
    __enable_irq();

    printf("\n\r\n\rMCUBoot Application\n\r\n\r");

    struct flash_area *fa;
    result = flash_area_open(0, (const struct flash_area **)&fa);

    if(result == CY_RSLT_SUCCESS)
    {
        result = flash_area_read(fa, 0x100000, read_buff, BUFF_SIZE);
        printf("Reading memory:\n\r");
        print_mem(read_buff, BUFF_SIZE/4);
    }

    if(result == CY_RSLT_SUCCESS)
    {
        flash_area_close((const struct flash_area *)fa);
    }

    if(result != CY_RSLT_SUCCESS)
    {
        blinky_period = BLINKY_PERIOD_ERROR;
    }

    for (;;)
    {
		/* Toggle the user LED periodically */
        Cy_SysLib_Delay(500) ;
#include "flash_map_backend/flash_map_backend.h"


static void do_boot(struct boot_rsp *rsp)
{
    uintptr_t flash_base;
    uint32_t app_addr = 0;
    int rc;

    /* The beginning of the image is the ARM vector table, containing
     * the initial stack pointer address and the reset vector
     * consecutively. Manually set the stack pointer and jump into the
     * reset vector
     */
    rc = flash_device_base(rsp->br_flash_dev_id, &flash_base);
    //assert(rc == 0);

        /* Invert the USER LED state */
        cyhal_gpio_toggle((cyhal_gpio_t) CYBSP_USER_LED1);
#if (MCUBOOT_LOG_LEVEL != MCUBOOT_LOG_LEVEL_OFF)
   while(!Cy_SCB_UART_IsTxComplete(SCB5))
   {
      /* Wait until UART transmission complete */
   }
#endif

    app_addr = flash_base + rsp->br_image_off + rsp->br_hdr->ih_hdr_size;

    __enable_irq();

    /* It is aligned to 0x400 (256 records in vector table*4bytes each) */
    Cy_SysEnableCM4(app_addr);
}

int main(void)
{
    // /* Initialize the device and board peripherals */
    // int result = cybsp_init();

    // if (result != CY_RSLT_SUCCESS)
    // {
    //     CY_ASSERT(0);
    // }

    // /* Initialize the User LED */
    // cyhal_gpio_init((cyhal_gpio_t) CYBSP_USER_LED1, CYHAL_GPIO_DIR_OUTPUT, CYHAL_GPIO_DRIVE_STRONG, CYBSP_LED_STATE_OFF);

    // /* enable interrupts */
    // __enable_irq();

    // for (;;)
    // {
	// 	/* Toggle the user LED periodically */
    //     Cy_SysLib_Delay(500) ;

    //     /* Invert the USER LED state */
    //     cyhal_gpio_toggle((cyhal_gpio_t) CYBSP_USER_LED1);
    // }

    struct boot_rsp rsp;
    int rc = 0;

    /* Check if pre-image processing was successful */
    /* If not - remain in ACQUIRE state so device will not be dead */
    CYBL_ASSERT(0 == rc);
    BOOT_LOG_INF("Processing available images");

    rc = boot_go(&rsp);
    if (rc != 0)
    {
        BOOT_LOG_ERR("Unable to find bootable image");
        while (1);
    }

    BOOT_LOG_INF("Jumping to the image in slot 0");
    do_boot(&rsp);

    BOOT_LOG_ERR("Never should get here");
    while (1);
}
