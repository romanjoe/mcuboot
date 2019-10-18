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

#include "sysflash/sysflash.h"
#include "flash_map_backend/flash_map_backend.h"

#define BLINKY_PERIOD_OK    (1000u)
#define BLINKY_PERIOD_ERROR (100u)

#define BUFF_SIZE           (128u)

uint32_t read_buff[BUFF_SIZE];
uint32_t write_buff[BUFF_SIZE] = {  0x06, 0xf7, 0xa5, 0x60, 0x07, 0x82, 0x54, 0x33,
                                    0xc4, 0xc6, 0x11, 0x53, 0xdf, 0x1a, 0x13, 0x5e,
                                    0xee, 0x2f, 0x38, 0xec, 0x68, 0x7b, 0x49, 0x2e,
                                    0xd4, 0x0d, 0x9c, 0x90, 0x34, 0x37, 0x55, 0x76,
                                    0x06, 0xf7, 0xa5, 0x60, 0x07, 0x82, 0x54, 0x33,
                                    0xc4, 0xc6, 0x11, 0x53, 0xdf, 0x1a, 0x13, 0x5e,
                                    0xee, 0x2f, 0x38, 0xec, 0x68, 0x7b, 0x49, 0x2e,
                                    0xd4, 0x0d, 0x9c, 0x90, 0x34, 0x37, 0x55, 0x76,
                                    0x06, 0xf7, 0xa5, 0x60, 0x07, 0x82, 0x54, 0x33,
                                    0xc4, 0xc6, 0x11, 0x53, 0xdf, 0x1a, 0x13, 0x5e,
                                    0xee, 0x2f, 0x38, 0xec, 0x68, 0x7b, 0x49, 0x2e,
                                    0xd4, 0x0d, 0x9c, 0x90, 0x34, 0x37, 0x55, 0x76,
                                    0x06, 0xf7, 0xa5, 0x60, 0x07, 0x82, 0x54, 0x33,
                                    0xc4, 0xc6, 0x11, 0x53, 0xdf, 0x1a, 0x13, 0x5e,
                                    0xee, 0x2f, 0x38, 0xec, 0x68, 0x7b, 0x49, 0x2e,
                                    0xd4, 0x0d, 0x9c, 0x90, 0x34, 0x37, 0x55, 0x76 };

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

    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    /* Initialize the User LED */
    cyhal_gpio_init((cyhal_gpio_t) CYBSP_USER_LED1, CYHAL_GPIO_DIR_OUTPUT, CYHAL_GPIO_DRIVE_STRONG, CYBSP_LED_STATE_OFF);

    /* Initialize retarget-io to use the debug UART port */
    cy_retarget_io_init(CYBSP_DEBUG_UART_TX, CYBSP_DEBUG_UART_RX, CY_RETARGET_IO_BAUDRATE);

    /* enable interrupts */
    __enable_irq();

    printf("\n\r\n\rMCUBoot Application\n\r\n\r");

    /* Flash write test */
    struct flash_area *fa;

    result = flash_area_open(FLASH_AREA_BOOTLOADER, (const struct flash_area **)&fa);

    if(result == CY_RSLT_SUCCESS)
    {
        result = flash_area_read(fa, 0x0, read_buff, BUFF_SIZE);
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

    /* Flash write test */
    result = flash_area_open(FLASH_AREA_IMAGE_SCRATCH, (const struct flash_area **)&fa);

    if(result == CY_RSLT_SUCCESS)
    {
        result = flash_area_write(fa, 0x0, write_buff, BUFF_SIZE);
        printf("Writing memory memory:\n\r");
        print_mem(write_buff, BUFF_SIZE/4);
    }

    if(result == CY_RSLT_SUCCESS)
    {
        result = flash_area_read(fa, 0x0, read_buff, BUFF_SIZE);
        printf("Reading memory previously written:\n\r");
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
        Cy_SysLib_Delay(blinky_period) ;

        /* Invert the USER LED state */
        cyhal_gpio_toggle((cyhal_gpio_t) CYBSP_USER_LED1);
    }
}
