/***************************************************************************//**
* \file cy_crc.h
* \version 1.0
*
********************************************************************************
* \copyright
* Copyright 2016-2020, Cypress Semiconductor Corporation.  All rights reserved.
* You may use this file only in accordance with the license, terms, conditions,
* disclaimers, and limitations in the end user license agreement accompanying
* the software package with which this file was provided.
*******************************************************************************/

#include <stdint.h>

uint32_t Cy_CRC_DataChecksum(const uint8_t *address, uint32_t length);
