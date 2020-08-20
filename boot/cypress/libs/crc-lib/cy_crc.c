/***************************************************************************//**
* \file cy_crc.c
* \version 1.0
*
********************************************************************************
* \copyright
* Copyright 2016-2020, Cypress Semiconductor Corporation.  All rights reserved.
* You may use this file only in accordance with the license, terms, conditions,
* disclaimers, and limitations in the end user license agreement accompanying
* the software package with which this file was provided.
*******************************************************************************/

#include "cy_crc.h"

#define NIBBLE_POS                          (4u)
#define NIBBLE_MSK                          (0xFu)
#define CRC_TABLE_SIZE                      (16u)           /* A number of uint32_t elements in the CRC32 table */
#define CRC_INIT                            (0xFFFFFFFFu)


/*******************************************************************************
* Function Name: Cy_CRC_DataChecksum
****************************************************************************//**
*
* This function computes a CRC-32C for the provided number of bytes contained
* in the provided buffer.
* 
* \param address    The pointer to a buffer containing the data to compute
*                   the checksum for.
* \param length     The number of bytes in the buffer to compute the checksum
*                   for.
*
* \return CRC-32C for the provided data.
* 
*******************************************************************************/
uint32_t Cy_CRC_DataChecksum(const uint8_t *address, uint32_t length)
{
    /* Contains generated values to calculate CRC-32C by 4 bits per iteration*/
    const static uint32_t crcTable[CRC_TABLE_SIZE] = 
    {
        0x00000000u, 0x105ec76fu, 0x20bd8edeu, 0x30e349b1u,
        0x417b1dbcu, 0x5125dad3u, 0x61c69362u, 0x7198540du,
        0x82f63b78u, 0x92a8fc17u, 0xa24bb5a6u, 0xb21572c9u,
        0xc38d26c4u, 0xd3d3e1abu, 0xe330a81au, 0xf36e6f75u,
    };
    
    uint32_t crc = CRC_INIT;
    if (length != 0u)
    {
        do
        {
            crc = crc ^ *address;
            crc = (crc >> NIBBLE_POS) ^ crcTable[crc & NIBBLE_MSK];
            crc = (crc >> NIBBLE_POS) ^ crcTable[crc & NIBBLE_MSK];
            --length;
            ++address;
        } while (length != 0u);
    }
    return (~crc);
}
