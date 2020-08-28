# Copyright (c) 2020 Cypress Semiconductor Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
################################################################

# CLI status.py examples:
# Start with default parameters for single image and default flash map
# python main.py --status_addr 0x10038000 --area_id 2 --slot_1_size 0x10000 --pages_num 2 --wr_size 0x200 --erased-val 0x00 --filename status
# same as
# python main.py -a 0x10038000 -i 2 -s1 65536 -n 2 -w 512 -R 0 -f status

import click
import crcmod
import math
import os
import struct

CRC_POLYNOMIAL = 0x11EDC6F41

COUNTER = 0x00000000
MAX_INT = 0xFFFFFFFF

MIN_PAGES_NUM = 2
MAX_PAGES_NUM = 16

MIN_WR_SIZE = 64
MAX_WR_SIZE = 0x100000

COLUMNS_NUMBER = 16

CRC_SIZE = 4
COUNTER_SIZE = 4
MAGIC_SIZE = 4

copyright = """/*
 * Copyright (c) 2020 Cypress Semiconductor Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
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
 /*******************************************************************************/

"""

magic_num = bytes([
        0x77, 0xC2, 0x95, 0xF3, 
        0x60, 0xD2, 0xEF, 0x7F, 
        0x35, 0x52, 0x50, 0x0F, 
        0x2C, 0xB6, 0x79, 0x80, 
        0xAF, 0xBE, 0xAD, 0xDE, ])

#class from imgtool based on click example
class BasedIntParamType(click.ParamType):
    name = "(DEC/HEX/OCT/BIN)"
    def convert(self, value, param, ctx):
        try:
            return int(value, 0)
        except ValueError:
            self.fail('%s is not a valid integer. Please use code literals '
                      'prefixed with 0b/0B, 0o/0O, or 0x/0X as necessary.'
                      % value, param, ctx)
   
@click.command()
@click.option('-i','--area_id', required=False, type=click.Choice(['1', '2', '5', '6']), default='2', show_default=True, help='Select flash area id number.')
@click.option('-a','--status_addr', required=False, type=BasedIntParamType(), default='0x10038000', show_default=True, help='Set address of status partition.')
@click.option('-s1','--slot_1_size', required=False, type=BasedIntParamType(), default='0x10000', show_default=True, help='Set slot size for first application.')
@click.option('-s2','--slot_2_size', required=False, type=BasedIntParamType(), default='0x10000', show_default=True, help='Set slot size for second application (multi image only).')
@click.option('-n','--pages_num', required=False, type=BasedIntParamType(), default='2', show_default=True, help='Nuber of cyclical D pages.')
@click.option('-w','--wr_size', required=False, type=BasedIntParamType(), default='512', show_default=True, help='Minimal write size in flash memory.')
@click.option('-R','--erased-val', required=False, type=BasedIntParamType(), default='0', show_default=True, help='Default value for erased flash.')
@click.option('-c','--generate_c', is_flag=True, show_default=True, help='Generate .c file of const char array.')
@click.option('-f','--filename', required=False, type=str, default='status', show_default=True, help='Set filename for generated files.')

def status(area_id, status_addr, slot_1_size, slot_2_size, pages_num, wr_size, erased_val, generate_c, filename):

    if pages_num < MIN_PAGES_NUM or pages_num > MAX_PAGES_NUM:
        raise SystemExit("Wrong page number. Select '--pages_num' between " + MIN_PAGES_NUM + " and " + MAX_PAGES_NUM)

    if wr_size < MIN_WR_SIZE or wr_size > MAX_WR_SIZE:
        raise SystemExit("Wrong write size. Minimal '--wr_size' " + MIN_WR_SIZE)

    if bin(wr_size)[2:].count('1') != 1:
        raise SystemExit("Wrong write size. '--wr_size' should be power of two.")

    if erased_val != 0 and erased_val != 0xFF:
        raise SystemExit("Wrong flash erase value. Only '0x00' and '0xFF' are possible for '--erased-val' option.")

    if slot_1_size % wr_size != 0:
        raise SystemExit("Wrong slot size for first image. '--slot_1_size' should be aligned to write size.")

    if slot_2_size % wr_size != 0:
        raise SystemExit("Wrong secondary slot size. '--slot_2_size' should be aligned to write size.")

    print('Area ID =', area_id)
    print('Status part addr =', hex(status_addr))
    print('Slot 1 size =', hex(slot_1_size))
    if area_id == '5' or area_id == '6':
        print('Slot 2 size =', hex(slot_2_size))
    print('Number of D pages =', pages_num)
    print('Minimal write size =', wr_size)
    print('Flash erase value =', hex(erased_val))
    print('Output filename =', filename)
    print('=================================')
    
    sect = [int(erased_val)] * (wr_size - len(magic_num) - COUNTER_SIZE - CRC_SIZE)
    sect += magic_num + COUNTER.to_bytes(COUNTER_SIZE, 'little')
    binary_arr = bytearray(sect)

    print('Creating binary file...')
    fbin = open(filename+'.bin', 'wb')
    fbin.write(binary_arr)
    
    crc32c = crcmod.mkCrcFun(CRC_POLYNOMIAL, 0, True, MAX_INT)
    crc_result = crc32c(binary_arr)
    fbin.write(struct.pack('<I', crc_result))

    fbin.flush()
    fbin.close()

    print('CRC32 =', hex(crc_result))
    sect += crc_result.to_bytes(CRC_SIZE, 'little')
 
    payload_items = wr_size - MAGIC_SIZE - COUNTER_SIZE - CRC_SIZE
    page1_size = (math.ceil (slot_1_size / wr_size / payload_items) + 1) * wr_size
    page2_size = (math.ceil (slot_2_size / wr_size / payload_items) + 1) * wr_size

    if area_id == '1':
        hex_offset = status_addr + page1_size - wr_size
    elif area_id == '2':
        hex_offset = status_addr + page1_size * pages_num + page1_size - wr_size
    elif area_id == '5':
        hex_offset = status_addr + page1_size * pages_num * 2 + page2_size - wr_size
    elif area_id == '6':
        hex_offset = status_addr + page1_size * pages_num * 2 + page2_size * pages_num + page2_size - wr_size
    else:
        raise SystemExit('Unsupported area id ' + area_id)

    print('Generating Intel HEX file...')
    print    ('arm-none-eabi-objcopy -I binary ' + filename + '.bin -O ihex ' + filename + '_id' + area_id + '.hex --change-addresses=' + str(hex(hex_offset)))
    os.system('arm-none-eabi-objcopy -I binary ' + filename + '.bin -O ihex ' + filename + '_id' + area_id + '.hex --change-addresses=' + str(hex(hex_offset)))
 
    if generate_c:
        print('Generating const char C file...')
        with open(filename + '_id' + area_id + '.c', "w") as c_fd:
            c_list = []

            c_fd.write(copyright)
            c_fd.write("#include <stdint.h>\n\n")
            c_fd.write("#define STATUS_INIT_DATA_ADDRESS " + hex(hex_offset) + "\n\n")
            c_fd.write("const uint8_t status_init_data[] = {\n")

            for n in sect:
                c_list.append(format(n, '#04x'))

            for i in range(int(len(c_list) / COLUMNS_NUMBER) + 1):
                line_list = c_list[i * COLUMNS_NUMBER: (i + 1) * COLUMNS_NUMBER]
                c_fd.write("   ")
                
                for item in line_list:
                    c_fd.write(" %su," % item)
                c_fd.write("\n")

            c_fd.write("};\n")
        c_fd.close()
    
if __name__ == '__main__':
    status()
