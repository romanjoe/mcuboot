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
# python status.py --status_addr 0x10038000 --area_id 2 --slot_1_size 0x10000 --pages_num 2 --wr_size 0x200 --erased-val 0x00 --filename status
# same as
# python status.py -a 0x10038000 -i 2 -s1 65536 -n 2 -w 512 -R 0 -f status

from status import main

if __name__ == '__main__':
    main.status()
