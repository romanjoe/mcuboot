### MCUBoot Bootloader

**Description:**

This application is based on upstream MCUBoot library. It is designed be first application started on CM0p.

Features implemented:
* Run on CM0p core
* Has debug prints to terminal on 115200
* Can validate image hash of 2 slots in flash memory BOOT and UPGRADE
* Starts image located in BOOT slot after validating signature
* Performs upgrade operation from UPGRADE slot to BOOT slot after UPGRADE image hash verification

**Flash map used for MCUBoot Bootloader:**

`0x10000000 - 0x10020000` - MCUBoot Bootloader

`0x10020000 - 0x10030000` - BOOT slot of Bootloader

`0x10030000 - 0x10040000` - UPGRADE slot of Bootloader

`0x10040000 - 0x10040100` - Scratch of Bootloader

Size of slots `0x10000` - 64kb

**Important**: make sure primary, secondary slot and bootloader app sizes are appropriate and correspond to flash area size defined in Applications' linker files.

**How to modify Flash map:**

__Option 1.__

Navigate to `flash_map_backend.h` and modify the flash area(s) / slots sizes to meet your needs.

__Option 2.__

Navigate to `sysflash.h`, uncomment `CY_FLASH_MAP_EXT_DESC` definition.
Now define and initialize `struct flash_area *boot_area_descs[]` with flash memory addresses and sizes you need at the beginning of application, so flash APIs from `cy_flash_map.c` will use it.

__Note:__ for both options make sure you have updated `MCUBOOT_MAX_IMG_SECTORS` appropriatery with sector size assumed to be 128.

**How to override the flash map values during build process:**

Navigate to MCUBootApp.mk, find section `DEFINES_APP +=`
Update this line and or add similar for flash map parameters to override.

The possible list could be:

* MCUBOOT_MAX_IMG_SECTORS
* CY_FLASH_MAP_EXT_DESC
* CY_BOOT_SCRATCH_SIZE
* CY_BOOT_BOOTLOADER_SIZE
* CY_BOOT_PRIMARY_1_SIZE
* CY_BOOT_SECONDARY_1_SIZE
* CY_BOOT_PRIMARY_2_SIZE
* CY_BOOT_SECONDARY_2_SIZE

As an example in a makefile it should look like following:

`DEFINES_APP +=-DCY_FLASH_MAP_EXT_DESC`

`DEFINES_APP +=-DMCUBOOT_MAX_IMG_SECTORS=512`

`DEFINES_APP +=-DCY_BOOT_PRIMARY_1_SIZE=0x15000`

**Multi-Image Operation**

Multi-image operation considers upgrading and verification of more then one image on the device.

To enable multi-image operation `MCUBOOT_IMAGE_NUMBER` should be set to number different then 1.

In multi-image operation (two images are considered for simplicity) MCUBoot Bootloader application operates as following:

* Verifies Primary_1 and Primary_2 images;
* Verifies Secondary_1 and Secondary_2 images;
* Upgrades Secondary to Primary if valid images found;
* Boots image from Primary_1 slot only;
* Boots Primary_1 only if both - Primary_1 and Primary_2 are present and valid;

This ensures two dependent applications can be accepted by device only in case both images are valid.

**Default Flash map for Multi-Image operation:**

`0x10000000 - 0x10020000` - MCUBoot Bootloader

`0x10020000 - 0x10030000` - Primary_1 (BOOT) slot of Bootloader

`0x10030000 - 0x10040000` - Secondary_1 (UPGRADE) slot of Bootloader

`0x10040000 - 0x10050000` - Primary_2 (BOOT) slot of Bootloader

`0x10050000 - 0x10060000` - Secondary_2 (UPGRADE) slot of Bootloader

`0x10060000 - 0x10060100` - Scratch of Bootloader

Size of slots `0x10000` - 64kb

**How to build MCUBoot Bootloader:**

Root directory for build is **boot/cypress**.

The following command will build MCUBoot Bootloader HEX file:

    make app APP_NAME=MCUBootApp TARGET=CY8CPROTO-062-4343W

Flags by defalt:

    BUILDCFG=Debug
    MAKEINFO=0
    
*Note:* When encrypted image feature will be used the private key of key pair for encrypting image should be placed to 'enc_priv_key' array in 'keys.c' file.

**How to program MCUBoot Bootloader:**

Use any preffered tool for programming hex files.

Currently implemented makefile jobs use DAPLINK interface for programming.

To program Bootloader image use following command:

    make load APP_NAME=MCUBootApp TARGET=CY8CPROTO-062-4343W

**Example terminal output:**

When user application programmed in BOOT slot:

    [INF] MCUBoot Bootloader Started

    [INF] User Application validated successfully

    [INF] Starting User Application on CM4 (wait)…
