### Blinking LED test application for MCUBoot Bootloader.

**Description:**

Implements simple Blinky LED CM4 application to demonstrate MCUBoot Application operation in terms of BOOT and UPGRADE process.

It is started by MCUBoot Application which is running on CM0p.

* Blinks RED led with 2 different rates, depending on type of image - BOOT or UPGRADE.
* Prints debug info and version of itself to terminal at 115200 baud.
* Can be built for BOOT slot or UPGRADE slot of MCUBoot Bootloader.

**How to build an application:**

Root directory for build is **boot/cypress.**

The following command will build regular HEX file of a Blinky Application, BOOT slot:

    make app APP_NAME=BlinkyApp TARGET=CY8CPROTO-062-4343W IMG_TYPE=BOOT

This have following defaults suggested:

    BUILDCFG=Debug
    IMG_TYPE=BOOT

To build UPGRADE image use following command:

    make app APP_NAME=BlinkyApp TARGET=CY8CPROTO-062-4343W IMG_TYPE=UPGRADE HEADER_OFFSET=0x10000

To build UPGRADE encrypted image use following command:

    make app APP_NAME=BlinkyApp TARGET=CY8CPROTO-062-4343W IMG_TYPE=UPGRADE HEADER_OFFSET=0x10000 ENC_IMG=1

*Note:* the image is signed also.

**How to sign an image:**

To sign obtained image use following command:

    make sign APP_NAME=BlinkyApp TARGET=CY8CPROTO-062-4343W IMG_TYPE=BOOT

    make sign APP_NAME=BlinkyApp TARGET=CY8CPROTO-062-4343W IMG_TYPE=UPGRADE

Flags defaults:

    BUILDCFG=Debug
    IMG_TYPE=BOOT

*Note:* before signing UPGRADE image it should be rebuilt with IMG_TYPE=UPGRADE parameter (clean \out before it).

**How to program an application:**

Use any preferred tool for programming hex files.

Currently implemented makefile jobs use DAPLINK interface for programming.

To program BOOT image:

    make load_boot APP_NAME=BlinkyApp TARGET=CY8CPROTO-062-4343W

To program UPGRADE image:

    make load_upgrade APP_NAME=BlinkyApp TARGET=CY8CPROTO-062-4343W

Flags defaults:

    BUILDCFG=Debug

**Flags:**
- `BUILDCFG` - configuration **Release** of **Debug**
- `MAKEINFO` - 0 (default) - less build info, 1 - verbose output of compilation.
- `HEADER_OFFSET` - 0 (default) - no offset of output hex file, 0x%VALUE% - offset for output hex file. Value 0x10000 is slot size MCUBoot Bootloader in this example
- `IMG_TYPE` - `BOOT` (default) - build image for BOOT slot of MCUBoot Bootloader, `UPGRADE` - build image for `UPGRADE` slot of MCUBoot Bootloader.
- `ENC_IMG` - 0 (default) - build unencrypted image, 1 - build encrypted image.
- `ENC_KEY_FILE` - name of file (w/o extension) with public key for encrypting image. File should be located in 'keys' folder.

**NOTE**: 
- In case of `UPGRADE` image `HEADER_OFFSET` should be set to MCUBoot Bootloader slot size.
- The `ENC_IMG=1` can be used ONLY with `UPGRADE` image type.

**Example terminal output:**

When user application programmed in BOOT slot:

    ===========================
    [BlinkyApp] BlinkyApp v1.0
    ===========================
    [BlinkyApp] GPIO initialized
    [BlinkyApp] UART initialized
    [BlinkyApp] Retarget I/O set to 115200 baudrate
    [BlinkyApp] Red led blinks with 1 sec period

When user application programmed in UPRADE slot and upgrade procedure was successful:

    ===========================
    [BlinkyApp] BlinkyApp v2.0
    ===========================

    [BlinkyApp] GPIO initialized
    [BlinkyApp] UART initialized
    [BlinkyApp] Retarget I/O set to 115200 baudrate
    [BlinkyApp] Red led blinks with 0.25 sec period

**Important**: make sure primary and secondary slot sizes are appropriate and correspond to flash area size defined in BlinkyApp linker file.
