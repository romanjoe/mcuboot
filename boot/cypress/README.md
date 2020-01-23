### Port of MCUBoot library to be used with Cypress targets

**Solution Description**

Given solution demonstrates operation of MCUBoot on Cypress' PSoC6 device.

There are two applications implemented:
* MCUBootApp - PSoC6 MCUBoot-based bootloading application;
* BlinkyApp - simple PSoC6 blinking LED application which is a target of BOOT/UPGRADE;

The device supported is CY8CPROTO-062-4343W board which is PSoC6 device with 2M of Flash available.

The default flash map implemented is next:

* [0x10000000, 0x10020000] - MCUBootApp (bootloader) area;
* [0x10020000, 0x10030000] - primary slot for BlinkyApp;
* [0x10030000, 0x10040000] - secondary slot for BlinkyApp;
* [0x10040000, 0x10041000] - scratch area;

MCUBootApp checks image integrity with SHA256, image authenticity with EC256 digital signature verification and uses completely SW implementation of cryptographic functions based on mbedTLS Library.

**Downloading Solution's Assets**

There is a set assets required:

* MCUBooot Library (root repository)
* PSoC6 BSP Library
* PSoC6 Peripheral Drivers Library (PDL)
* mbedTLS Cryptographic Library

Those are represented as submodules.

To retrieve source code with subsequent submodules pull:

    git clone --recursive http://git-ore.aus.cypress.com/repo/cy_mcuboot_project/cy_mcuboot.git

Submodules can also be updated and initialized separately:

    cd cy_mcuboot
    git submodule update --init --recursive

**Building Solution**

This folder contains make files infrastructure for building both MCUBoot Bootloader and sample BlinkyLed application used to with Bootloader.

Instructions on how to build and upload Bootloader and sample image are located is `Readme.md` files in corresponding folders.

Root directory for build is **boot/cypress.**

**Currently supported targets:**

`* CY8CPROTO-062-4343W`

**Build environment troubleshooting:**

Following CLI / IDE can be used for project build:

* Cygwin
* Powerhell
* Msys2
* Git bash
* Eclipse / ModusToolbox ("makefile project from existing source")

*Make* - make sure it is added to system's `PATH` variable and correct path is first in the list;

*Python/Python3* - make sure you have correct path referenced in `PATH`;

*Msys2* - to use systems PATH navigate to msys2 folder, open `msys2_shell.cmd`, uncomment set `MSYS2_PATH_TYPE=inherit`, restart MSYS2 shell.

This will iherit system's PATH so should find `python3.7` installed in regular way as well as imgtool and its dependencies.

**Changes to allow encrypting image**
* Added folders to 'cypress':
    - hal (with headers);
    - libs/tinycrypt;
    - tinycrypt; (headers directory)
* Added files:
    - enc-ec256-priv.pem; (private key for encryption)
    - enc-ec256-pub.pem; (public key for encryption)
* Changed files:
    - Makefile; (added two values):
        - `ENC_KEY_FILE ?= enc-ec256-pub` (file name with public key for encryption)
        - `ENC_IMG ?= 0` (if 1 encrypt image else not)
    - BlinkyApp/BlinkyApp.mk (added command line parameters for imgtool to encrypt image)
    - MCUBootApp\config\mcuboot_config\mcuboot_config.h (added two defines to build mcuboot with encrypting image feature)
    - MCUBootApp\libs.mk (added tinycrypt to build)
    - MCUBootApp\keys.c (added 'enc_priv_key' array, enc_priv_key_len and bootutil_enc_key structure)

**Command to build encrypted image**
* to build mcuboot with encrypted image support:

      make app TARGET=CY8CPROTO-062-4343W

* to load mcuboot to target:

      cp ./MCUBootApp/out/CY8CPROTO-062-4343W/Debug/MCUBootApp.hex /d/

* to build BlinkyApp for slot 0 (BOOT):

      make app APP_NAME=BlinkyApp TARGET=CY8CPROTO-062-4343W IMG_TYPE=BOOT

* to load BlinkyApp to target to slot 0:

      cp ./BlinkyApp/out/CY8CPROTO-062-4343W/Debug/boot/BlinkyApp_signed.hex /d/


* to build BlinkyApp for slot 1 (UPDRADE) w/o encrypting image:

      make app APP_NAME=BlinkyApp TARGET=CY8CPROTO-062-4343W IMG_TYPE=UPGRADE HEADER_OFFSET=0x10000

* to build BlinkyApp for slot 1 (UPDRADE) w/ encrypting image:

      make app APP_NAME=BlinkyApp TARGET=CY8CPROTO-062-4343W IMG_TYPE=UPGRADE HEADER_OFFSET=0x10000 ENC_IMG=1

* to load BlinkyApp to target to slot 1:

      cp ./BlinkyApp/out/CY8CPROTO-062-4343W/Debug/BlinkyApp_signed_upgrade.hex /d/

