/* tools/mkbootimg/bootimg.h
**
** Copyright 2007, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stdint.h>

#ifndef _BOOT_IMAGE_H_
#define _BOOT_IMAGE_H_

#define CMDLINE_SIZE 1024
#define BOOTSTUB_SIZE 8192

#define OSIP_PADDING 384
#define BOOTHEADER_PADDING 3048

typedef struct OSII OSII;
typedef struct OSIP_header OSIP_header;
typedef struct boot_img_hdr boot_img_hdr;

struct OSII {                   /* os image identifier */
    uint16_t os_rev_minor;
    uint16_t os_rev_major;
    uint32_t logical_start_block;

    uint32_t ddr_load_address;
    uint32_t entry_point;
    uint32_t size_of_os_image;  /* nb of sectors */

    uint8_t  attribute;         /* image_type 0x1 = boot, 0xd = recovery */
    uint8_t  reserved[3];
};

struct OSIP_header {            /* os image profile */
    uint32_t sig;
    uint8_t  intel_reserved;
    uint8_t  header_rev_minor;
    uint8_t  header_rev_major;
    uint8_t  header_checksum;
    uint8_t  num_pointers;
    uint8_t  num_images;
    uint16_t header_size;
    uint32_t reserved[5];

    struct OSII desc;

    uint8_t osip_padding[OSIP_PADDING];
};

struct boot_img_hdr
{
    /* mbr*/
    struct   OSIP_header osip;
    uint32_t boot_sig;
    uint16_t boot_nul;
    uint8_t  part_table[64];
    uint16_t mbr_sig;

    /* boot header */
    uint8_t  cmdline[CMDLINE_SIZE];
    uint32_t kernel_size;  /* page size aligned */
    uint32_t ramdisk_size; /* page size aligned */
    uint32_t console_suppression;
    uint32_t console_dev_type;
    uint32_t reserved_flag_0;
    uint32_t reserved_flag_1;
    uint8_t  boot_padding[BOOTHEADER_PADDING];
};

#endif
