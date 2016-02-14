/* tools/mkbootimg/mkbootimg.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>

#include "bootimg.h"

static void *load_file(const char *fn, unsigned *_sz, unsigned pagesize)
{
    char *data;
    int sz;
    int aligned_sz;
    int fd;

    data = 0;
    fd = open(fn, O_RDONLY);
    if(fd < 0) return 0;

    sz = lseek(fd, 0, SEEK_END);
    if(sz < 0) goto oops;

    if(lseek(fd, 0, SEEK_SET) != 0) goto oops;

    if (pagesize == 0) {
        aligned_sz = sz;
    } else {
        unsigned pagemask = pagesize - 1;
        aligned_sz = (sz + pagemask) & ~pagemask;
    }

    data = (char*) calloc(aligned_sz, sizeof(char));
    if(data == 0) goto oops;

    if(read(fd, data, sz) != sz) goto oops;
    close(fd);

    if(_sz) *_sz = aligned_sz;
    return data;

oops:
    close(fd);
    if(data != 0) free(data);
    return 0;
}

static uint8_t calc_checksum(void *_buf, int size)
{
        int i;
        uint8_t checksum = 0;
        uint8_t *buf = (uint8_t *)_buf;
        for (i = 0; i < size; i++)
                checksum = checksum ^ (buf[i]);
        return checksum;
}

int usage(void)
{
    fprintf(stderr,"usage: mkbootimg\n"
            "       --cmdline <kernel-commandline>\n"
            "       --bootstub <filename>\n"
            "       --kernel <filename>\n"
            "       --ramdisk <filename>\n"
            "       -o|--output <filename>\n"
            );
    return 1;
}

int main(int argc, char **argv)
{
    boot_img_hdr hdr;

    char *cmdline = "";
    size_t cmdlen;

    char *bootstub_fn = NULL;
    void *bootstub_data = NULL;
    uint32_t bootstub_size;

    char *kernel_fn = NULL;
    void *kernel_data = NULL;

    char *ramdisk_fn = NULL;
    void *ramdisk_data = NULL;

    char *bootimg = NULL;
    unsigned pagesize = 4096;
    int fd;

    argc--;
    argv++;

    while(argc > 0){
        char *arg = argv[0];
        char *val = argv[1];
        argc -= 2;
        argv += 2;
        if(!strcmp(arg, "--output") || !strcmp(arg, "-o")) {
            bootimg = val;
        } else if(!strcmp(arg, "--cmdline")) {
            cmdline = val;
        } else if(!strcmp(arg, "--bootstub")) {
            bootstub_fn = val;
        } else if(!strcmp(arg, "--kernel")) {
            kernel_fn = val;
        } else if(!strcmp(arg, "--ramdisk")) {
            ramdisk_fn = val;
/*        } else {
            return usage();*/
        }
    }

    cmdlen = strlen(cmdline);
    if(cmdlen > (CMDLINE_SIZE - 1)) {
        fprintf(stderr,"error: kernel commandline too large\n");
        return 1;
    }

    if(bootstub_fn == 0) {
        fprintf(stderr,"error: no bootstub specified\n");
        return usage();
    }

    if(kernel_fn == 0) {
        fprintf(stderr,"error: no kernel image specified\n");
        return usage();
    }

    if(ramdisk_fn == 0) {
        fprintf(stderr,"error: no ramdisk image specified\n");
        return usage();
    }

    if(bootimg == 0) {
        fprintf(stderr,"error: no output filename specified\n");
        return usage();
    }

    /* initialize header */
    memset(&hdr, 0, sizeof(hdr));
    memset(&hdr.osip, 0xff, sizeof(hdr.osip));

    /* fake mbr */
    memset(&hdr.osip, 0, 56);

    hdr.osip.sig = 0x24534f24;
    hdr.osip.header_rev_major = 1;
    hdr.osip.num_pointers = 1;
    hdr.osip.num_images = 1;
    hdr.osip.header_size = 56;

    hdr.osip.desc.logical_start_block = 1;
    hdr.osip.desc.ddr_load_address = 0x01100000;
    hdr.osip.desc.entry_point = 0x01101000;
    hdr.osip.desc.attribute = 0xd;

    hdr.mbr_sig = 0xaa55;

    /* header */
    strncpy((char *)hdr.cmdline, cmdline, CMDLINE_SIZE - 1);
    hdr.cmdline[CMDLINE_SIZE - 1] = '\0';
    hdr.console_dev_type = 0xff;
    hdr.reserved_flag_0 = 0x02bd02bd;
    hdr.reserved_flag_1 = 0x12bd12bd;

    /* bootstub */
    bootstub_data = load_file(bootstub_fn, &bootstub_size, 0);
    if(bootstub_data == 0) {
        fprintf(stderr,"error: could not load bootstub '%s'\n", bootstub_fn);
        return 1;
    }

    if (bootstub_size > BOOTSTUB_SIZE) {
        fprintf(stderr,"error: bootstub too large\n");
        return 1;
    }

    /* kernel */
    kernel_data = load_file(kernel_fn, &hdr.kernel_size, pagesize);
    if(kernel_data == 0) {
        fprintf(stderr,"error: could not load kernel '%s'\n", kernel_fn);
        return 1;
    }

    /* ramdisk */
    ramdisk_data = load_file(ramdisk_fn, &hdr.ramdisk_size, pagesize);
    if(ramdisk_data == 0) {
        fprintf(stderr,"error: could not load ramdisk '%s'\n", ramdisk_fn);
        return 1;
    }

    /* total size + checksum */
    hdr.osip.desc.size_of_os_image = (sizeof(hdr) + bootstub_size + hdr.kernel_size + hdr.ramdisk_size) / 512 - 1; // total size - mbr size (512 bytes aligned)
    hdr.osip.header_checksum = calc_checksum(&hdr, hdr.osip.header_size);

    /* write boot image */
    fd = open(bootimg, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if(fd < 0) {
        fprintf(stderr,"error: could not create '%s'\n", bootimg);
        return 1;
    }

    if(write(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) goto fail;
    if(write(fd, bootstub_data, bootstub_size) != (ssize_t) bootstub_size) goto fail;
    if(write(fd, kernel_data, hdr.kernel_size) != (ssize_t) hdr.kernel_size) goto fail;
    if(write(fd, ramdisk_data, hdr.ramdisk_size) != (ssize_t) hdr.ramdisk_size) goto fail;

    return 0;

fail:
    unlink(bootimg);
    close(fd);
    fprintf(stderr,"error: failed writing '%s': %s\n", bootimg,
            strerror(errno));
    return 1;
}
