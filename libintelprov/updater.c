/*
 * Copyright 2011-2013 Intel Corporation
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
 */

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mman.h>
#include "update_osip.h"
#include "util.h"
#include "edify/expr.h"

Value *FlashOSImage(const char *name, State *state, int argc, Expr *argv[]) {
    Value *funret = NULL;
    char *filename, *image_name;
    void *data;
    int ret;

    if (argc != 2) {
        ErrorAbort(state, "%s: Invalid parameters.", name);
        goto exit;
    }

    if (ReadArgs(state, argv, 2, &filename, &image_name) < 0) {
        ErrorAbort(state, "%s: ReadArgs failed.", name);
        goto exit;
    }

    int length = file_size(filename);
    if (length == -1)
        goto free;

    data = file_mmap(filename, length, true);
    if (data == MAP_FAILED)
        goto free;

    int index = get_named_osii_index(image_name);

    if (index < 0) {
        ErrorAbort(state, "%s: Can't find OSII index!", name);
        goto unmap;
    }

    ret = write_stitch_image(data, length, index);

    if (ret != 0) {
        ErrorAbort(state, "%s: Failed to flash %s image %s, %s.",
                   name, filename, image_name, strerror(errno));
        goto unmap;
    }

    funret = StringValue(strdup(""));

unmap:
    munmap(data, length);
free:
    free(filename);
    free(image_name);
exit:
    return funret;
}

void Register_libintel_updater(void)
{
    RegisterFunction("flash_os_image", FlashOSImage);
}
