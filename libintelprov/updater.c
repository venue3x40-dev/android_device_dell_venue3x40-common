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
    int length;

    Value *contents;
    Value *image_name_value;

    if (argc != 2) {
        ErrorAbort(state, "%s: Invalid parameters.", name);
        goto exit;
    }

    if (ReadValueArgs(state, argv, 2, &contents, &image_name_value) < 0) {
        ErrorAbort(state, "%s: ReadValueArgs failed.", name);
        goto exit;
    }

    image_name = image_name_value->data;

    if (contents->type == VAL_STRING) {
        filename = contents->data;

        length = file_size(filename);
        if (length == -1)
            goto free;

        data = file_mmap(filename, length, true);
        if (data == MAP_FAILED)
            goto free;
    } else {
        data = contents->data;
        length = contents->size;
    }

    int index = get_named_osii_index(image_name);

    if (index < 0) {
        ErrorAbort(state, "%s: Can't find OSII index!", name);
        goto unmap;
    }

    ret = write_stitch_image(data, length, index);

    if (ret != 0) {
        ErrorAbort(state, "%s: Failed to flash %s image, %s.",
                   name, image_name, strerror(errno));
        goto unmap;
    }

    funret = StringValue(strdup(""));

unmap:
    if (contents->type == VAL_STRING)
        munmap(data, length);
free:
    FreeValue(contents);
    FreeValue(image_name_value);
exit:
    return funret;
}

void Register_libintel_updater(void)
{
    RegisterFunction("write_osip_image", FlashOSImage);
}
