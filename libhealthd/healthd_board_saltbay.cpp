/*
 * Copyright (C) 2013 The Android Open Source Project
 * Copyright (C) 2016 The CyanogenMod Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <healthd.h>
#include <cutils/properties.h>

#include "minui/minui.h"

#define SHUTDOWN_PROP "init.shutdown_to_charging"
static bool charger_is_connected = false;

void healthd_board_init(struct healthd_config *)
{
}

#define STR_LEN    8
void healthd_board_mode_charger_draw_battery(
                struct android::BatteryProperties *batt_prop)
{
    char cap_str[STR_LEN];
    int x, y;
    int str_len_px;
    static int char_height = -1, char_width = -1;

    if (char_height == -1 && char_width == -1)
        gr_font_size(&char_width, &char_height);
    snprintf(cap_str, (STR_LEN - 1), "%d%%", batt_prop->batteryLevel);
    str_len_px = gr_measure(cap_str);
    x = (gr_fb_width() - str_len_px) / 2;
    y = (gr_fb_height() + char_height) / 2;
    gr_color(0xa4, 0xc6, 0x39, 255);
    gr_text(x, y, cap_str, 0);
}

int healthd_board_battery_update(struct android::BatteryProperties *props)
{
    bool new_is_connected = props->chargerAcOnline | props->chargerUsbOnline |
            props->chargerWirelessOnline | props->chargerDockAcOnline;
    if (new_is_connected != charger_is_connected) {
        charger_is_connected = new_is_connected;
        property_set(SHUTDOWN_PROP, charger_is_connected ? "1" : "0");
    }

    return 1;
}

void healthd_board_mode_charger_battery_update(struct android::BatteryProperties *)
{
}

void healthd_board_mode_charger_set_backlight(bool)
{
}

void healthd_board_mode_charger_init()
{
}
