/*
 * Copyright (C) 2015 The CyanogenMod Project
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

enum {
    PROFILE_POWER_SAVE = 0,
    PROFILE_BALANCED,
    PROFILE_HIGH_PERFORMANCE,
    PROFILE_MAX
};

typedef struct governor_settings {
    int boost;
    int boostpulse_duration;
    int go_hispeed_load;
    int hispeed_freq;
    int timer_rate;
    int above_hispeed_delay;
    int io_is_busy;
    int min_sample_time;
    char *target_loads;
    int scaling_min_freq;
    int scaling_max_freq;
} power_profile;

static power_profile profiles[PROFILE_MAX] = {
    [PROFILE_POWER_SAVE] = {
        .boost = 0,
        .boostpulse_duration = 0,
        .go_hispeed_load = 90,
        .hispeed_freq = 933000,
        .io_is_busy = 0,
        .target_loads = "95 1333000:99",
        .scaling_min_freq = 533000,
        .scaling_max_freq = 1333000,
    },
    [PROFILE_BALANCED] = {
        .boost = 0,
        .boostpulse_duration = 80000,
        .go_hispeed_load = 80,
        .hispeed_freq = 933000,
        .io_is_busy = 1,
        .target_loads = "85 1333000:95 1600000:99",
        .scaling_min_freq = 533000,
        .scaling_max_freq = 1600000,
    },
    [PROFILE_HIGH_PERFORMANCE] = {
        .boost = 1,
        .boostpulse_duration = 0,
        .go_hispeed_load = 99,
        .hispeed_freq = 1600000,
        .io_is_busy = 0,
        .target_loads = "90",
        .scaling_min_freq = 533000,
        .scaling_max_freq = 1600000,
    },
};
