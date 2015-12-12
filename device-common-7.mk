#
# Copyright 2013 The Android Open-Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_PATH := device/dell/venue3x40-common

PRODUCT_PROPERTY_OVERRIDES += \
    ro.sf.lcd_density=213

# Audio
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/configs/parameter-framework/ParameterFrameworkConfiguration.xml:system/etc/parameter-framework/ParameterFrameworkConfiguration.xml \
    $(LOCAL_PATH)/configs/parameter-framework/Settings/Audio/AudioConfigurableDomains.xml:system/etc/parameter-framework/Settings/Audio/AudioConfigurableDomains.xml

# Camera
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/configs/camera_profiles_708.xml:system/etc/camera_profiles_708.xml \
    $(LOCAL_PATH)/configs/media_profiles_708.xml:system/etc/media_profiles.xml
