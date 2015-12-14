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

DEVICE_PACKAGE_OVERLAYS += $(LOCAL_PATH)/overlay-lte

# GPS
PRODUCT_PACKAGES += \
    libshim_gps

PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/configs/gps.xml:system/etc/gps.xml \
    $(LOCAL_PATH)/configs/gps.conf:system/etc/gps.conf

# Init files
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/rootdir/init.lte.rc:root/init.lte.rc

# These are the hardware-specific features
PRODUCT_COPY_FILES += \
    frameworks/native/data/etc/android.hardware.location.gps.xml:system/etc/permissions/android.hardware.location.gps.xml

$(call inherit-product, vendor/dell/venue3x40-common/device-common-vendor-blobs-lte.mk)
