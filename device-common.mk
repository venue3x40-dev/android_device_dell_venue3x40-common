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

# Video
PRODUCT_PACKAGES += \
    libdrm \
    libgccdemangle \
    libstlport \
    pvrsrvctl

# Init files
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/rootdir/init.saltbay.rc:root/init.saltbay.rc \
    $(LOCAL_PATH)/rootdir/init.saltbay.usb.rc:root/init.saltbay.usb.rc \
    $(LOCAL_PATH)/rootdir/ueventd.saltbay.rc:root/ueventd.saltbay.rc \
    $(LOCAL_PATH)/rootdir/fstab.saltbay:root/fstab.saltbay

# These are the hardware-specific features
PRODUCT_COPY_FILES += \
    frameworks/native/data/etc/tablet_core_hardware.xml:system/etc/permissions/tablet_core_hardware.xml \
    frameworks/native/data/etc/android.hardware.touchscreen.multitouch.jazzhand.xml:system/etc/permissions/android.hardware.touchscreen.multitouch.jazzhand.xml

PRODUCT_CHARACTERISTICS := tablet

$(call inherit-product, frameworks/native/build/tablet-dalvik-heap.mk)

$(call inherit-product, vendor/dell/venue3x40-common/device-common-vendor-blobs.mk)