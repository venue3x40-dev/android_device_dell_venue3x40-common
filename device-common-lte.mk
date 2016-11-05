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

# RIL
PRODUCT_PACKAGES += \
    libshim_tcs \
    ril-wrapper

PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/configs/repository7160.txt:system/etc/rril/repository7160.txt \
    $(LOCAL_PATH)/configs/mmgr_7160_conf_2.xml:system/etc/telephony/mmgr_7160_conf_2.xml \
    $(LOCAL_PATH)/configs/telephony_scalability.xml:system/etc/telephony/telephony_scalability.xml

PRODUCT_PROPERTY_OVERRIDES += \
    ro.telephony.ril_class=Venue3x40RIL \
    rild.libpath=/system/lib/ril-wrapper.so \
    ro.telephony.default_network=9 \
    telephony.lteOnGsmDevice=1 \
    \
    audiocomms.modemLib=libmamgr-xmm.so \
    audiocomms.XMM.primaryChannel=/dev/gsmtty13

# Init files
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/rootdir/init.lte.rc:root/init.lte.rc

# These are the hardware-specific features
PRODUCT_COPY_FILES += \
    frameworks/native/data/etc/android.hardware.location.gps.xml:system/etc/permissions/android.hardware.location.gps.xml \
    frameworks/native/data/etc/android.hardware.telephony.gsm.xml:system/etc/permissions/android.hardware.telephony.gsm.xml

$(call inherit-product, vendor/dell/venue3x40-common/device-common-vendor-blobs-lte.mk)
