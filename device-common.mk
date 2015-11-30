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

DEVICE_PACKAGE_OVERLAYS += $(LOCAL_PATH)/overlay

# Houdini
ADDITIONAL_DEFAULT_PROPERTIES += \
    ro.dalvik.vm.native.bridge=libhoudini.so

PRODUCT_PROPERTY_OVERRIDES += \
    ro.dalvik.vm.isa.arm=x86 \
    ro.enable.native.bridge.exec=1

# Video
PRODUCT_PACKAGES += \
    libdrm \
    libgccdemangle \
    libstlport \
    pvrsrvctl

PRODUCT_PACKAGES += \
    libcorkscrew \
    libva \
    libva-android \
    libva-tpi \
    libwsbm

PRODUCT_PROPERTY_OVERRIDES += \
    ro.opengles.version=196608

# Audio
PRODUCT_PACKAGES += \
    libshim_audio \
    \
    audio.a2dp.default \
    audio.r_submix.default \
    audio.usb.default

PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/configs/audio_policy.conf:system/etc/audio_policy.conf \
    $(LOCAL_PATH)/configs/libdsp_config.xml:system/etc/libdsp_config.xml \
    $(LOCAL_PATH)/configs/parameter-framework/Structure/Audio/AudioClass.xml:system/etc/parameter-framework/Structure/Audio/AudioClass.xml \
    $(LOCAL_PATH)/configs/parameter-framework/Structure/Audio/ConfigurationSubsystem.xml:system/etc/parameter-framework/Structure/Audio/ConfigurationSubsystem.xml \
    $(LOCAL_PATH)/configs/parameter-framework/Structure/Audio/DSPSubsystem.xml:system/etc/parameter-framework/Structure/Audio/DSPSubsystem.xml \
    $(LOCAL_PATH)/configs/parameter-framework/Structure/Audio/IMCSubsystem.xml:system/etc/parameter-framework/Structure/Audio/IMCSubsystem.xml \
    $(LOCAL_PATH)/configs/parameter-framework/Structure/Audio/PowerSubsystem.xml:system/etc/parameter-framework/Structure/Audio/PowerSubsystem.xml \
    $(LOCAL_PATH)/configs/parameter-framework/Structure/Audio/SysfsAudioSubsystem.xml:system/etc/parameter-framework/Structure/Audio/SysfsAudioSubsystem.xml \
    $(LOCAL_PATH)/configs/parameter-framework/Structure/Audio/UTASubsystem.xml:system/etc/parameter-framework/Structure/Audio/UTASubsystem.xml \
    $(LOCAL_PATH)/configs/parameter-framework/Structure/Audio/VirtualDevicesSubsystem.xml:system/etc/parameter-framework/Structure/Audio/VirtualDevicesSubsystem.xml \
    $(LOCAL_PATH)/configs/parameter-framework/Structure/Audio/WM8958Subsystem.xml:system/etc/parameter-framework/Structure/Audio/WM8958Subsystem.xml

# Multimedia
PRODUCT_PACKAGES += \
    libstagefrighthw \
    \
    libisv_omx_core \
    \
    libwrs_omxil_common \
    libwrs_omxil_core_pvwrapped \
    \
    libva_videodecoder \
    libva_videoencoder \
    \
    libOMXVideoDecoderAVC \
    libOMXVideoDecoderH263 \
    libOMXVideoDecoderMPEG4 \
    libOMXVideoDecoderVP8 \
    libOMXVideoEncoderAVC \
    \
    pvr_drv_video

PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/configs/media_codecs.xml:system/etc/media_codecs.xml \
    frameworks/av/media/libstagefright/data/media_codecs_google_audio.xml:system/etc/media_codecs_google_audio.xml \
    frameworks/av/media/libstagefright/data/media_codecs_google_telephony.xml:system/etc/media_codecs_google_telephony.xml \
    frameworks/av/media/libstagefright/data/media_codecs_google_video.xml:system/etc/media_codecs_google_video.xml \
    $(LOCAL_PATH)/configs/wrs_omxil_components.list:system/etc/wrs_omxil_components.list

# Wifi
PRODUCT_PACKAGES += \
    dhcpcd.conf \
    wpa_supplicant \
    wpa_supplicant.conf \
    hostapd

PRODUCT_PROPERTY_OVERRIDES += \
    wifi.interface=wlan0

include hardware/broadcom/wlan/bcmdhd/firmware/bcm4339/device-bcm.mk

# Sensors
PRODUCT_PACKAGES += \
    sensors.saltbay

# Lights
PRODUCT_PACKAGES += \
    lights.saltbay

# Init files
PRODUCT_COPY_FILES += \
    $(LOCAL_PATH)/rootdir/init.saltbay.rc:root/init.saltbay.rc \
    $(LOCAL_PATH)/rootdir/init.saltbay.usb.rc:root/init.saltbay.usb.rc \
    $(LOCAL_PATH)/rootdir/ueventd.saltbay.rc:root/ueventd.saltbay.rc \
    $(LOCAL_PATH)/rootdir/fstab.saltbay:root/fstab.saltbay

# Charger mode
PRODUCT_PACKAGES += \
    charger_res_images

# These are the hardware-specific features
PRODUCT_COPY_FILES += \
    frameworks/native/data/etc/tablet_core_hardware.xml:system/etc/permissions/tablet_core_hardware.xml \
    frameworks/native/data/etc/android.hardware.touchscreen.multitouch.jazzhand.xml:system/etc/permissions/android.hardware.touchscreen.multitouch.jazzhand.xml \
    frameworks/native/data/etc/android.hardware.usb.host.xml:system/etc/permissions/android.hardware.usb.host.xml \
    frameworks/native/data/etc/android.hardware.wifi.xml:system/etc/permissions/android.hardware.wifi.xml \
    frameworks/native/data/etc/android.hardware.wifi.direct.xml:system/etc/permissions/android.hardware.wifi.direct.xml \
    frameworks/native/data/etc/android.hardware.bluetooth.xml:system/etc/permissions/android.hardware.bluetooth.xml \
    frameworks/native/data/etc/android.hardware.bluetooth_le.xml:system/etc/permissions/android.hardware.bluetooth_le.xml \
    frameworks/native/data/etc/android.hardware.sensor.accelerometer.xml:system/etc/permissions/android.hardware.sensor.accelerometer.xml \
    frameworks/native/data/etc/android.hardware.sensor.light.xml:system/etc/permissions/android.hardware.sensor.light.xml

PRODUCT_CHARACTERISTICS := tablet

$(call inherit-product, frameworks/native/build/tablet-dalvik-heap.mk)

$(call inherit-product, vendor/dell/venue3x40-common/device-common-vendor-blobs.mk)
