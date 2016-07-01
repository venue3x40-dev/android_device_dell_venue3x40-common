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

# Architecture
TARGET_ARCH := x86
TARGET_ARCH_VARIANT := silvermont
TARGET_CPU_ABI := x86

ENABLE_CPUSETS := true

TARGET_BOARD_PLATFORM := merrifield
TARGET_BOOTLOADER_BOARD_NAME := merrifield

TARGET_USES_64_BIT_BINDER := true

# Houdini
TARGET_CPU_ABI2 := armeabi-v7a
TARGET_CPU_ABI_LIST_32_BIT := x86,armeabi-v7a,armeabi
BUILD_ARM_FOR_X86 := true

# Specific headers
TARGET_BOARD_KERNEL_HEADERS := device/dell/venue3x40-common/kernel-headers
TARGET_SPECIFIC_HEADER_PATH := device/dell/venue3x40-common/include

# Inline kernel building
TARGET_KERNEL_SOURCE := kernel/dell/venue3x40
TARGET_KERNEL_CONFIG := cyanogenmod_venue3x40_defconfig

KERNEL_TOOLCHAIN_PREFIX := x86_64-linux-android-
BOARD_KERNEL_IMAGE_NAME := bzImage

# Kernel
BOARD_KERNEL_CMDLINE := init=/init pci=noearly loglevel=0 vmalloc=256M androidboot.hardware=saltbay
BOARD_KERNEL_CMDLINE += watchdog.watchdog_thresh=60 androidboot.spid=xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
BOARD_KERNEL_CMDLINE += androidboot.serialno=012345678901234567890123456789
BOARD_KERNEL_CMDLINE += snd_pcm.maximum_substreams=8 ip=50.0.0.2:50.0.0.1::255.255.255.0::usb0:on
BOARD_KERNEL_CMDLINE += androidboot.selinux=permissive

# Custom mkbootimg
BOARD_CUSTOM_MKBOOTIMG := mkosimage
BOARD_MKBOOTIMG_ARGS += --bootstub device/dell/venue3x40-common/bootstub

# Filesystem
TARGET_KERNEL_HAVE_EXFAT := true

TARGET_USERIMAGES_USE_EXT4 := true

BOARD_SYSTEMIMAGE_PARTITION_SIZE   := 1610612736
BOARD_USERDATAIMAGE_PARTITION_SIZE := 11802754048
BOARD_CACHEIMAGE_PARTITION_SIZE    := 1610612736

BOARD_FLASH_BLOCK_SIZE := 2048

# Dexopt
ifeq ($(HOST_OS),linux)
  ifeq ($(WITH_DEXPREOPT),)
    WITH_DEXPREOPT := true
  endif
endif

# Video
ENABLE_IMG_GRAPHICS := true
INTEL_HWC_MERRIFIELD := true
TARGET_DISABLE_CURSOR_LAYER := true

# Multimedia
BUILD_WITH_FULL_STAGEFRIGHT := true
INTEL_VA := true
ENABLE_MRFL_GRAPHICS := true
BOARD_USES_WRS_OMXIL_CORE := true
BOARD_USES_MRST_OMX := true
TARGET_HAS_VPP := true
USE_HW_VP8 := true

COMMON_GLOBAL_CFLAGS += -DMIXVBP_KK_BLOBS

# Camera
INTEL_VIDEO_XPROC_SHARING := true

# Wifi
BOARD_WLAN_DEVICE                := bcmdhd
WPA_SUPPLICANT_VERSION           := VER_0_8_X
BOARD_WPA_SUPPLICANT_DRIVER      := NL80211
BOARD_WPA_SUPPLICANT_PRIVATE_LIB := lib_driver_cmd_bcmdhd
BOARD_HOSTAPD_DRIVER             := NL80211
BOARD_HOSTAPD_PRIVATE_LIB        := lib_driver_cmd_bcmdhd
WIFI_DRIVER_FW_PATH_PARAM        := "/sys/module/bcm4335/parameters/firmware_path"
WIFI_DRIVER_FW_PATH_STA          := "/vendor/firmware/fw_bcmdhd.bin"
WIFI_DRIVER_FW_PATH_AP           := "/vendor/firmware/fw_bcmdhd_apsta.bin"

# Bluetooth
BOARD_HAVE_BLUETOOTH := true
BOARD_HAVE_BLUETOOTH_BCM := true
BOARD_BLUEDROID_VENDOR_CONF := device/dell/venue3x40-common/bluetooth/vnd_venue3x40.txt

# OpenGL
USE_OPENGL_RENDERER := true
TARGET_REQUIRES_SYNCHRONOUS_SETSURFACE := true

# Charger mode
BOARD_CHARGER_ENABLE_SUSPEND := true
BOARD_HEALTHD_CUSTOM_CHARGER_RES := device/dell/venue3x40-common/charger/images

# Healthd
BOARD_HAL_STATIC_LIBRARIES := libhealthd.saltbay

# Recovery
TARGET_RECOVERY_FSTAB := device/dell/venue3x40-common/rootdir/fstab.saltbay
