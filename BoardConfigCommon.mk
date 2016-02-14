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
TARGET_CPU_SMP := true

TARGET_BOARD_PLATFORM := merrifield
TARGET_BOOTLOADER_BOARD_NAME := merrifield

# Kernel
TARGET_KERNEL_SOURCE := kernel/dell/venue3x40
TARGET_KERNEL_CONFIG := twrp_venue3x40_defconfig

TARGET_KERNEL_CROSS_COMPILE_PREFIX := x86_64-linux-android-
BOARD_KERNEL_IMAGE_NAME := bzImage

BOARD_KERNEL_CMDLINE := init=/init pci=noearly loglevel=0 vmalloc=256M androidboot.hardware=saltbay
BOARD_KERNEL_CMDLINE += watchdog.watchdog_thresh=60 androidboot.spid=xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
BOARD_KERNEL_CMDLINE += androidboot.serialno=012345678901234567890123456789
BOARD_KERNEL_CMDLINE += snd_pcm.maximum_substreams=8 ip=50.0.0.2:50.0.0.1::255.255.255.0::usb0:on

# Custom mkbootimg
BOARD_CUSTOM_MKBOOTIMG := mkosimage
BOARD_MKBOOTIMG_ARGS += --bootstub device/dell/venue3x40-common/bootstub

BOARD_CUSTOM_BOOTIMG_MK := device/dell/venue3x40-common/custombootimg.mk

# Filesystem
TARGET_USERIMAGES_USE_EXT4 := true
TARGET_USERIMAGES_USE_F2FS := true
TW_INCLUDE_NTFS_3G := true
TW_NO_EXFAT_FUSE := true                          # Use native exFat driver

BOARD_SYSTEMIMAGE_PARTITION_SIZE   := 1610612736
BOARD_USERDATAIMAGE_PARTITION_SIZE := 11802754048
BOARD_CACHEIMAGE_PARTITION_SIZE    := 1610612736

BOARD_FLASH_BLOCK_SIZE := 2048

# Recovery
TW_THEME := portrait_hdpi
RECOVERY_GRAPHICS_USE_LINELENGTH := true
TARGET_RECOVERY_PIXEL_FORMAT := "BGRA_8888"
TW_MAX_BRIGHTNESS := 100
TW_INPUT_BLACKLIST := lis3dh_acc

TARGET_RECOVERY_FSTAB := device/dell/venue3x40-common/recovery.fstab

BOARD_UMS_LUNFILE := "/sys/class/android_usb/f_mass_storage/lun/file"
TW_CUSTOM_BATTERY_PATH := "/sys/class/power_supply/bq27441_battery"

BOARD_HAS_NO_REAL_SDCARD := true
RECOVERY_SDCARD_ON_DATA := true
TW_INCLUDE_CRYPTO := true
