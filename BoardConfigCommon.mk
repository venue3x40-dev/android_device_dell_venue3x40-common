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

TARGET_BOARD_PLATFORM := merrifield
TARGET_BOOTLOADER_BOARD_NAME := merrifield

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
BOARD_KERNEL_CMDLINE += androidboot.selinux=disabled

# Custom mkbootimg
BOARD_CUSTOM_MKBOOTIMG := mkosimage
BOARD_MKBOOTIMG_ARGS += --bootstub device/dell/venue3x40-common/bootstub

# Filesystem
TARGET_USERIMAGES_USE_EXT4 := true

BOARD_SYSTEMIMAGE_PARTITION_SIZE   := 1610612736

BOARD_FLASH_BLOCK_SIZE := 2048

# OpenGL
USE_OPENGL_RENDERER := true
TARGET_REQUIRES_SYNCHRONOUS_SETSURFACE := true

# Recovery
TARGET_RECOVERY_FSTAB := device/dell/venue3x40-common/rootdir/fstab.saltbay
