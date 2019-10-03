# Copyright (C) 2007 The Android Open Source Project
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
# wangxf14 modify for lenovo recovery 
#
LENOVO_RECOVERY_SUPPORT=yes
LENOVO_SHARED_SDCARD=yes
LENOVO_FACTORY_WIPE_DATA_SHUTDOWN=yes
ifneq ($(LENOVO_RECOVERY_SUPPORT),yes)
# LENOVO_RECOVERY_SUPPORT no begin

LOCAL_PATH := $(call my-dir)


include $(CLEAR_VARS)

LOCAL_SRC_FILES := fuse_sideload.c

LOCAL_CFLAGS := -O2 -g -DADB_HOST=0 -Wall -Wno-unused-parameter
LOCAL_CFLAGS += -D_XOPEN_SOURCE -D_GNU_SOURCE

LOCAL_MODULE := libfusesideload

LOCAL_STATIC_LIBRARIES := libcutils libc libmincrypt
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
    adb_install.cpp \
    asn1_decoder.cpp \
    bootloader.cpp \
    device.cpp \
    fuse_sdcard_provider.c \
    install.cpp \
    recovery.cpp \
    roots.cpp \
    screen_ui.cpp \
    ui.cpp \
    verifier.cpp \

LOCAL_MODULE := recovery

LOCAL_FORCE_STATIC_EXECUTABLE := true

ifeq ($(HOST_OS),linux)
LOCAL_REQUIRED_MODULES := mkfs.f2fs
endif

RECOVERY_API_VERSION := 3
RECOVERY_FSTAB_VERSION := 2
LOCAL_CFLAGS += -DRECOVERY_API_VERSION=$(RECOVERY_API_VERSION)
LOCAL_CFLAGS += -Wno-unused-parameter

LOCAL_C_INCLUDES += \
    system/vold \
    system/extras/ext4_utils \
    system/core/adb \

LOCAL_STATIC_LIBRARIES := \
    libext4_utils_static \
    libsparse_static \
    libminzip \
    libz \
    libmtdutils \
    libmincrypt \
    libminadbd \
    libfusesideload \
    libminui \LOCAL_MODULE_TAGS
    libpng \
    libfs_mgr \
    libbase \
    libcutils \
    liblog \
    libselinux \
    libstdc++ \
    libutils \
    libm \
    libc

ifeq ($(TARGET_USERIMAGES_USE_EXT4), true)
    LOCAL_CFLAGS += -DUSE_EXT4
    LOCAL_C_INCLUDES += system/extras/ext4_utils
    LOCAL_STATIC_LIBRARIES += libext4_utils_static libz
endif

LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/sbin

ifeq ($(TARGET_USE_MDTP), true)
    LOCAL_CFLAGS += -DUSE_MDTP
endif

ifeq ($(TARGET_RECOVERY_UI_LIB),)
  LOCAL_SRC_FILES += default_device.cpp
else
  LOCAL_STATIC_LIBRARIES += $(TARGET_RECOVERY_UI_LIB)
endif

include $(BUILD_EXECUTABLE)

# All the APIs for testing
include $(CLEAR_VARS)
LOCAL_MODULE := libverifier
LOCAL_MODULE_TAGS := tests
LOCAL_SRC_FILES := \
    asn1_decoder.cpp
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := verifier_test
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_TAGS := tests
LOCAL_CFLAGS += -Wno-unused-parameter
LOCAL_SRC_FILES := \
    verifier_test.cpp \
    asn1_decoder.cpp \
    verifier.cpp \
    ui.cpp
LOCAL_STATIC_LIBRARIES := \
    libmincrypt \
    libminui \
    libminzip \
    libcutils \
    libstdc++ \
    libc
include $(BUILD_EXECUTABLE)


include $(LOCAL_PATH)/minui/Android.mk \
    $(LOCAL_PATH)/minzip/Android.mk \
    $(LOCAL_PATH)/minadbd/Android.mk \
    $(LOCAL_PATH)/mtdutils/Android.mk \
    $(LOCAL_PATH)/tests/Android.mk \
    $(LOCAL_PATH)/tools/Android.mk \
    $(LOCAL_PATH)/edify/Android.mk \
    $(LOCAL_PATH)/uncrypt/Android.mk \
    $(LOCAL_PATH)/updater/Android.mk \
    $(LOCAL_PATH)/applypatch/Android.mk
# LENOVO_RECOVERY_SUPPORT no end
else
# LENOVO_RECOVERY_SUPPORT yes begin
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_SRC_FILES := fuse_sideload.c
LOCAL_CFLAGS := -O2 -g -DADB_HOST=0 -Wall -Wno-unused-parameter
LOCAL_CFLAGS += -D_XOPEN_SOURCE -D_GNU_SOURCE
LOCAL_MODULE := libfusesideload
LOCAL_STATIC_LIBRARIES := libcutils libc libmincrypt
include $(BUILD_STATIC_LIBRARY)
include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
    lenovo_recovery.cpp \
    bootloader.cpp \
    install.cpp \
    roots.cpp \
    ui.cpp \
    screen_ui.cpp \
    asn1_decoder.cpp \
    recovery_ui.cpp \
    verifier.cpp \
    adb_install.cpp \
    fuse_sdcard_provider.c
# Begin, modify for lenovo recovery 
ifeq ($(LENOVO_SHARED_SDCARD),yes)
LOCAL_SRC_FILES += \
    rm-ex.c
endif
# End, lenovo-sw wangxf14 porting
LOCAL_MODULE := recovery
LOCAL_FORCE_STATIC_EXECUTABLE := true
ifeq ($(HOST_OS),linux)
LOCAL_REQUIRED_MODULES := mkfs.f2fs
endif
RECOVERY_API_VERSION := 3
RECOVERY_FSTAB_VERSION := 2
LOCAL_CFLAGS += -DRECOVERY_API_VERSION=$(RECOVERY_API_VERSION)
LOCAL_CFLAGS += -Wno-unused-parameter
LOCAL_STATIC_LIBRARIES := \
    libext4_utils_static \
    libsparse_static \
    libminzip \
    libz \
    libmtdutils \
    libmincrypt \
    libminadbd \
    libfusesideload \
    libminui \
    libpng \
    libfs_mgr \
    libcutils \
    liblog \
    libselinux \
    libstdc++ \
    libm \
    libc

LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/sbin

ifeq ($(LENOVO_RECOVERY_SUPPORT),yes)
LOCAL_STATIC_LIBRARIES += \
	libmiui \
	libm
MYDEFINE_CFLAGS := \
	-D_GLIBCXX_DEBUG_PEDANTIC \
	-DFT2_BUILD_LIBRARY=1 \
	-DDARWIN_NO_CARBON \
	-D_MIUI_NODEBUG=1
LOCAL_CFLAGS += $(MYDEFINE_CFLAGS)
LOCAL_CFLAGS += -DLENOVO_RECOVERY_SUPPORT
LOCAL_CFLAGS += -DLENOVO_SHARED_SDCARD
LOCAL_CFLAGS += -DLENOVO_FACTORY_WIPE_DATA_SHUTDOWN
LOCAL_CFLAGS += -DLENOVO_OTA_AUTO_TEST
endif
ifeq ($(LENOVO_EXFAT),true)
LOCAL_CFLAGS += -DLENOVO_EXFAT
endif
ifeq ($(TARGET_USERIMAGES_USE_EXT4), true)
    LOCAL_CFLAGS += -DUSE_EXT4
    LOCAL_C_INCLUDES += system/extras/ext4_utils system/vold
    LOCAL_STATIC_LIBRARIES += libext4_utils_static libz
endif
# This binary is in the recovery ramdisk, which is otherwise a copy of root.
# It gets copied there in config/Makefile.  LOCAL_MODULE_TAGS suppresses
# a (redundant) copy of the binary in /system/bin for user builds.
# TODO: Build the ramdisk image in a more principled way.
LOCAL_MODULE_TAGS := eng
ifeq ($(TARGET_RECOVERY_UI_LIB),)
  LOCAL_SRC_FILES += default_device.cpp
else
  LOCAL_STATIC_LIBRARIES += $(TARGET_RECOVERY_UI_LIB)
endif
LOCAL_C_INCLUDES += system/extras/ext4_utils
LOCAL_C_INCLUDES += external/openssl/include
include $(BUILD_EXECUTABLE)
# All the APIs for testing
include $(CLEAR_VARS)
LOCAL_MODULE := libverifier
LOCAL_MODULE_TAGS := tests
LOCAL_SRC_FILES := \
    asn1_decoder.cpp
include $(BUILD_STATIC_LIBRARY)
include $(CLEAR_VARS)
LOCAL_MODULE := verifier_test
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_TAGS := tests
LOCAL_CFLAGS += -DNO_RECOVERY_MOUNT
LOCAL_CFLAGS += -Wno-unused-parameter
LOCAL_CFLAGS += -DVERIFIER_TEST
LOCAL_SRC_FILES := \
    verifier_test.cpp \
    asn1_decoder.cpp \
    verifier.cpp \
    ui.cpp
LOCAL_STATIC_LIBRARIES := \
    libmincrypt \
    libminui \
    libminzip \
    libcutils \
    libstdc++ \
    libc
include $(BUILD_EXECUTABLE)
include $(LOCAL_PATH)/minui/Android.mk \
    $(LOCAL_PATH)/minzip/Android.mk \
    $(LOCAL_PATH)/minadbd/Android.mk \
    $(LOCAL_PATH)/mtdutils/Android.mk \
    $(LOCAL_PATH)/tests/Android.mk \
    $(LOCAL_PATH)/tools/Android.mk \
    $(LOCAL_PATH)/edify/Android.mk \
    $(LOCAL_PATH)/uncrypt/Android.mk \
    $(LOCAL_PATH)/updater/Android.mk \
    $(LOCAL_PATH)/applypatch/Android.mk
ifeq ($(LENOVO_RECOVERY_SUPPORT),yes)
include $(LOCAL_PATH)/../miui/Android.mk
endif
## LENOVO_RECOVERY_SUPPORT yes end
endif