LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  main.c \
  kernel_memory.c \
  kallsyms.c \
  ptmx.c \
  mm.c \
  fops_handler.c \
  mmc_protect_part.c \
  ccsecurity.c \
  reset_security_ops.c \
  lsm_capability.c \
  mmap.c

LOCAL_MODULE := unlock_security_module
LOCAL_MODULE_TAGS := optional
LOCAL_STATIC_LIBRARIES := libdiagexploit
LOCAL_STATIC_LIBRARIES += libperf_event_exploit
LOCAL_STATIC_LIBRARIES += libdevice_database
LOCAL_STATIC_LIBRARIES += libmsm_acdb_exploit
LOCAL_STATIC_LIBRARIES += libfj_hdcp_exploit
LOCAL_STATIC_LIBRARIES += libfb_mem_exploit
LOCAL_STATIC_LIBRARIES += libput_user_exploit
LOCAL_STATIC_LIBRARIES += libkallsyms
LOCAL_STATIC_LIBRARIES += libz_static
LOCAL_LDFLAGS += -static

TOP_SRCDIR := $(abspath $(LOCAL_PATH))
TARGET_C_INCLUDES += \
  $(TOP_SRCDIR)/device_database

include $(BUILD_EXECUTABLE)

include $(call all-makefiles-under,$(LOCAL_PATH))
