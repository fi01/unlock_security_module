LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
  main.c \
  kernel_memory.c \
  kallsyms.c \
  ptmx.c \
  mm.c \
  fops_handler.c \
  ccsecurity.c \
  reset_security_ops.c \
  lsm_capability.c

LOCAL_MODULE := unlock_security_module
LOCAL_MODULE_TAGS := optional
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_STATIC_LIBRARIES := libdiagexploit
LOCAL_STATIC_LIBRARIES += libperf_event_exploit
LOCAL_STATIC_LIBRARIES += libdevice_database
LOCAL_STATIC_LIBRARIES += libmsm_acdb_exploit
LOCAL_STATIC_LIBRARIES += libfj_hdcp_exploit
LOCAL_STATIC_LIBRARIES += libkallsyms
LOCAL_STATIC_LIBRARIES += libcutils libc

include $(BUILD_EXECUTABLE)

include $(call all-makefiles-under,$(LOCAL_PATH))
