LOCAL_PATH := $(call my-dir)  
  
TARGET_PIE := true  
NDK_APP_PIE := true  
  
include $(CLEAR_VARS)  
  
# 需要编译的源码文件  
LOCAL_SRC_FILES := \  
  drizzleDumper.c  
LOCAL_C_INCLUDE := \  
  drizzleDumper.h \  
  definitions.h  
  
LOCAL_MODULE := drizzleDumper  
LOCAL_MODULE_TAGS := optional  
  
# Allow execution on android-16+  
# 支持PIE  
LOCAL_CFLAGS += -fPIE  
LOCAL_LDFLAGS += -fPIE -pie  
  
# 编译生成可执行ELF文件  
include $(BUILD_EXECUTABLE)  
  
include $(call all-makefiles-under,$(LOCAL_PATH))  