ARCHS ?= arm64
target ?= iphone:11.0:11.0
include $(THEOS)/makefiles/common.mk 

TOOL_NAME = inject
inject_CODESIGN_FLAGS = -Hsha256 -Hsha1 -Sentitlements.xml
inject_FRAMEWORKS = IOKit Security
inject_CFLAGS = -Wno-error=unused-function -Wno-error=unused-variable -Wno-error=missing-braces -Iinclude
inject_LIBRARIES = mis
inject_FILES = inject.m patchfinder64.c kern_funcs.c

include $(THEOS_MAKE_PATH)/tool.mk
