ARCHS ?= arm64
include $(THEOS)/makefiles/common.mk 

TOOL_NAME = inject
inject_CODESIGN_FLAGS = -Hsha256 -Sentitlements.xml
inject_FRAMEWORKS = IOKit
inject_CFLAGS = -Wno-error=unused-function -Wno-error=unused-variable -Wno-error=missing-braces -Iinclude
inject_FILES = inject.c patchfinder64.c async_wake_ios/async_wake_ios/libjb/trav.c

include $(THEOS_MAKE_PATH)/tool.mk
