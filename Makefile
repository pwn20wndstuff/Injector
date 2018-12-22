ARCHS ?= arm64
target ?= iphone:11.0:11.0
CFLAGS = -Iinclude
include $(THEOS)/makefiles/common.mk 

TOOL_NAME = inject
inject_CODESIGN_FLAGS = -Sentitlements.xml
inject_LIBRARIES = mis
inject_FRAMEWORKS = IOKit Security
inject_FILES = main.c inject.m patchfinder64.c kern_funcs.c

include $(THEOS_MAKE_PATH)/tool.mk
