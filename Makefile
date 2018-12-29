ARCHS ?= arm64
target ?= iphone:latest:11.0
CFLAGS = -Iinclude
include $(THEOS)/makefiles/common.mk 

TOOL_NAME = inject
inject_CODESIGN_FLAGS = -Sentitlements.xml
inject_LIBRARIES = mis
inject_FRAMEWORKS = IOKit Security
inject_FILES = main.m inject.m patchfinder64.c kern_funcs.c

include $(THEOS_MAKE_PATH)/tool.mk
