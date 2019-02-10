ARCHS ?= arm64
target ?= iphone:latest:11.0
CFLAGS = -Iinclude
GO_EASY_ON_ME=1
include $(THEOS)/makefiles/common.mk 

TOOL_NAME = inject
inject_CODESIGN_FLAGS = -Sentitlements.xml
inject_CFLAGS += -I./patchfinder64 -Wno-unused-variable -Wno-unused-function
inject_LIBRARIES = mis
inject_FRAMEWORKS = IOKit Security
inject_FILES = main.m inject.m patchfinder64/patchfinder64.c kern_funcs.c

include $(THEOS_MAKE_PATH)/tool.mk
