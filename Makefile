ARCHS = arm64 arm64e
TARGET ?= iphone:clang:16.5:15.0

include $(THEOS)/makefiles/common.mk

SUBPROJECTS += tweak manager

include $(THEOS_MAKE_PATH)/aggregate.mk
