include $(THEOS)/makefiles/common.mk

TWEAK_NAME = iOSCaptureHook

iOSCaptureHook_FILES = Tweak.xm ICTLSHooks.mm ../shared/ICPreferences.m
iOSCaptureHook_FRAMEWORKS = Foundation Security UIKit
iOSCaptureHook_LIBRARIES = substrate
iOSCaptureHook_CFLAGS = -fobjc-arc -fblocks -I$(THEOS_PROJECT_DIR)/../shared
iOSCaptureHook_CCFLAGS = $(iOSCaptureHook_CFLAGS) -std=c++17

include $(THEOS_MAKE_PATH)/tweak.mk
