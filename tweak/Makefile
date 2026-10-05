include $(THEOS)/makefiles/common.mk

TWEAK_NAME = iOSCaptureHook iOSCaptureDirect

iOSCaptureHook_FILES = Tweak.xm ICTLSHooks.mm ../shared/ICPreferences.m
iOSCaptureHook_FRAMEWORKS = Foundation Security UIKit
iOSCaptureHook_LIBRARIES = substrate
iOSCaptureHook_CFLAGS = -fobjc-arc -fblocks -I$(THEOS_PROJECT_DIR)/shared
iOSCaptureHook_CCFLAGS = $(iOSCaptureHook_CFLAGS) -std=c++17

iOSCaptureDirect_FILES = Tweak.xm ICTLSHooks.mm third_party/fishhook/fishhook.c
iOSCaptureDirect_FRAMEWORKS = Foundation Security UIKit
iOSCaptureDirect_CFLAGS = -fobjc-arc -fblocks -DIOSCAPTURE_DIRECT_INJECTION=1 -I$(THEOS_PROJECT_DIR)/shared -I$(THEOS_CURRENT_DIR)/third_party/fishhook
iOSCaptureDirect_CCFLAGS = $(iOSCaptureDirect_CFLAGS) -std=c++17

include $(THEOS_MAKE_PATH)/tweak.mk
