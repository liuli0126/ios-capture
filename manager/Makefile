include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = iOSCapture

iOSCapture_FILES = main.m AppDelegate.m RootViewController.m ../shared/ICPreferences.m
iOSCapture_FRAMEWORKS = Foundation UIKit Security
iOSCapture_CFLAGS = -fobjc-arc -fblocks -I$(THEOS_PROJECT_DIR)/shared
iOSCapture_RESOURCE_DIRS = Resources
iOSCapture_CODESIGN_FLAGS = -S$(THEOS_PROJECT_DIR)/manager/entitlements.plist

include $(THEOS_MAKE_PATH)/application.mk
