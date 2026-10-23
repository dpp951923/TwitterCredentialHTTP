TARGET := iphone:clang:latest:15.0
ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = TwitterCredentialHTTP
TwitterCredentialHTTP_FILES = Tweak.xm
TwitterCredentialHTTP_CFLAGS = -fobjc-arc
TwitterCredentialHTTP_FRAMEWORKS = Foundation Security
TwitterCredentialHTTP_FILTER = com.atebits.Tweetie2

include $(THEOS_MAKE_PATH)/tweak.mk
