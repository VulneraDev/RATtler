SDKROOT := $(shell xcrun --sdk macosx --show-sdk-path)
BUILD_DIR := build
TARGET := $(BUILD_DIR)/rattler-es-sensor
SOURCE := Sources/rattler_es_sensor.c

.PHONY: all clean sign

all: $(TARGET)

$(TARGET): $(SOURCE)
	mkdir -p $(BUILD_DIR)
	xcrun --sdk macosx clang -fblocks -std=c11 -Wall -Wextra -Werror \
		-mmacosx-version-min=11.3 -isysroot "$(SDKROOT)" \
		-lEndpointSecurity -lbsm $(SOURCE) -o $(TARGET)

sign: $(TARGET)
	@test -n "$(IDENTITY)" || (echo "Set IDENTITY to an approved Developer ID signing identity" && exit 2)
	codesign --force --options runtime --timestamp \
		--entitlements RATtlerESSensor.entitlements \
		--sign "$(IDENTITY)" $(TARGET)

clean:
	rm -rf $(BUILD_DIR)
