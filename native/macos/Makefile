SDKROOT := $(shell xcrun --sdk macosx --show-sdk-path)
BUILD_DIR := build
TARGET := $(BUILD_DIR)/rattler-es-sensor
GUARD_TARGET := $(BUILD_DIR)/rattler-es-guard
SOURCE := Sources/rattler_es_sensor.c
GUARD_SOURCE := Sources/rattler_es_guard.c

.PHONY: all clean sign

all: $(TARGET) $(GUARD_TARGET)

$(TARGET): $(SOURCE)
	mkdir -p $(BUILD_DIR)
	xcrun --sdk macosx clang -fblocks -std=c11 -Wall -Wextra -Werror \
		-mmacosx-version-min=11.3 -isysroot "$(SDKROOT)" \
		-lEndpointSecurity -lbsm $(SOURCE) -o $(TARGET)

$(GUARD_TARGET): $(GUARD_SOURCE)
	mkdir -p $(BUILD_DIR)
	xcrun --sdk macosx clang -fblocks -std=c11 -Wall -Wextra -Werror \
		-mmacosx-version-min=11.3 -isysroot "$(SDKROOT)" \
		-lEndpointSecurity -lbsm -lpthread $(GUARD_SOURCE) -o $(GUARD_TARGET)

sign: $(TARGET) $(GUARD_TARGET)
	@test -n "$(IDENTITY)" || (echo "Set IDENTITY to an approved Developer ID signing identity" && exit 2)
	codesign --force --options runtime --timestamp \
		--entitlements RATtlerESSensor.entitlements \
		--sign "$(IDENTITY)" $(TARGET)
	codesign --force --options runtime --timestamp \
		--entitlements RATtlerESSensor.entitlements \
		--sign "$(IDENTITY)" $(GUARD_TARGET)

clean:
	rm -rf $(BUILD_DIR)
