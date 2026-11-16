ZIG ?= .toolchain/zig-x86_64-linux-0.14.1/zig
EXPECTED_ZIG_VERSION := 0.14.1
ZIG_TARGET := x86_64-linux-musl
TARGET := open-trestle-secret-scanner
SOURCE := launcher.c
CPPFLAGS := -DOPEN_TRESTLE_PRODUCTION_BUILD=1
CFLAGS := -std=c17 -O2 -pipe -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=3 -Wall -Wextra -Werror -Wformat=2 -Wconversion -Wshadow -Wstrict-prototypes
LDFLAGS := -static -pie -s -Wl,-z,relro,-z,now,-z,noexecstack,--build-id=none

.PHONY: all clean verify-toolchain

all: $(TARGET)

verify-toolchain:
	@test "$$($(ZIG) version)" = "$(EXPECTED_ZIG_VERSION)"

$(TARGET): verify-toolchain $(SOURCE)
	@global_cache="$$(mktemp -d)"; local_cache="$$(mktemp -d)"; trap 'rm -rf "$$global_cache" "$$local_cache"' EXIT; env -i LC_ALL=C SOURCE_DATE_EPOCH=0 ZIG_GLOBAL_CACHE_DIR="$$global_cache" ZIG_LOCAL_CACHE_DIR="$$local_cache" "$(ZIG)" cc -target $(ZIG_TARGET) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCE)

clean:
	rm -f $(TARGET)
