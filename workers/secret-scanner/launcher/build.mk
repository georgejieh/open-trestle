CC := /usr/bin/gcc
EXPECTED_CC_VERSION := 16.2.1
TARGET := open-trestle-secret-scanner
SOURCE := launcher.c
CPPFLAGS := -DOPEN_TRESTLE_PRODUCTION_BUILD=1
CFLAGS := -std=c17 -O2 -pipe -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=3 -Wall -Wextra -Werror -Wformat=2 -Wconversion -Wshadow -Wstrict-prototypes
LDFLAGS := -static-pie -Wl,-z,relro,-z,now,-z,noexecstack,--build-id=none

.PHONY: all clean verify-compiler

all: $(TARGET)

verify-compiler:
	@test "$$($(CC) -dumpfullversion)" = "$(EXPECTED_CC_VERSION)"

$(TARGET): verify-compiler $(SOURCE)
	LC_ALL=C SOURCE_DATE_EPOCH=0 $(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCE)

clean:
	rm -f $(TARGET)
