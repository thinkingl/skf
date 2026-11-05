CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra -Wno-deprecated-declarations
CPPFLAGS := -Iinclude/skf -Ithird_party/sqlite3
CFLAGS += -fPIC -DSKF_HAS_ECCDECRYPT -Wno-pointer-sign
LDLIBS := -lcrypto -lpthread -ldl
SQLITE_LIB ?= -l:libsqlite3.so.0

.PHONY: all clean test check hw-cross

all: libsoftskf.so softskf-init tests/softskf_test tests/softskf_admin_test \
	tests/skf_all tests/skf_imports_test

libsoftskf.so: src/softskf.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -shared -o $@ $< $(SQLITE_LIB) $(LDLIBS)

softskf-init: src/softskf_init.c libsoftskf.so
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< -L. -lsoftskf \
		-Wl,-rpath,'$$ORIGIN' $(LDLIBS)

tests/softskf_test: tests/softskf_test.c libsoftskf.so
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< -L. -lsoftskf \
		-Wl,-rpath,'$$ORIGIN/..' $(LDLIBS)

tests/softskf_admin_test: tests/softskf_admin_test.c libsoftskf.so
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc -o $@ $< -L. -lsoftskf \
		-Wl,-rpath,'$$ORIGIN/..' $(LDLIBS) -lpthread

tests/skf_all: CFLAGS += -USKF_HAS_ECCDECRYPT
tests/skf_all: tests/skf_all.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDLIBS)

tests/skf_imports_test: tests/skf_imports_test.c libsoftskf.so
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< -L. -lsoftskf \
		-Wl,-rpath,'$$ORIGIN/..' $(LDLIBS)

tests/hw_cross_test: tests/hw_cross_test.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDLIBS)

test: tests/softskf_test tests/softskf_admin_test
	rm -rf /tmp/softskf-test
	SOFTSKF_HOME=/tmp/softskf-test ./softskf-init --auth-key 0123456789abcdef \
		--app KEDA --admin-pin 123456 --user-pin 123456
	SOFTSKF_HOME=/tmp/softskf-test ./tests/softskf_test
	./tests/softskf_admin_test

hw-cross: tests/hw_cross_test
	@echo "Run as root (SG_IO needs CAP_SYS_RAWIO):"
	@echo "  sudo env SOFTSKF_HOME=$${SOFTSKF_HOME:-/tmp/softskf-xval} ./tests/hw_cross_test \\"
	@echo "      /path/to/vendor/libskf.so ./libsoftskf.so"

check: all
	rm -rf /tmp/softskf-check
	mkdir -p /tmp/softskf-check
	SOFTSKF_HOME=/tmp/softskf-check ./softskf-init --auth-key 0123456789abcdef \
		--app KEDA --admin-pin 123456 --user-pin 123456
	cd /tmp/softskf-check && \
		SOFTSKF_HOME=/tmp/softskf-check SKF_DEVAUTH_KEY=0123456789abcdef \
		$(CURDIR)/tests/skf_all $(CURDIR)/libsoftskf.so
	SOFTSKF_HOME=/tmp/softskf-check ./tests/skf_imports_test

clean:
	rm -f libsoftskf.so softskf-init tests/softskf_test \
		tests/softskf_admin_test tests/skf_all tests/skf_imports_test \
		tests/hw_cross_test
