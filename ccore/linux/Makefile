CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
RPATH := -Wl,-rpath,'$$ORIGIN/lib'

.PHONY: all clean native native-arm64

all: skf_test_generic skf_test_vendor skf_pin skf_all skf_destructive skf_devauth skf_delapp skf_imports_test skf_diff_test skf_event_diff_test skf_lock_test skf_ext_ecc_test skf_session_ecc_test skf_cert_check skf_cert_diff skf_cert_regress

skf_test_generic: skf_test.c
	$(CC) $(CFLAGS) -o $@ $< -Iinclude/skf -Llib $(RPATH) -lskf

skf_test_vendor: skf_test.c
	$(CC) $(CFLAGS) -o $@ $< -Iinclude/skf -Llib $(RPATH) -l:libskf_szgx_3310uk.so

skf_pin: skf_pin.c
	$(CC) $(CFLAGS) -o $@ $< -Iinclude/skf -Llib $(RPATH) -lskf

skf_all: skf_all.c
	$(CC) $(CFLAGS) -o $@ $< -Iinclude/skf -ldl

skf_destructive: skf_destructive.c
	$(CC) $(CFLAGS) -o $@ $< -Iinclude/skf -Llib $(RPATH) -lskf

skf_devauth: skf_devauth.c
	$(CC) $(CFLAGS) -o $@ $< -Iinclude/skf -Llib $(RPATH) -lskf

skf_delapp: skf_delapp.c
	$(CC) $(CFLAGS) -o $@ $< -Iinclude/skf -Llib $(RPATH) -lskf

skf_imports_test: skf_imports_test.c
	$(CC) $(CFLAGS) -o $@ $< -Iinclude/skf -Llib $(RPATH) -lskf -lcrypto

skf_diff_test: skf_diff_test.c
	$(CC) $(CFLAGS) -o $@ $< -Iinclude/skf -ldl

skf_event_diff_test: skf_event_diff_test.c
	$(CC) $(CFLAGS) -o $@ $< -Iinclude/skf -ldl -lpthread

skf_lock_test: skf_lock_test.c
	$(CC) $(CFLAGS) -o $@ $< -Iinclude/skf -ldl -lpthread

skf_ext_ecc_test: skf_ext_ecc_test.c
	$(CC) $(CFLAGS) -o $@ $< -Iinclude/skf -ldl -lcrypto

skf_session_ecc_test: skf_session_ecc_test.c
	$(CC) $(CFLAGS) -o $@ $< -Iinclude/skf -ldl -lcrypto

skf_cert_check: skf_cert_check.c
	$(CC) $(CFLAGS) -o $@ $< -Iinclude/skf -ldl -lcrypto

skf_cert_diff: skf_cert_diff.c
	$(CC) $(CFLAGS) -o $@ $< -Iinclude/skf -ldl -lcrypto

skf_cert_regress: skf_cert_regress.c reimpl/libskf_native.so
	$(CC) $(CFLAGS) -o $@ $< -Iinclude/skf -Lreimpl \
		-Wl,-rpath,'$$ORIGIN/reimpl' -l:libskf_native.so -lcrypto

arm64_sgprobe_x86: arm64_sgprobe.c
	$(CC) $(CFLAGS) -o $@ $<

arm64_sgprobe_aarch64: arm64_sgprobe.c
	aarch64-linux-gnu-gcc -static $(CFLAGS) -o $@ $<

native: reimpl/libskf_native.so
	ln -sf libskf_native.so reimpl/libskf.so

reimpl/libskf_native.so: reimpl/skf_native.c
	$(CC) -shared -fPIC $(CFLAGS) -Iinclude/skf -o $@ $< -lcrypto

native-arm64: reimpl/libskf_native_aarch64.so

reimpl/libskf_native_aarch64.so: reimpl/skf_native.c
	aarch64-linux-gnu-gcc -shared -fPIC $(CFLAGS) -Iinclude/skf -o $@ $< -lcrypto

clean:
	rm -f skf_test_generic skf_test_vendor skf_pin skf_all skf_destructive skf_devauth skf_delapp skf_imports_test skf_diff_test skf_event_diff_test skf_lock_test skf_ext_ecc_test skf_session_ecc_test skf_cert_check skf_cert_diff skf_cert_regress arm64_sgprobe_x86 arm64_sgprobe_aarch64 skf_info_only reimpl/libskf_native.so reimpl/libskf_native_aarch64.so reimpl/libskf.so reimpl/*.o
