ROOTDIR := $(CURDIR)

TESTS = ut_basic ut_simple1 ut_simple2 ut_unload
NUM_TESTS := $(words $(TESTS))

CFLAGS := -m32 -Wall -Werror -O0 -ggdb -fno-strict-aliasing -fno-omit-frame-pointer -masm=intel
CFLAGS += -fPIC -I.. -std=c11
LDFLAGS :=  -pthread -ldl $(ROOTDIR)/../build/libpatchmem.so
CC := gcc

all: $(TESTS:%=build/%)

.PHONY: clean test tests .force
.force: ;

$(shell mkdir -p build &>/dev/null)

clean:
	rm -f build/*

# generic test dependency
$(TESTS:%=test/%): test/% : build/%

# generic test runner
test/%: build/% .force
	$<

build/ut_basic: ut_basic.c
	$(CC) -o $@ $(CFLAGS) -DTEST_HOOK ut_basic.c $(LDFLAGS)

build/ut_simple1: ut_simple1.c ut_simple1_preload.c
	$(CC) -o $@ $(CFLAGS) -rdynamic ut_simple1.c $(LDFLAGS)
	$(CC) -o build/ut_simple1_preload.so $(CFLAGS) -shared ut_simple1_preload.c $(LDFLAGS)

test/ut_simple1:
	LD_PRELOAD=build/ut_simple1_preload.so $<

build/ut_simple2: ut_simple2.c ut_simple2_preload.c
	$(CC) -o $@ $(CFLAGS) -rdynamic ut_simple2.c $(LDFLAGS)
	$(CC) -o build/ut_simple2_preload.so -m32 -fPIC -shared ut_simple2_preload.c -ldl
	$(CC) -o build/ut_simple2_injected.so $(CFLAGS) -shared ut_simple2_injected.c $(LDFLAGS)

test/ut_simple2:
	./ut_simple2.sh

build/ut_unload: ut_unload.c ut_unload_lib.c
	$(CC) -o $@ $(CFLAGS) -rdynamic ut_unload.c $(LDFLAGS)
	$(CC) -o build/ut_unload_lib.so $(CFLAGS) -shared ut_unload_lib.c $(LDFLAGS)

test/ut_unload:
	$< $(ROOTDIR)/build/ut_unload_lib.so

# pretty `make test`
_pos = $(if $(findstring $1,$2),$(call _pos,$1,\
		$(wordlist 2,$(words $2),$2),x $3),$3)
pos = $(words $(call _pos,$1,$2))

define run-test
@echo [$(call pos,$(1),$(TESTS)) / $(NUM_TESTS)] Running $(1):
@$(MAKE)  --no-print-directory test/$(1)
@echo OK!

endef

test: all
	$(foreach TEST,$(TESTS),\
		$(call run-test,$(TEST)) \
	)

# just an alias
tests: test