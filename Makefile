OBJECTS = patchmem.o
CFLAGS := -m32 -Wall -Werror -O0 -ggdb -MMD -MP -fno-strict-aliasing -masm=intel $(CFLAGS)
CFLAGS += -fPIC
LDFLAGS := -m32 $(LDFLAGS)

$(shell mkdir -p build &>/dev/null)

ifeq ($(OS),Windows_NT)
	LIB_TARGET ?= patchmem.dll
	OBJECTS += os_win.o rc.o
	CFLAGS += -D_WIN32_WINNT=0x501
else
	OBJECTS += os_linux.o
	LIB_TARGET ?= libpatchmem.so
	CFLAGS += -pthread
	LDFLAGS += -pthread -ldl
endif

all: build/$(LIB_TARGET)

.PHONY: clean

clean:
	rm -f $(OBJECTS:%.o=build/%.o) $(OBJECTS:%.o=build/%.d) build/patchmem.dll build/libpatchmem.so

install: all
	@if [ ! -d "${CONFIG_INSTALL_PATH}" ]; then \
			echo "CONFIG_INSTALL_PATH invalid or not defined"; exit 1; \
	fi
	cp build/$(LIB_TARGET) $(CONFIG_INSTALL_PATH:/=)/$(LIB_TARGET)

build/patchmem.dll: $(OBJECTS:%.o=build/%.o)
	gcc $(LDFLAGS) -o $@ -shared $(filter %.o,$^) -lkeystone -Wl,--subsystem,windows -static-libgcc

build/libpatchmem.so: $(OBJECTS:%.o=build/%.o)
	gcc -o $@ -shared $(filter %.o,$^) -lkeystone $(LDFLAGS)

build/%.o: %.c
	gcc $(CFLAGS) -c -o $@ $<

build/rc.o: patchmem.rc
	windres -i $< -o $@

-include $(OBJECTS:%.o=build/%.d)
