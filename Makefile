OBJECTS = patchmem.o stackframe_x86.o rc.o
CFLAGS := -m32 -Wall -Werror -O2 -ggdb -MMD -MP -fno-strict-aliasing -masm=intel $(CFLAGS)
CFLAGS += -fPIC -D_WIN32_WINNT=0x501

$(shell mkdir -p build &>/dev/null)

all: build/patchmem.dll

.PHONY: clean

clean:
	rm -f $(OBJECTS:%.o=build/%.o) $(OBJECTS:%.o=build/%.d) build/patchmem.dll

install: all
	@if [ ! -d "${CONFIG_INSTALL_PATH}" ]; then \
			echo "CONFIG_INSTALL_PATH invalid or not defined"; exit 1; \
	fi
	cp build/patchmem.dll $(CONFIG_INSTALL_PATH:/=)/patchmem.dll

build/patchmem.dll: $(OBJECTS:%.o=build/%.o)
	gcc $(CFLAGS) -o $@ -shared $(filter %.o,$^) -lkeystone -Wl,--subsystem,windows -static-libgcc

build/%.o: %.c
	gcc $(CFLAGS) -c -o $@ $<

build/rc.o: patchmem.rc
	windres -i $< -o $@

-include $(OBJECTS:%.o=build/%.d)
