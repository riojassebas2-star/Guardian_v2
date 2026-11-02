CC      ?= gcc
CFLAGS  ?= -std=gnu11 -O2 -Wall -Wextra
SRCS     = src/guardian.c src/config.c src/logjson.c src/pidtable.c src/procinfo.c \
           src/netmon.c src/auditor.c src/detect.c src/monitor.c src/boveda.c \
           src/canario.c src/control.c src/sha256.c
OBJS     = $(SRCS:src/%.c=build/%.o)

all: guardian tests/simulador_estres

guardian: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) -lm

build/%.o: src/%.c src/guardian.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build:
	mkdir -p build

tests/simulador_estres: tests/simulador_estres.c
	$(CC) $(CFLAGS) -o $@ $<

test: all
	sudo ./tests/prueba.sh

install: all
	sudo deploy/instalar.sh

uninstall:
	sudo deploy/desinstalar.sh

test-asan:
	$(MAKE) clean
	$(MAKE) CFLAGS="-std=gnu11 -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-omit-frame-pointer"
	sudo env ASAN_OPTIONS=detect_leaks=0 ./tests/prueba.sh

clean:
	rm -rf build guardian tests/simulador_estres

.PHONY: all test test-asan install uninstall clean
