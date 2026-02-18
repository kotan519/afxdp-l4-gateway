CC ?= clang
CFLAGS := -O2 -g -Wall -Wextra
BPF_LIBS := $(shell pkg-config --libs libbpf) -lelf -lz
BPF_CFLAGS := $(shell pkg-config --cflags libbpf)

all: gate

gate: src/main.o src/xsk.o
	$(CC) $(CFLAGS) -o $@ $^ $(BPF_LIBS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) $(BPF_CFLAGS) -Isrc -c $< -o $@

clean:
	rm -f gate src/*.o
