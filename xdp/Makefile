CLANG ?= clang

CFLAGS = -O2 -g -Wall \
         -target bpf \
         -D__TARGET_ARCH_x86 \
         -I/usr/include/x86_64-linux-gnu

BPF_OBJS = xdp_redirect.o xdp_arp_pass.o

all: $(BPF_OBJS)

%.o: %.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o