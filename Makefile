obj-m=fuzzer.o
KDIR=/lib/modules/$(shell uname -r)/build
PWD=$(CURDIR)
BIN=fuzzer.ko

all: $(BIN)

$(BIN): fuzzer.c Makefile
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: $(BIN)
	install -m 644 $(BIN) /lib/modules/$(shell uname -r)/extra/
	depmod -a

.PHONY: all clean install
