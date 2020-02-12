CLANG := clang
CFLAGS := -g -O -Wall -MMD

TEST_BINARIES := test_objfcn_64 test_objfcn_32
TEST_TARGET_OBJS := \
	func_64_pie.o \
	func_64_pic.o \
	func_32_nopic.o \
	func_64.so

ifdef ARM
TEST_BINARIES += test_objfcn_arm32
TEST_TARGET_OBJS += func_arm32_nopic.o
endif

all: test

test: $(TEST_BINARIES) $(TEST_TARGET_OBJS)
	./test_objfcn_64 func_64_pie.o
	./test_objfcn_64 func_64_pic.o
	./test_objfcn_32 func_32_nopic.o
ifdef ARM
	qemu-arm -L /usr/arm-linux-gnueabi ./test_objfcn_arm32 func_arm32_nopic.o
endif

test_objfcn_64: test_objfcn.c objfcn.c func.c
	$(CC) $(CFLAGS) -ldl -rdynamic -o $@ test_objfcn.c objfcn.c

test_objfcn_32: test_objfcn.c objfcn.c func.c
	$(CC) $(CFLAGS) -m32 -ldl -rdynamic -o $@ test_objfcn.c objfcn.c

test_objfcn_arm32: test_objfcn.c objfcn.c func.c
	$(CLANG) -target arm-linux-gnueabi $(CFLAGS) -ldl -rdynamic -o $@ test_objfcn.c objfcn.c

func_64_pic.o: func.c
	$(CC) -fPIC -c -o $@ $<

func_64.so: func_64_pic.o
	$(CC) -fPIC -shared -o $@ $<

func_64_pie.o: func.c
	$(CC) -fPIE -c -o $@ $<

func_32_nopic.o: func.c
	$(CC) -m32 -fno-PIC -c -o $@ $<

func_arm32_nopic.o: func.c
	$(CLANG) -target arm-linux-gnueabi -fno-PIC -c -o $@ $<

-include *.d
