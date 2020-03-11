CLANG := clang
CFLAGS := -g -O -Wall -MMD
AARCH64_CXX := aarch64-linux-gnu-g++

TEST_BINARIES := test_objfcn_64 test_objfcn_32 test_objfcn_cpp_64
TEST_TARGET_OBJS := \
	func_64_pie.o \
	func_64_pic.o \
	func_32_nopic.o \
	func_64.so \
	cpp_64.so

ifdef ARM
TEST_BINARIES += test_objfcn_arm32
TEST_TARGET_OBJS += func_arm32_nopic.o
endif

ifdef AARCH64
TEST_BINARIES += test_objfcn_cpp_aarch64
TEST_TARGET_OBJS += cpp_aarch64.so
endif

all: test

test: $(TEST_BINARIES) $(TEST_TARGET_OBJS)
	./test_objfcn_64 func_64_pie.o
	./test_objfcn_64 func_64_pic.o
	./test_objfcn_32 func_32_nopic.o
	./test_objfcn_64 func_64.so
	./test_objfcn_cpp_64 cpp_64.so
ifdef ARM
	qemu-arm -L /usr/arm-linux-gnueabi ./test_objfcn_arm32 func_arm32_nopic.o
endif

test_objfcn_64: test_objfcn.c objfcn.c func.c
	$(CC) $(CFLAGS) -rdynamic -o $@ test_objfcn.c objfcn.c -ldl

test_objfcn_32: test_objfcn.c objfcn.c func.c
	$(CC) $(CFLAGS) -m32 -rdynamic -o $@ test_objfcn.c objfcn.c -ldl

test_objfcn_arm32: test_objfcn.c objfcn.c func.c
	$(CLANG) -target arm-linux-gnueabi $(CFLAGS) -rdynamic -o $@ test_objfcn.c objfcn.c -ldl

test_objfcn_cpp_64: test_objfcn_cpp.cc objfcn.c
	$(CXX) $(CFLAGS) -rdynamic -o $@ test_objfcn_cpp.cc objfcn.c -ldl

test_objfcn_cpp_aarch64: test_objfcn_cpp.cc objfcn.c
	$(AARCH64_CXX) $(CFLAGS) -rdynamic -o $@ test_objfcn_cpp.cc objfcn.c -ldl

func_64_pic.o: func.c
	$(CC) -fPIC -c -o $@ $<

func_64.so: func_64_pic.o
	$(CC) -fPIC -shared -o $@ $<

cpp_64.so: cpp.cc
	$(CXX) -fPIC -shared -o $@ $<

func_64_pie.o: func.c
	$(CC) -fPIE -c -o $@ $<

func_32_nopic.o: func.c
	$(CC) -m32 -fno-PIC -c -o $@ $<

func_arm32_nopic.o: func.c
	$(CLANG) -target arm-linux-gnueabi -fno-PIC -c -o $@ $<

cpp_aarch64.so: cpp.cc
	$(AARCH64_CXX) -fPIC -shared -o $@ $<

-include *.d

clean:
	rm -f $(TEST_BINARIES) *.o *.so
