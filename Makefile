CFLAGS := -g -O -Wall -MMD

all: test

test: test_objfcn func_64_pic.o func_64_pie.o
	./$< func_64_pic.o
	./$< func_64_pie.o

test_objfcn: test_objfcn.o objfcn.o
	$(CC) $(CFLAGS) -ldl -rdynamic -o $@ $^

func_64_pic.o: func.c
	$(CC) -fPIC -c -o $@ $<

func_64_pie.o: func.c
	$(CC) -fPIE -c -o $@ $<

-include *.d
