CFLAGS := -g -O -Wall -MMD

all: test

test: test_objfcn func.o
	./$<

test_objfcn: test_objfcn.o objfcn.o
	$(CC) $(CFLAGS) -ldl -rdynamic -o $@ $^

func.o: func.c
	$(CC) -fPIC -c -o $@ $<

-include *.d
