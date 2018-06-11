#include "objfcn.h"

#include <assert.h>
#include <stdio.h>

#include "func.c"

typedef int (*func_t)(int);

int failed = 0;

void check(int expected, int actual) {
  if (expected != actual) {
    fprintf(stderr, "expected %d but comes %d\n", expected, actual);
    failed++;
  }
}

int func_in_main(void) {
  return 99;
}

int main(int argc, char* argv[]) {
  if (argc <= 1) {
    fprintf(stderr, "object file not specified\n");
    return 1;
  }
  void* handle = objopen(argv[1], 0);
  if (handle == NULL) {
    fprintf(stderr, "objopen failed: %s\n", objerror());
    return 1;
  }
  func_t fp = (func_t)objsym(handle, "func");
  if (fp == NULL) {
    fprintf(stderr, "objsym failed\n");
    return 1;
  }
  check(func(-1), fp(-1));
  check(func(-1), fp(-1));
  objclose(handle);
  return failed;
}
