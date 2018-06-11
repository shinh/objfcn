#include <stdio.h>

int g_counter = 0;
int g_value = 3;
const int g_const = 42;

int dummy(void) {
  return -3;
}

int func_in_main(void);

int func(int x) {
  g_counter++;
  g_value = x;
  return x + g_counter + g_value + g_const + func_in_main();
}
