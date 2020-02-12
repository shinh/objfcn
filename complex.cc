namespace {
thread_local int g_tls_var = 19;
thread_local int g_tls_var2 = 120;
thread_local int g_tls_bss;
thread_local int g_tls_bss2;
}

__attribute__((constructor))
static void init() {
  ++g_tls_bss;
}

extern "C" {
  int func(int x) {
    g_tls_var++;
    g_tls_bss -= 3;
    g_tls_bss2 += 3;
    return x + g_tls_var + g_tls_var2 + g_tls_bss + g_tls_bss2;
  }
}
