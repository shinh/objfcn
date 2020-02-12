namespace {
thread_local int g_tls_var = 140;
}

extern "C" {
  int func(int x) {
    g_tls_var++;
    return x + g_tls_var;
  }
}
