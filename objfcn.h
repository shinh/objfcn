void* objopen(const char* filename, int flags);

int objclose(void* handle);

void* objsym(void* handle, const char* symbol);

char* objerror(void);
