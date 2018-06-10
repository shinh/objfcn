#ifndef RUBY_OBJFCN_H
#define RUBY_OBJFCN_H 1

void* objopen(const char* filename, int flags);

int objclose(void* handle);

void* objsym(void* handle, const char* symbol);

char* objerror(void);

#endif /* RUBY_OBJFCN_H */
