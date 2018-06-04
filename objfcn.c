#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include "objfcn.h"

#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define SPLIT_ALLOC 1

#if defined(__x86_64__)
# define R_64 R_X86_64_64
# define R_PC32 R_X86_64_PC32
# define R_PLT32 R_X86_64_PLT32
#else
# error "Unsupported architecture"
#endif

#if __SIZEOF_POINTER__ == 8
# define Elf_Addr Elf64_Addr
# define Elf_Ehdr Elf64_Ehdr
# define Elf_Shdr Elf64_Shdr
# define Elf_Sym Elf64_Sym
# define Elf_Rel Elf64_Rel
# define Elf_Rela Elf64_Rela
# define ELF_ST_TYPE(v) ELF64_ST_TYPE(v)
# define ELF_R_SYM(v) ELF64_R_SYM(v)
# define ELF_R_TYPE(v) ELF64_R_TYPE(v)
#else
# define Elf_Addr Elf32_Addr
# define Elf_Ehdr Elf32_Ehdr
# define Elf_Shdr Elf32_Shdr
# define Elf_Sym Elf32_Sym
# define Elf_Rel Elf32_Rel
# define Elf_Rela Elf32_Rela
# define ELF_ST_TYPE(v) ELF32_ST_TYPE(v)
# define ELF_R_SYM(v) ELF32_R_SYM(v)
# define ELF_R_TYPE(v) ELF32_R_TYPE(v)
#endif

typedef struct {
  char* name;
  char* addr;
} symbol;

typedef struct {
  symbol* symbols;
  int num_symbols;
  char* code;
  size_t code_size;
  size_t code_used;
} obj_handle;

static char obj_error[256];

#if SPLIT_ALLOC

static char* alloc_code(obj_handle* obj, size_t size) {
  char* r = obj->code + obj->code_used;
  obj->code_used += size;
  return r;
}

#else

static char* code;
static size_t code_used;

static char* alloc_code(obj_handle* obj, size_t size) {
  char* r = code + code_used;
  code_used += size;
  return r;
}

static void init(void) {
  code = (char*)mmap(NULL, 1024 * 1024 * 1024,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);
  if (code == MAP_FAILED) {
    sprintf(obj_error, "mmap failed");
  }
}

#endif

char* read_file(const char* filename) {
  FILE* fp = NULL;
  char* bin = NULL;
  long filesize = 0;
  fp = fopen(filename, "rb");
  if (fp == NULL) {
    sprintf(obj_error, "failed to open %s: %s", filename, strerror(errno));
    return NULL;
  }

  if (fseek(fp, 0, SEEK_END) != 0) {
    sprintf(obj_error, "fseek failed: %s", strerror(errno));
    goto error;
  }

  filesize = ftell(fp);
  if (filesize < 0) {
    sprintf(obj_error, "ftell failed: %s", strerror(errno));
    goto error;
  }

  if (fseek(fp, 0, SEEK_SET) != 0) {
    sprintf(obj_error, "fseek failed: %s", strerror(errno));
    goto error;
  }

  bin = (char*)malloc(filesize);
  if (fread(bin, 1, filesize, fp) != (size_t)filesize) {
    sprintf(obj_error, "fread failed: %s", strerror(errno));
    goto error;
  }

  fclose(fp);
  return bin;

error:
  free(bin);
  fclose(fp);
  return NULL;
}

void* objopen(const char* filename, int flags) {
  char* bin = NULL;
  obj_handle* obj = NULL;
  Elf_Ehdr* ehdr = NULL;

#if !SPLIT_ALLOC
  if (!code) {
    init();
  }
  if (code == MAP_FAILED) {
    return NULL;
  }
#endif

  bin = read_file(filename);
  if (bin == NULL) {
    return NULL;
  }

  obj = (obj_handle*)malloc(sizeof(obj_handle));
  if (obj == NULL) {
    sprintf(obj_error, "malloc failed");
    free(bin);
    return NULL;
  }
  memset(obj, 0, sizeof(*obj));

  ehdr = (Elf_Ehdr*)bin;
  if (memcmp(ehdr->e_ident, ELFMAG, 4)) {
    sprintf(obj_error, "%s is not ELF", filename);
    free(bin);
    free(obj);
    return NULL;
  }

  // TODO: more validation.

  {
  Elf_Shdr* shdrs = (Elf_Shdr*)(bin + ehdr->e_shoff);
  //Elf_Shdr* shstrtab = &shdrs[ehdr->e_shstrndx];
  Elf_Sym* symtab = NULL;
  int symnum = 0;
  int strtab_index = -1;
  const char* strtab = NULL;
  char* addrs[ehdr->e_shnum];

  for (int i = 0; i < ehdr->e_shnum; i++) {
    Elf_Shdr* shdr = &shdrs[i];
    if (shdr->sh_type == SHT_SYMTAB) {
      symtab = (Elf_Sym*)(bin + shdr->sh_offset);
      symnum = shdr->sh_size / sizeof(Elf_Sym);
      strtab_index = shdr->sh_link;
    }

    if (shdr->sh_type == SHT_STRTAB && i == strtab_index) {
      strtab = bin + shdr->sh_offset;
    }
  }

#if SPLIT_ALLOC
  size_t code_size = 0;
  for (int i = 0; i < ehdr->e_shnum; i++) {
    Elf_Shdr* shdr = &shdrs[i];
    if (shdr->sh_flags & SHF_ALLOC) {
      code_size += shdr->sh_size;
    }
  }
  obj->code_size = (code_size + 4095) & ~4095;
  obj->code = (char*)mmap(NULL, obj->code_size,
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS,
                          -1, 0);
  if (obj->code == MAP_FAILED) {
    sprintf(obj_error, "mmap failed: %s", strerror(errno));
    free(bin);
    free(obj);
    return NULL;
  }
#endif

  memset(addrs, 0, sizeof(addrs));
  for (int i = 0; i < ehdr->e_shnum; i++) {
    Elf_Shdr* shdr = &shdrs[i];
    if (shdr->sh_flags & SHF_ALLOC) {
      addrs[i] = alloc_code(obj, shdr->sh_size);
      if (shdr->sh_type != SHT_NOBITS) {
        memcpy(addrs[i], bin + shdr->sh_offset, shdr->sh_size);
      }
    }
  }

  for (int i = 0; i < symnum; i++) {
    Elf_Sym* sym = &symtab[i];
    if (ELF_ST_TYPE(sym->st_info) == STT_OBJECT ||
        ELF_ST_TYPE(sym->st_info) == STT_FUNC) {
      obj->num_symbols++;
    }
  }
  obj->symbols = (symbol*)malloc(sizeof(symbol) * obj->num_symbols);
  for (int i = 0, ns = 0; i < symnum; i++) {
    Elf_Sym* sym = &symtab[i];
    if (ELF_ST_TYPE(sym->st_info) == STT_OBJECT ||
        ELF_ST_TYPE(sym->st_info) == STT_FUNC) {
      const char* name = strtab + sym->st_name;
      char* addr = addrs[sym->st_shndx] + sym->st_value;
      // Write back so we can use the address later.
      sym->st_value = (Elf_Addr)addr;
      //fprintf(stderr, "%s => %p\n", name, addr);
      obj->symbols[ns].name = strdup(name);
      obj->symbols[ns].addr = addr;
      ns++;
    }
  }

  for (int i = 0; i < ehdr->e_shnum; i++) {
    Elf_Shdr* shdr = &shdrs[i];
    int has_addend = shdr->sh_type == SHT_RELA;
    size_t relsize = has_addend ? sizeof(Elf_Rela) : sizeof(Elf_Rel);
    int relnum = shdr->sh_size / relsize;
    char* target_base = addrs[shdr->sh_info];

    if ((shdr->sh_type != SHT_REL && shdr->sh_type != SHT_RELA) ||
        target_base == NULL) {
      continue;
    }

    for (int j = 0; j < relnum; j++) {
      Elf_Rela* rel = (Elf_Rela*)(bin + shdr->sh_offset + relsize * j);
      char* target = target_base + rel->r_offset;
      Elf_Sym* sym = &symtab[ELF_R_SYM(rel->r_info)];
      int addend = has_addend ? rel->r_addend : 0;
      char* sym_addr = NULL;
      switch (ELF_ST_TYPE(sym->st_info)) {
        case STT_SECTION:
          sym_addr = addrs[sym->st_shndx];
          break;

        case STT_FUNC:
        case STT_OBJECT:
          sym_addr = (char*)sym->st_value;
          break;

        case STT_NOTYPE:
          if (sym->st_shndx == SHN_UNDEF) {
            sym_addr = (char*)dlsym(RTLD_DEFAULT, strtab + sym->st_name);
            if (sym_addr == NULL) {
              sprintf(obj_error, "failed to resolve %s", strtab + sym->st_name);
              free(bin);
              objclose(obj);
              return NULL;
            }
          } else {
            sym_addr = addrs[sym->st_shndx];
          }
          break;

        default:
          sprintf(obj_error, "unsupported relocation sym %d",
                  ELF_ST_TYPE(sym->st_info));
          free(bin);
          objclose(obj);
          return NULL;
      }
      //fprintf(stderr, "%d %s target=%p sym_addr=%p addend=%d\n",
      //        j, strtab + sym->st_name, target, sym_addr, addend);

      switch (ELF_R_TYPE(rel->r_info)) {
#ifdef R_64
        case R_64:
          *(uint64_t*)target = (uint64_t)sym_addr + addend;
          break;
#endif

#ifdef R_PC32
        case R_PC32:
          *(uint32_t*)target = (sym_addr - target) + addend;
          break;
#endif

#ifdef R_PLT32
        case R_PLT32: {
          void* dest = sym_addr;
#if defined(__x86_64__)
          sym_addr = alloc_code(obj, 6 + 8);
          sym_addr[0] = 0xff;
          sym_addr[1] = 0x25;
          *(uint32_t*)(sym_addr + 2) = 0;
          *(uint64_t*)(sym_addr + 6) = (uint64_t)dest;
#endif
          *(uint32_t*)target = (sym_addr - target) + addend;
          break;
        }
#endif

#if defined(__x86_64__)
        case R_X86_64_REX_GOTPCRELX: {
          void* dest = sym_addr;
          sym_addr = alloc_code(obj, 8);
          *(uint64_t*)(sym_addr) = (uint64_t)dest;
          *(uint32_t*)target = (sym_addr - target) + addend;
          break;
        }
#endif

        default:
          sprintf(obj_error, "Unknown reloc: %ld", ELF_R_TYPE(rel->r_info));
          free(bin);
          objclose(obj);
          return NULL;
      }
    }
  }

  }

  free(bin);
  return obj;
}

int objclose(void* handle) {
  obj_handle* obj = (obj_handle*)handle;
  if (obj->code) {
    munmap(obj->code, obj->code_size);
  }
  for (int i = 0; i < obj->num_symbols; i++) {
    free(obj->symbols[i].name);
  }
  free(obj);
  return 0;
}

void* objsym(void* handle, const char* symbol) {
  obj_handle* obj = (obj_handle*)handle;
  for (int i = 0; i < obj->num_symbols; i++) {
    if (!strcmp(obj->symbols[i].name, symbol)) {
      return obj->symbols[i].addr;
    }
  }
  return NULL;
}

char* objerror(void) {
  return obj_error;
}
