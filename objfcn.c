#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include "objfcn.h"

#include <assert.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#define OBJFCN_LOG 1

#define OBJFCN_TLS_SIZE 8192

#if OBJFCN_LOG
# define LOGF(...) if (1) fprintf(stderr, __VA_ARGS__)
#else
# define LOGF(...) if (0) fprintf(stderr, __VA_ARGS__)
#endif

#define OBJFCN_SPLIT_ALLOC 0

#if defined(__x86_64__)
# define R_64 R_X86_64_64
# define R_PC32 R_X86_64_PC32
# define R_PLT32 R_X86_64_PLT32
# define R_RELATIVE R_X86_64_RELATIVE
# define R_GLOB_DAT R_X86_64_GLOB_DAT
# define R_JUMP_SLOT R_X86_64_JUMP_SLOT
# define DYN_SUPPORTED 1
#elif defined(__i386__)
# define R_32 R_386_32
# define R_PC32 R_386_PC32
#elif defined(__arm__)
#elif defined(__aarch64__)
# define R_64 R_AARCH64_ABS64
# define R_RELATIVE R_AARCH64_RELATIVE
# define R_GLOB_DAT R_AARCH64_GLOB_DAT
# define R_JUMP_SLOT R_AARCH64_JUMP_SLOT
# define DYN_SUPPORTED 1
#else
# error "Unsupported architecture"
#endif

#if __SIZEOF_POINTER__ == 8
# define Elf_Addr Elf64_Addr
# define Elf_Ehdr Elf64_Ehdr
# define Elf_Phdr Elf64_Phdr
# define Elf_Shdr Elf64_Shdr
# define Elf_Sym Elf64_Sym
# define Elf_Rel Elf64_Rela
# define Elf_Rela Elf64_Rela
# define Elf_Dyn Elf64_Dyn
# define ELFW_ST_BIND(v) ELF64_ST_BIND(v)
# define ELFW_ST_TYPE(v) ELF64_ST_TYPE(v)
# define ELFW_R_SYM(v) ELF64_R_SYM(v)
# define ELFW_R_TYPE(v) ELF64_R_TYPE(v)
#else
# define Elf_Addr Elf32_Addr
# define Elf_Ehdr Elf32_Ehdr
# define Elf_Phdr Elf32_Phdr
# define Elf_Shdr Elf32_Shdr
# define Elf_Sym Elf32_Sym
# define Elf_Rel Elf32_Rel
# define Elf_Rela Elf32_Rela
# define Elf_Dyn Elf32_Dyn
# define ELFW_ST_BIND(v) ELF32_ST_BIND(v)
# define ELFW_ST_TYPE(v) ELF32_ST_TYPE(v)
# define ELFW_R_SYM(v) ELF32_R_SYM(v)
# define ELFW_R_TYPE(v) ELF32_R_TYPE(v)
#endif

__thread char g_objfcn_tls[OBJFCN_TLS_SIZE];

typedef struct {
  char* name;
  char* addr;
} symbol;

typedef struct {
  uint32_t nbuckets;
  uint32_t nchain;
  uint8_t tail[1];
} Elf_Hash;

static uint32_t* elf_hash_buckets(Elf_Hash* hash) {
  return (uint32_t*)(hash->tail);
}

static uint32_t* elf_hash_chains(Elf_Hash* hash) {
  return (uint32_t*)(&elf_hash_buckets(hash)[hash->nbuckets]);
}

static uint32_t elf_hash_calc(const char* p) {
  uint32_t h = 0, g;
  while (*p) {
    h = (h << 4) + (unsigned char)*p++;
    g = h & 0xf0000000;
    h ^= g;
    h ^= g >> 24;
  }
  return h;
}

typedef struct {
  uint32_t nbuckets;
  uint32_t symndx;
  uint32_t maskwords;
  uint32_t shift2;
  uint8_t tail[1];
} Elf_GnuHash;

static Elf_Addr* gnu_hash_bloom_filter(Elf_GnuHash* hash) {
  return (Elf_Addr*)(hash->tail);
}

static uint32_t* gnu_hash_buckets(Elf_GnuHash* hash) {
  return (uint32_t*)(&gnu_hash_bloom_filter(hash)[hash->maskwords]);
}

static uint32_t* gnu_hash_hashvals(Elf_GnuHash* hash) {
  return (uint32_t*)(&gnu_hash_buckets(hash)[hash->nbuckets]);
}

static uint32_t gnu_hash_calc(const char* p) {
  uint32_t h = 5381;
  for (; *p; p++) {
    h = h * 33 + (unsigned char)*p;
  }
  return h;
}

typedef struct {
  symbol* symbols;
  int num_symbols;
  char* code;
  size_t code_size;
  size_t code_used;

  int is_dyn;
  char* base;
  const char* strtab;
  Elf_Sym* symtab;
  Elf_Hash* elf_hash;
  Elf_GnuHash* gnu_hash;
} obj_handle;

static char obj_error[256];

static uintptr_t align_down(uintptr_t v, size_t align) {
  return v & ~(align - 1);
}

static uintptr_t align_up(uintptr_t v, size_t align) {
  return align_down(v + align - 1, align);
}

#if OBJFCN_SPLIT_ALLOC

static char* alloc_code(obj_handle* obj, size_t size) {
  char* r = obj->code + obj->code_used;
  obj->code_used += size;
  return r;
}

static void align_code(obj_handle* obj, size_t align) {
  obj->code_used = align_up(obj->code_used, align);
}

#else

static char* code;
static size_t code_used;

static char* alloc_code(obj_handle* obj, size_t size) {
  char* r = code + code_used;
  code_used += size;
  return r;
}

static void align_code(obj_handle* obj, size_t align) {
  code_used = align_up(code_used, align);
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

static char* read_file(const char* filename) {
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

static int should_load(Elf_Shdr* shdr) {
#ifdef SHT_ARM_EXIDX
  return shdr->sh_flags & SHF_ALLOC && shdr->sh_type != SHT_ARM_EXIDX;
#else
  return shdr->sh_flags & SHF_ALLOC;
#endif
}

static size_t relocate(obj_handle* obj,
                       const char* bin,
                       Elf_Sym* symtab,
                       const char* strtab,
                       char** addrs,
                       int code_size_only) {
  size_t code_size = 0;
  Elf_Ehdr* ehdr = (Elf_Ehdr*)bin;
  Elf_Shdr* shdrs = (Elf_Shdr*)(bin + ehdr->e_shoff);
  for (int i = 0; i < ehdr->e_shnum; i++) {
    Elf_Shdr* shdr = &shdrs[i];
    int has_addend = shdr->sh_type == SHT_RELA;
    size_t relsize = has_addend ? sizeof(Elf_Rela) : sizeof(Elf_Rel);
    int relnum = shdr->sh_size / relsize;
    char* target_base = addrs[shdr->sh_info];

    if ((shdr->sh_type != SHT_REL && shdr->sh_type != SHT_RELA) ||
        !should_load(&shdrs[shdr->sh_info])) {
      continue;
    }

    for (int j = 0; j < relnum; j++) {
      Elf_Rela* rel = (Elf_Rela*)(bin + shdr->sh_offset + relsize * j);
      char* target = target_base + rel->r_offset;
      Elf_Sym* sym = &symtab[ELFW_R_SYM(rel->r_info)];
      int addend = has_addend ? rel->r_addend : 0;
      char* sym_addr = NULL;

      if (!code_size_only) {
        switch (ELFW_ST_TYPE(sym->st_info)) {
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
                sprintf(obj_error, "failed to resolve %s",
                        strtab + sym->st_name);
                return (size_t)-1;
              }
            } else {
              sym_addr = addrs[sym->st_shndx];
            }
            break;

          default:
            sprintf(obj_error, "unsupported relocation sym %d",
                    ELFW_ST_TYPE(sym->st_info));
            return (size_t)-1;
        }
        //fprintf(stderr, "%d %s target=%p sym_addr=%p addend=%d\n",
        //        j, strtab + sym->st_name, target, sym_addr, addend);
      }

      switch (ELFW_R_TYPE(rel->r_info)) {
#ifdef R_32
        case R_32:
          if (!code_size_only)
            *(uint32_t*)target += (uint32_t)sym_addr + addend;
          break;
#endif

#ifdef R_64
        case R_64:
          if (!code_size_only)
            *(uint64_t*)target += (uint64_t)sym_addr + addend;
          break;
#endif

#ifdef R_PC32
        case R_PC32:
          if (!code_size_only)
            *(uint32_t*)target += (sym_addr - target) + addend;
          break;
#endif

#ifdef R_PLT32
        case R_PLT32:
          if (code_size_only) {
            code_size += 6 + 8;
          } else {
#if defined(__x86_64__)
            void* dest = sym_addr;
            sym_addr = alloc_code(obj, 6 + 8);
            sym_addr[0] = 0xff;
            sym_addr[1] = 0x25;
            *(uint32_t*)(sym_addr + 2) = 0;
            *(uint64_t*)(sym_addr + 6) = (uint64_t)dest;
#endif
            *(uint32_t*)target += (sym_addr - target) + addend;
          }
          break;
#endif

#if defined(__x86_64__)
        case R_X86_64_REX_GOTPCRELX:
          if (code_size_only) {
            code_size += 8;
          } else {
            void* dest = sym_addr;
            sym_addr = alloc_code(obj, 8);
            *(uint64_t*)(sym_addr) = (uint64_t)dest;
            *(uint32_t*)target += (sym_addr - target) + addend;
          }
          break;
#endif

#if defined(__arm__)
        case R_ARM_CALL:
          if (code_size_only) {
            code_size += 8;
          } else {
            void* dest = sym_addr;
            sym_addr = alloc_code(obj, 8);
            // ldr pc, [pc, #-4]
            *(uint32_t*)sym_addr = 0xe51ff004;
            *(uint32_t*)(sym_addr + 4) = (uint32_t)dest;
            int32_t v = ((sym_addr - target) + addend - 8) >> 2;
            if (v >= (1 << 23) || v < -(1 << 23)) {
              sprintf(obj_error, "Relocation out of range: %x", v);
              return (size_t)-1;
            }
            *(uint32_t*)target =
                (((uint8_t*)target)[3] << 24U) | (0xffffff & v);
          }
          break;

        case R_ARM_ABS32:
          if (!code_size_only)
            *(uint32_t*)target = (uint32_t)sym_addr + addend;
          break;
#endif

        default:
          sprintf(obj_error, "Unknown reloc: %ld",
                  (long)ELFW_R_TYPE(rel->r_info));
          return (size_t)-1;
      }
    }
  }
  return code_size;
}

static int is_defined(Elf_Sym* sym) {
  int bind = ELFW_ST_BIND(sym->st_info);
  return ((bind == STB_GLOBAL || bind == STB_WEAK) &&
          sym->st_shndx != SHN_UNDEF);
}

static void* objsym_dyn_elf_hash(obj_handle* obj, const char* symbol) {
  assert(obj->elf_hash);
  Elf_Hash* elf_hash = obj->elf_hash;

  uint32_t h = elf_hash_calc(symbol);
  uint32_t n = elf_hash_buckets(elf_hash)[h % elf_hash->nbuckets];
  for (; n; n = elf_hash_chains(elf_hash)[n]) {
    Elf_Sym* sym = &obj->symtab[n];

    if (!strcmp(symbol, obj->strtab + sym->st_name) && is_defined(sym)) {
      return obj->base + sym->st_value;
    }
  }
  return NULL;
}

static void* objsym_dyn_gnu_hash(obj_handle* obj, const char* symbol) {
  assert(obj->gnu_hash);
  Elf_GnuHash* gnu_hash = obj->gnu_hash;

  uint32_t h = gnu_hash_calc(symbol);
  // TODO(hamaji): Use the bloom filter.
  int n = gnu_hash_buckets(gnu_hash)[h % gnu_hash->nbuckets];
  // fprintf(stderr, "lookup n=%d mask=%x\n", n, gnu_hash->maskwords);
  if (n == 0) return NULL;
  const uint32_t* hv = &gnu_hash_hashvals(gnu_hash)[n - gnu_hash->symndx];
  for (Elf_Sym* sym = &obj->symtab[n];; ++sym) {
    uint32_t h2 = *hv++;
    if ((h & ~1) == (h2 & ~1) &&
        !strcmp(symbol, obj->strtab + sym->st_name) &&
        is_defined(sym)) {
      return obj->base + sym->st_value;
    }
    if (h2 & 1) break;
  }
  return NULL;
}

static void* objsym_dyn(obj_handle* obj, const char* symbol) {
  assert(obj->symtab);
  if (obj->gnu_hash) {
    return objsym_dyn_gnu_hash(obj, symbol);
  } else {
    return objsym_dyn_elf_hash(obj, symbol);
  }
}

#if DYN_SUPPORTED

static void undefined() {
  LOGF("undefined function called\n");
  abort();
}

#endif

#if defined(__aarch64__)

typedef struct TlsDesc {
  ptrdiff_t (*entry)(struct TlsDesc*);
  void* arg;
} TlsDesc;

static ptrdiff_t return_tls(struct TlsDesc* desc) {
  return (ptrdiff_t)desc->arg;
}

#endif

static void relocate_dyn(const char* reloc_type, obj_handle* obj,
                         Elf_Rel* rel, int relsz) {
  size_t i;
  for (i = 0; i < relsz / sizeof(*rel); rel++, i++) {
    LOGF("rel offset=%x\n", (int)rel->r_offset);
    void** addr = (void**)(obj->base + rel->r_offset);
    int type = ELFW_R_TYPE(rel->r_info);
    Elf_Sym* sym = obj->symtab + ELFW_R_SYM(rel->r_info);
    const char* sname = obj->strtab + sym->st_name;
    void* val = 0;

    val = objsym_dyn(obj, sname);
    if (!val)
      val = dlsym(RTLD_DEFAULT, sname);

    LOGF("%s: %p %s(%p) %d => %p\n",
         reloc_type, (void*)addr, sname, sym, type, val);

    switch (type) {
#if 0
    case R_386_32: {
      *addr += (int)val;
    }
    case R_386_COPY: {
      if (val) {
        *addr = *(int*)val;
      } else {
        fprintf(stderr, "undefined: %s\n", sname);
        abort();
      }
    }
    case R_386_GLOB_DAT: {
      break;
    }
    case R_386_JMP_SLOT: {
      if (val) {
        *addr = (int)val;
      } else {
        *addr = (int)&undefined;
      }
      break;
    }
#endif

#if DYN_SUPPORTED
    case R_GLOB_DAT:
    case R_JUMP_SLOT: {
      if (val) {
        *addr = val;
      } else {
        *addr = (void*)&undefined;
      }
      break;
    }

    case R_RELATIVE: {
      *addr = (void*)(*(char**)addr + (intptr_t)obj->base);
      break;
    }

    case R_64: {
#if __SIZEOF_POINTER__ == 8
      *addr = (void*)((char*)val + rel->r_addend);
#else
      *addr = val;
#endif
      break;
    }
#endif

    case R_X86_64_DTPMOD64: {
      // TODO(hamaji): Retrive the right module ID.
      *addr = (void*)1;
      break;
    }

    case R_X86_64_DTPOFF64: {
      break;
    }

#if defined(__aarch64__)
    case R_AARCH64_TLSDESC: {
      TlsDesc* desc = (TlsDesc*)addr;
      desc->entry = &return_tls;
      desc->arg = (void*)(g_objfcn_tls + sym->st_value + rel->r_addend - (intptr_t)__builtin_thread_pointer());
      break;
    }
#endif

    default:
      LOGF("Unsupported reloc: %d\n", type);
      abort();
      break;

    }

  }
}

static int load_object_dyn(obj_handle* obj, const char* bin,
                           const char* filename) {
  Elf_Ehdr* ehdr = (Elf_Ehdr*)bin;
  Elf_Phdr* phdrs = (Elf_Phdr*)(bin + ehdr->e_phoff);

  size_t max_addr = 0;
  for (int i = 0; i < ehdr->e_phnum; i++) {
    Elf_Phdr* phdr = &phdrs[i];
    if (phdr->p_type != PT_LOAD) continue;
    size_t end_addr = align_up(phdr->p_vaddr + phdr->p_memsz, 4096);
    if (max_addr < end_addr) {
      max_addr = end_addr;
    }
  }

  char* code = alloc_code(obj, max_addr);
  align_code(obj, 4096);

  obj->base = code;
  obj->is_dyn = 1;

  for (int i = 0; i < ehdr->e_phnum; i++) {
    Elf_Phdr* phdr = &phdrs[i];
    if (phdr->p_type != PT_LOAD) continue;
    memcpy(code + phdr->p_vaddr, bin + phdr->p_offset, phdr->p_filesz);
  }

  for (int i = 0; i < ehdr->e_phnum; i++) {
    Elf_Phdr* phdr = &phdrs[i];
    if (phdr->p_type != PT_TLS) continue;
    assert(phdr->p_memsz <= OBJFCN_TLS_SIZE);
    memcpy(g_objfcn_tls, bin + phdr->p_offset, phdr->p_filesz);
  }

  for (int i = 0; i < ehdr->e_phnum; i++) {
    Elf_Phdr* phdr = &phdrs[i];
    if (phdr->p_type != PT_DYNAMIC) continue;

    Elf_Dyn* dyns = (Elf_Dyn*)(code + phdr->p_vaddr);
    for (Elf_Dyn* dyn = dyns; dyn->d_tag; dyn++) {
      if (dyn->d_tag == DT_STRTAB) {
        obj->strtab = code + dyn->d_un.d_ptr;
      }
    }

    Elf_Rel* rel = NULL;
    int relsz = 0, pltrelsz = 0;
    void** init_array = NULL;
    int init_arraysz = 0;
    for (Elf_Dyn* dyn = dyns; dyn->d_tag; dyn++) {
      switch (dyn->d_tag) {
      case DT_NEEDED: {
        const char* name = obj->strtab + dyn->d_un.d_ptr;
        void* handle = dlopen(name, RTLD_GLOBAL);
        LOGF("DT_NEEDED %s %p\n", name, handle);
        (void)handle;
        break;
      }

      case DT_SYMTAB:
        obj->symtab = (Elf_Sym*)(code + dyn->d_un.d_ptr);
        break;

      case DT_HASH:
        obj->elf_hash = (Elf_Hash*)(code + dyn->d_un.d_ptr);
        break;

      case DT_GNU_HASH:
        obj->gnu_hash = (Elf_GnuHash*)(code + dyn->d_un.d_ptr);
        break;

      case DT_RELENT:
      case DT_PLTREL: {
        int pltrel = dyn->d_un.d_val;
        assert(pltrel == DT_RELA);
        break;
      }

      case DT_RELA: {
        rel = (Elf_Rel*)(code + dyn->d_un.d_ptr);
        LOGF("rel: %p\n", rel);
        break;
      }
      case DT_RELASZ: {
        relsz = dyn->d_un.d_val;
        LOGF("relsz: %d\n", relsz);
        break;
      }
      case DT_PLTRELSZ: {
        pltrelsz = dyn->d_un.d_val;
        LOGF("pltrelsz: %d\n", pltrelsz);
        break;
      }

      case DT_INIT_ARRAY: {
        init_array = (void**)(code + dyn->d_un.d_ptr);
        break;
      }
      case DT_INIT_ARRAYSZ: {
        init_arraysz = dyn->d_un.d_val;
        break;
      }

      }
    }

    assert(rel);
    relocate_dyn("rel", obj, rel, relsz);
    relocate_dyn("pltrel", obj, rel + relsz / sizeof(*rel), pltrelsz);

#if defined(__arm__) || defined(__aarch64__)
    __builtin___clear_cache(obj->code, obj->code + obj->code_size);
#endif

    if (init_array) {
      for (size_t i = 0; i < init_arraysz / sizeof(void*); i++) {
        LOGF("calling init_array: %p\n", init_array[i]);
        ((void(*)())(init_array[i]))();
      }
    }
  }
  return 1;
}

static int load_object(obj_handle* obj, const char* bin, const char* filename) {
  Elf_Ehdr* ehdr = (Elf_Ehdr*)bin;
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
  }

  for (int i = 0; i < ehdr->e_shnum; i++) {
    Elf_Shdr* shdr = &shdrs[i];
    if (shdr->sh_type == SHT_STRTAB && i == strtab_index) {
      strtab = bin + shdr->sh_offset;
    }
  }

#if OBJFCN_SPLIT_ALLOC
  {
    size_t expected_code_size = 0;
    for (int i = 0; i < ehdr->e_shnum; i++) {
      Elf_Shdr* shdr = &shdrs[i];
      if (should_load(shdr)) {
        expected_code_size += shdr->sh_size;
        expected_code_size = align_up(expected_code_size, 16);
      }
    }
    size_t reloc_code_size = relocate(obj, bin, symtab, strtab, addrs,
                                      1 /* code_size_only */);
    if (reloc_code_size == (size_t)-1) {
      return 0;
    }
    expected_code_size += reloc_code_size;

    obj->code_size = align_up(expected_code_size, 4096);
    obj->code = (char*)mmap(NULL, obj->code_size,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS,
                            -1, 0);
    if (obj->code == MAP_FAILED) {
      sprintf(obj_error, "mmap failed: %s", strerror(errno));
      return 0;
    }

#if 0
    fprintf(stderr, "%p-%p (+%zx) %s\n",
            obj->code, obj->code + obj->code_size,
            expected_code_size, filename);
#endif
#if OBJFCN_LOG
    {
      char buf[256];
      FILE* log_fp;
      sprintf(buf, "/tmp/objfcn.%d.log", getpid());
      log_fp = fopen(buf, "ab");
      fprintf(log_fp, "objopen %p-%p (+%zx) %s\n",
              obj->code, obj->code + obj->code_size,
              expected_code_size, filename);
      fclose(log_fp);
    }
#endif
  }

#endif

  memset(addrs, 0, sizeof(addrs));
  for (int i = 0; i < ehdr->e_shnum; i++) {
    Elf_Shdr* shdr = &shdrs[i];
    if (should_load(shdr)) {
      addrs[i] = alloc_code(obj, shdr->sh_size);
      align_code(obj, 16);
      if (shdr->sh_type != SHT_NOBITS) {
        memcpy(addrs[i], bin + shdr->sh_offset, shdr->sh_size);
      }
    }
  }

  for (int i = 0; i < symnum; i++) {
    Elf_Sym* sym = &symtab[i];
    if (ELFW_ST_TYPE(sym->st_info) == STT_OBJECT ||
        ELFW_ST_TYPE(sym->st_info) == STT_FUNC) {
      obj->num_symbols++;
    }
  }
  obj->symbols = (symbol*)malloc(sizeof(symbol) * obj->num_symbols);
  for (int i = 0, ns = 0; i < symnum; i++) {
    Elf_Sym* sym = &symtab[i];
    if (ELFW_ST_TYPE(sym->st_info) == STT_OBJECT ||
        ELFW_ST_TYPE(sym->st_info) == STT_FUNC) {
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

  if (relocate(obj, bin, symtab, strtab, addrs, 0 /* code_size_only */) ==
      (size_t)-1) {
    return 0;
  }

#if defined(__arm__) || defined(__aarch64__)
  __builtin___clear_cache(obj->code, obj->code + obj->code_size);
#endif

  return 1;
}

void* objopen(const char* filename, int flags) {
  char* bin = NULL;
  obj_handle* obj = NULL;
  Elf_Ehdr* ehdr = NULL;

#if !OBJFCN_SPLIT_ALLOC
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

  if (ehdr->e_type == ET_DYN) {
    if (load_object_dyn(obj, bin, filename)) {
      free(bin);
      return obj;
    }
  } else {
    if (load_object(obj, bin, filename)) {
      free(bin);
      return obj;
    }
  }

  free(bin);
  objclose(obj);
  return NULL;
}

int objclose(void* handle) {
  obj_handle* obj = (obj_handle*)handle;
  if (obj->code) {
#if OBJFCN_LOG
    char buf[256];
    FILE* log_fp;
    sprintf(buf, "/tmp/objfcn.%d.log", getpid());
    log_fp = fopen(buf, "ab");
    fprintf(log_fp, "objclose %p-%p\n",
            obj->code, obj->code + obj->code_size);
    fclose(log_fp);
#endif
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
  if (obj->is_dyn) {
    return objsym_dyn(obj, symbol);
  }

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
