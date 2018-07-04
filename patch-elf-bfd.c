/*
* @Author: ystlong
* @Date:   2018-06-30 16:57:28
* @Last Modified by:   ystlong
* @Last Modified time: 2018-07-01 13:54:46
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <inttype.h>
#include "elf-dis.h"
#include "parse_elf_bfd.h"

typedef unsigned char uint8_t;
// void info_abfd(bfd *abfd);
// void info_asection(asection *sect);
// void info_asymbol(asymbol *symbol);
struct opt_offset {
  // 文件偏移
  long val;
  // 该偏移对应的地址vma
  unsigned long addr;
  unsigned long arch;
  unsigned long mach;
  struct opt_offset *next;
};

typedef struct option {
  int type;
#define OPT_ADDR 1
#define OPT_FUNC 2
#define OPT_KEY 3
  union {
    const char *func_name;
    unsigned long addr_value;
    struct {
      uint8_t *val;
      uint8_t *mask;
      int len;
    } key;
  } target;
  const char *org_target;
  const char *value;
  struct opt_offset *file_offset;
  int offset_len;
  // long file_offset;
} option_t;

#define MAX_OPTIONS 10
static option_t *options[MAX_OPTIONS + 1];
static int option_count = 0;
static parse_info_t parse_info;
static int dump_buf_disasm = FALSE;  // d
static int force_write = FALSE;      // f

#define MAX_READ_LEN (4 * 8)
static int buf_read_len = MAX_READ_LEN;
static int exit_status = 1;

static void add_new_offset(option_t *opt, long val, unsigned long addr,
                           bfd *abfd) {
  struct opt_offset *off = opt->file_offset;
  while (off) {
    if (addr == off->addr && val == off->val) return;
    off = off->next;
  }
  off = (struct opt_offset *)malloc(sizeof(struct opt_offset));
  assert(off != NULL);
  memset(off, 0, sizeof(struct opt_offset));
  off->next = opt->file_offset;
  off->val = val;
  off->addr = addr;
  if (abfd != NULL) {
    off->mach = bfd_get_mach(abfd);
    off->arch = bfd_get_arch(abfd);
  }

  opt->file_offset = off;
  opt->offset_len++;
  exit_status = 0;
}

static inline uint8_t char_2_uint8t(char c) {
  if (c >= 'a' && c <= 'f')
    return c - ('a' - '9' + '0' - 1);
  else if (c >= 'A' && c <= 'F')
    return c - ('A' - '9' + '0' - 1);
  else if (c >= '0' && c <= '9')
    return c - '0';
  printf("error char_2_uint8t char format err: %c\n", c);
  exit(-20);
  return 0;
}

// patch_val 应为16进制字符串
static int parse_patch_val(const char *patch_val, size_t val_len,
                           uint8_t *buff) {
  assert(val_len % 2 == 0);
  for (int i; i < val_len; i += 2) {
    buff[i / 2] =
        char_2_uint8t(patch_val[i]) << 4 | char_2_uint8t(patch_val[i + 1]);
  }
  return val_len / 2;
}

static void print_byte(void *_buf, size_t size) {
  uint8_t *buf = (uint8_t *)_buf;
  for (int i = 0; i < size; i++) {
    printf("%02x", buf[i]);
  }
}

static void parse_symbol_file_offset(asymbol *symbol, option_t *opt) {
  // symbol->value表示地址， 相对section其实地址，
  // 即symbol->value+section的offset就为实际symbol对应的offset
  long section_file_offset = symbol->the_bfd->origin + symbol->section->filepos;
  // long symbol_sec_offset = symbol->value - symbol->section->vma;
  long symbol_sec_offset = symbol->value;
  // info_asymbol(symbol);
  // info_asection(symbol->section);

  assert(symbol_sec_offset >= 0 && symbol_sec_offset < symbol->section->size);
  long offset = section_file_offset + symbol_sec_offset;
  add_new_offset(opt, offset, symbol->section->vma + symbol->value,
                 symbol->the_bfd);
  printf("find symbol name: %s, offset: %x, vma: 0x%x\n", symbol->name, offset,
         symbol->value + symbol->section->vma);
}

static int get_symbol_data(asymbol *symbol, int len, uint8_t *buf) {
  // bfd_boolean bfd_get_section_contents
  //  (bfd *abfd, asection *section, void *location, file_ptr offset,
  //   bfd_size_type count);
  if (!bfd_get_section_contents(symbol->the_bfd, symbol->section, buf,
                                symbol->value, len)) {
    // debug("read data error\n");
    return -1;
  }
  return len;
}

static void parse_symbol_opt_key(asymbol *symbol, option_t *opt) {
  assert(opt->type == OPT_KEY);
  uint8_t buf[128];
  if (get_symbol_data(symbol, opt->target.key.len, buf) ==
      opt->target.key.len) {
    for (int i = 0; i < opt->target.key.len; i++) {
      if (opt->target.key.mask[i]) continue;
      if (buf[i] != opt->target.key.val[i]) {
        return;
      }
    }
    print_byte(opt->target.key.val, opt->target.key.len);
    printf(":");
    print_byte(buf, opt->target.key.len);
    printf(" key find at symbol: %s\n", symbol->name);
    parse_symbol_file_offset(symbol, opt);
  }
}

static void process_symbol(asymbol *symbol) {
  if (option_count == 0) info_asymbol(symbol);
  // int symbol_finish = 1;
  for (int i = 0; i < option_count; i++) {
    if (options[i]->type == OPT_FUNC) {
      // if (options[i]->file_offset < 0) {
      if (strcmp(symbol->name, options[i]->target.func_name) == 0) {
        // find symbol, parse file offset
        parse_symbol_file_offset(symbol, options[i]);
      }
      // if (options[i]->file_offset < 0) symbol_finish = 0;
      // }
    } else if (options[i]->type == OPT_KEY) {
      parse_symbol_opt_key(symbol, options[i]);
    }
  }
}

static void parse_section_file_offset(asection *section, option_t *option) {
  long section_file_offset = section->owner->origin + section->filepos;
  // 这里输入的为绝对地址，因此需要计算
  long symbol_sec_offset = option->target.addr_value - section->vma;
  assert(symbol_sec_offset >= 0);
  long offset = section_file_offset + symbol_sec_offset;
  add_new_offset(option, offset, option->target.addr_value, section->owner);
  printf("find addr in section %s, file offset: %x", section->name, offset);
  printf(", vma: 0x%x", option->target.addr_value);
  printf("\n");
}

// reloacte段可能出现错误地址， 有可能一个地址在多个section中，
// 需要在上层过滤只保留代码段，还没做
static void process_section(asection *section) {
  if (option_count == 0) info_asection(section);
  if (strcmp(section->name, ".text") != 0) {
    // 过滤只是用.text段
    return;
  }
  int section_finish = 0;
  for (int i = 0; i < option_count; i++) {
    if (options[i]->type == OPT_ADDR) {
      // if (options[i]->file_offset < 0) {
      if (options[i]->target.addr_value >= section->vma &&
          options[i]->target.addr_value < (section->vma + section->size)) {
        parse_section_file_offset(section, options[i]);
      }
      // if (options[i]->file_offset < 0) section_finish = 0;
      // }
    }
  }
}

static void parse_file(const char *filename) {
  parse_info.process_section = process_section;
  parse_info.process_symbol = process_symbol;
  parse_info.finish = 0;
  parse_elf(filename, &parse_info);
}

static option_t *new_opts(int type, const char *target, const char *value) {
  if (option_count == 0) {
    memset(options, 0, (MAX_OPTIONS + 1) * sizeof(option_t *));
  }
  if (option_count >= MAX_OPTIONS) {
    printf("options is full, exit\n");
    exit(2);
  }
  option_t *opt = (option_t *)malloc(sizeof(option_t));
  if (opt == NULL) {
    printf("request option mem faild exit\n");
    exit(3);
  }
  opt->type = type;
  opt->file_offset = NULL;
  opt->offset_len = 0;
  opt->org_target = target;
  switch (opt->type) {
    case OPT_FUNC:
      opt->target.func_name = target;
      break;
    case OPT_ADDR:
      opt->target.addr_value = strtoul(target, NULL, 16);
      printf("input addr: 0x%x\n", opt->target.addr_value);
      break;
    case OPT_KEY: {
      int len = strlen(target);
      if (len % 2 != 0) {
        printf("key char len error, must even number\n");
        exit(4);
      }
      uint8_t *buf_key = (uint8_t *)malloc(len);
      if (buf_key == NULL) {
        perror("alloc key buf error");
        exit(5);
      }
      opt->target.key.val = buf_key;
      opt->target.key.mask = buf_key + (len / 2);
      opt->target.key.len = len / 2;

      for (int i = 0; i < len; i += 2) {
        if (target[i] == '.' || target[i + 1] == '.') {
          // mask , after will not compiler
          opt->target.key.val[i / 2] = 0;
          opt->target.key.mask[i / 2] = 1;
        } else {
          opt->target.key.val[i / 2] =
              char_2_uint8t(target[i]) << 4 | char_2_uint8t(target[i + 1]);
          opt->target.key.mask[i / 2] = 0;
        }
      }
      // print_byte(opt->target.key.val, opt->target.key.len);
      // printf("\n");
      // print_byte(opt->target.key.mask, opt->target.key.len);
      // printf("\n");
      // exit(3);
    } break;
  }
  opt->value = value;
  options[option_count] = opt;
  option_count++;
  return opt;
}

static void dis_buf(struct opt_offset *opt, void *buf, size_t buf_len) {
  disassemble_buf(stdout, opt->arch, opt->mach, opt->addr, buf_len, buf);
}

static void read_find_val(const char *filename) {
  FILE *file = fopen(filename, "r");
  if (file == NULL) {
    perror("open file");
    exit(4);
    return;
  }
  int out_file = 0;
  for (int i = 0; i < option_count; i++) {
    struct opt_offset *opt_off = options[i]->file_offset;
    if (opt_off == NULL) continue;
    if (out_file == 0) {
      printf("%s\n", filename);
      out_file = 1;
    }
    // printf("offset len: %d, ", options[i]->offset_len);
    printf("read %s:\n", options[i]->org_target);
    uint8_t buf[MAX_READ_LEN];
    while (opt_off) {
      printf("FKEY: ");
      printf("%x: ", opt_off->addr);
      fseek(file, opt_off->val, SEEK_SET);
      fread(buf, 1, buf_read_len, file);
      print_byte(buf, buf_read_len);
      printf("\n");
      if (dump_buf_disasm) {
        dis_buf(opt_off, buf, buf_read_len);
      }
      opt_off = opt_off->next;
    }
    printf("\n");
  }
  fclose(file);
}

#include <fcntl.h>
#include <unistd.h>

int access(const char *pathname, int mode);

static int back_org_file(const char *filename) {
  char buf[1024];
  buf[0] = 0;
  strcat(buf, filename);
  strcat(buf, ".org");
  if (access(buf, F_OK) != -1) {
    //文件存在
  } else {
    // 文件不存在， 备份原始文件
    FILE *ofs = fopen(buf, "w");
    FILE *ifs = fopen(filename, "r");
    if (ofs == NULL || ifs == NULL) {
      perror("error back org file");
      return 1;
    }
    int len;
    char buff[1024];
    while (len = fread(buff, 1, 1024, ifs)) {
      fwrite(buff, 1, len, ofs);
    }
    fclose(ofs);
    fclose(ifs);
  }
  return 0;
}

static void write_find_val(const char *filename) {
  FILE *file = fopen(filename, "r+");
  if (file == NULL) {
    perror("open file write");
    exit(3);
    return;
  }
  uint8_t buf[1024];
  int len;
  int bak_flag = 0;
  for (int i = 0; i < option_count; i++) {
    struct opt_offset *opt_off = options[i]->file_offset;
    if (opt_off != NULL && bak_flag == 0) {
      if (options[i]->offset_len > 1) {
        if (!force_write) {
          printf("warn got key %s multi file_offset skip patch: %s\n",
                 options[i]->org_target, filename);
          continue;
        }
      }
      if (back_org_file(filename)) {
        printf("back org file error, will not write\n");
        exit_status = 2;
        goto _exit;
      }
      bak_flag = 1;
    }
    len = parse_patch_val(options[i]->value, strlen(options[i]->value), buf);
    while (opt_off) {
      fseek(file, opt_off->val, SEEK_SET);
      if (fwrite(buf, 1, len, file) != len) {
        printf(_("warn write val len not match\n"));
        // 如果能够检查写入数据是否正确更好
      }
      opt_off = opt_off->next;
    }
  }
_exit:
  fclose(file);
  return;
}

int main(int argc, char const *argv[]) {
  const char *filename;
  int write = FALSE;
  int pos_inx = 2;
  if (argc < 2) {
  usage:
    printf("boot cmd: [");
    for (int i = 0; i < argc; i++) printf("%s ", argv[i]);
    printf("] run error;\n");
    printf(
        "usage: %s elf_path [r|w|rd|wd] "
        "[--func func_name replace_hex_bytes] "
        "[--addr hex_addr replace_hex_bytes] "
        "[--key hex_key_val replace_hex_bytes]\n"
        "    r       : only read func_name or hex_addr hex byte\n"
        "    w       : will write replace_hex_bytes to elf_path file\n"
        "    rd|wd   : will disassemble read buf\n"
        "    wfd|wdf : force write when find multi key\n"
        "    wf:     : force write when find multi key"
        "\n",
        argv[0]);
    return 1;
  }
  filename = argv[1];
  if (argc > 2) {
    if (strcmp(argv[2], "w") == 0) {
      write = TRUE;
      pos_inx = 3;
    } else if (strcmp(argv[2], "r") == 0) {
      pos_inx = 3;
    } else if (strcmp(argv[2], "rd") == 0) {
      pos_inx = 3;
      dump_buf_disasm = TRUE;
    } else if (strcmp(argv[2], "wd") == 0) {
      write = TRUE;
      pos_inx = 3;
      dump_buf_disasm = TRUE;
    } else if (strcmp(argv[2], "wf") == 0) {
      write = TRUE;
      pos_inx = 3;
      force_write = TRUE;
    } else if (strcmp(argv[2], "wdf") == 0 || strcmp(argv[2], "wfd") == 0) {
      write = TRUE;
      pos_inx = 3;
      force_write = TRUE;
      dump_buf_disasm = TRUE;
    }

    for (pos_inx; pos_inx < argc; pos_inx += 3) {
      if (pos_inx + 3 > argc) goto usage;
      const char *st = argv[pos_inx];

      // printf("%s\n", st);
      if (strcmp(st, "--func") == 0) {
        new_opts(OPT_FUNC, argv[pos_inx + 1], argv[pos_inx + 2]);
      } else if (strcmp(st, "--addr") == 0) {
        new_opts(OPT_ADDR, argv[pos_inx + 1], argv[pos_inx + 2]);
      } else if (strcmp(st, "--key") == 0) {
        // printf("%s\n", argv[pos_inx+1]);
        new_opts(OPT_KEY, argv[pos_inx + 1], argv[pos_inx + 2]);
      } else {
        goto usage;
      }
    }
  }

  parse_file(filename);
  read_find_val(filename);
  if (write && option_count > 0) {
    write_find_val(filename);
    read_find_val(filename);
  }
  /* code */
  return exit_status;
}
