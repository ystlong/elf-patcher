/*
* @Author: ystlong
* @Date:   2018-06-30 16:23:39
* @Last Modified by:   slp
* @Last Modified time: 2018-07-02 10:04:04
*/

#include <stdio.h>
#include <stdlib.h>
// #include "bfd.h"
#include "parse_elf_bfd.h"
// #define _(msg) "%s:%d " msg, __FILE__, __LINE__

// #define debug(msg) printf(_(msg));

// typedef struct parse_info {
//   void (*process_symbol)(asymbol *symbol);
//   void (*process_section)(asection *section);
//   int finish;
// } parse_info_t;

static int exit_status = 0;
#define bfd_fatal(args...) \
  do {                     \
    printf(args);          \
    exit(2);               \
  } while (0)

#define nonfatal(msg)    \
  do {                   \
    printf(_(""));       \
    printf("%s\n", msg); \
    exit_status = 1;     \
  } while (0)

static long get_file_size(const char *filename) {
  struct stat st;
  stat(filename, &st);
  return st.st_size;
}

static bfd *open_file(const char *filename) {
  bfd *abfd;
  char *target = NULL;
  if (get_file_size(filename) < 1) {
    exit_status = 1;
    return NULL;
  }

  abfd = bfd_openr(filename, target);

  if (abfd == NULL) {
    // nonfatal(filename);
    printf(_("bfd file openr error%s\n"), filename);
    return NULL;
  }
  return abfd;
}

void info_abfd(bfd *abfd) {
  printf("bfd name: %s, ", abfd->filename);
  printf("sections: %p, ", abfd->sections);
  printf("start_address: %x, ", abfd->start_address);
  printf("target_xvec_name: %s, ", abfd->xvec->name);
  printf("origin: %-8x, ", abfd->origin);
  printf("proxy_origin: %-8x, ", abfd->proxy_origin);
  printf("\n");
}

void info_asection(asection *sect) {
  printf("sect name: %-20s, ", sect->name);
  printf("size: %-8x, ", sect->size);
  printf("filepos: %-8x,", sect->filepos);
  // printf("file_ptr origin: %-8x, ", sect->origin);
  // printf("offset: %-8d, ", sect->offset);
  printf("vma: 0x%x, ", sect->vma);
  printf("flags: 0x%x", sect->flags);
  printf("\n");
}

void info_asymbol(asymbol *symbol) {
  printf("symbol ");
  printf("name: %-15s, ", symbol->name);
  printf("value: %-8x, ", symbol->value);
  printf("\n");

  // if (strcmp(symbol->name, "main") == 0) {
  //   info_asection(symbol->section);
  // }
  return;
}

void parse_dynamic_symtab(bfd *abfd, parse_info_t *parse_info) {
  asymbol **sy = NULL;
  long storage;
  int dynsymcount = 0;

  storage = bfd_get_dynamic_symtab_upper_bound(abfd);
  if (storage < 0) {
    if (!(bfd_get_file_flags(abfd) & DYNAMIC)) {
      // printf(_("%s: not a dynamic object\n"), bfd_get_filename(abfd));
      exit_status = 1;
      dynsymcount = 0;
      return;
    }

    bfd_fatal(bfd_get_filename(abfd));
  }
  if (storage) sy = (asymbol **)malloc(storage);

  dynsymcount = bfd_canonicalize_dynamic_symtab(abfd, sy);
  if (dynsymcount < 0) bfd_fatal(bfd_get_filename(abfd));
  for (long i = 0; i < dynsymcount; i++) {
    // 所有处理完成
    if (parse_info->finish) break;
    // 回调dyn symbol
    parse_info->process_symbol(sy[i]);
  }
}

static void parse_list_symbol(bfd *abfd, parse_info_t *parse_info) {
  asymbol **symbol_table;
  long storage_needed;
  long number_of_symbols;
  long i;
  if (parse_info == NULL) return;
  storage_needed = bfd_get_symtab_upper_bound(abfd);

  if (storage_needed < 0) {
    printf(_("get sytab upper bound error\n"));
    return;
  }
  if (storage_needed == 0) return;

  symbol_table = (asymbol **)malloc(storage_needed);
  number_of_symbols = bfd_canonicalize_symtab(abfd, symbol_table);

  if (number_of_symbols < 0) {
    printf(_("get sytab upper bound error\n"));
    return;
  }
  for (i = 0; i < number_of_symbols; i++) {
    // 所有处理完成
    if (parse_info->finish) break;
    // 回调symbol
    parse_info->process_symbol(symbol_table[i]);
    // info_asymbol(symbol_table[i]);
  }
}

static void parse_object_section(bfd *abfd, parse_info_t *parse_info) {
  asection *p;
  if (parse_info == NULL) return;
  for (p = abfd->sections; p != NULL; p = p->next) {
    if (parse_info->finish) break;
    if (parse_info->process_section) {
      parse_info->process_section(p);
    }
  }
  // bfd_map_over_sections(abfd, sec_func_call, parse_info);
}

static void parse_object_bfd(bfd *abfd, parse_info_t *parse_info) {
  char **matching;
  if (bfd_check_format_matches(abfd, bfd_object, &matching)) {
    // info_abfd(abfd);
    // get_section(abfd);
    // symbol_read(abfd);
    parse_list_symbol(abfd, parse_info);
    parse_dynamic_symtab(abfd, parse_info);
    parse_object_section(abfd, parse_info);
    return;
  }

  // if (bfd_get_error () == bfd_error_file_ambiguously_recognized)
  //   {
  //     nonfatal (bfd_get_filename (abfd));
  //     // list_matching_formats (matching);
  //     free (matching);
  //     return;
  //   }

  if (bfd_get_error() != bfd_error_file_not_recognized) {
    nonfatal(bfd_get_filename(abfd));
    return;
  }
}

static void parse_any_bfd(bfd *abfd, int level, parse_info_t *parse_info) {
  char **matching;
  // if (bfd_check_format_matches(abfd, bfd_archive, &matching)) {
  if (bfd_check_format(abfd, bfd_archive)) {
    bfd *arfile = NULL;
    bfd *last_arfile = NULL;
    if (level == 0) {
      // printf(_("In archive %s:\n"), bfd_get_filename(abfd));
    }else if (level > 100) { 
      printf(_("Archive nesting is too deep"));
      return;
    } else{
      printf(_("In nested archive %s:\n"), bfd_get_filename(abfd));
    }

    for (;;) {
      bfd_set_error(bfd_error_no_error);

      arfile = bfd_openr_next_archived_file(abfd, arfile);
      if (arfile == NULL) {
        if (bfd_get_error() != bfd_error_no_more_archived_files)
          nonfatal(bfd_get_filename(abfd));
        break;
      }

      parse_any_bfd(arfile, level + 1, parse_info);

      if (last_arfile != NULL) {
        bfd_close(last_arfile);
        /* PR 17512: file: ac585d01.  */
        if (arfile == last_arfile) {
          last_arfile = NULL;
          break;
        }
      }
      last_arfile = arfile;
    }
  } else {
    parse_object_bfd(abfd, parse_info);
  }
}

int parse_elf(const char *filename, parse_info_t *parse_info) {
  bfd *abfd = NULL;
  bfd_init();
  bfd_set_default_target("elf64-x86-64");
  if (parse_info == NULL) {
    printf(_("please set parse_info\n"));
    return 2;
  }

  abfd = open_file(filename);
  if (abfd == NULL) {
    nonfatal("open file error");
    return 1;
  }
  // printf("%s\n", abfd->xvec->name);
  // return 0;
  parse_any_bfd(abfd, 0, parse_info);
}

