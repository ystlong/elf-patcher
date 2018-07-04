#ifndef PARSE_ELF_BFD_H
#define PARSE_ELF_BFD_H 1

#include "config.h"
#include "bfd.h"

typedef struct parse_info {
  void (*process_symbol)(asymbol *symbol);
  void (*process_section)(asection *section);
  int finish;
} parse_info_t;

int parse_elf(const char *filename, parse_info_t *parse_info);

void info_abfd(bfd *abfd);
void info_asection(asection *sect);
void info_asymbol(asymbol *symbol);


#define _(msg) "%s:%d " msg, __FILE__, __LINE__
#define _l() printf("%s:%d ", __FILE__, __LINE__)
#define debug(args...) _l();printf(args)

#endif