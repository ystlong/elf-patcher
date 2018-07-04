#ifndef ELF_DIS_H
#define ELF_DIS_H 1

#include "config.h"
#include "bfd.h"
#include "dis-asm.h"

void disassemble_buf(FILE *stream, unsigned long arch, unsigned long mach, 
	bfd_vma pc, size_t buf_len, void *buf);

#endif