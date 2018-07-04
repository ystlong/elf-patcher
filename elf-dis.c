/*
* @Author: ystlong
* @Date:   2018-06-11 19:13:04
* @Last Modified by:   slp
* @Last Modified time: 2018-07-02 08:58:52

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "config.h"
#include "bfd.h"
#include "dis-asm.h"
#include "elf-dis.h"
#include "disassemble.h"

typedef struct {
	disassemble_info dis_info;
	unsigned char buf[128];
	int buf_inx;
	FILE *stream;
}disassemble_wrapper;

// bfd_vma, struct disassemble_info * -> void
// Formatter for address in memory referencing instructions
static void override_print_address(bfd_vma addr, struct disassemble_info *info){
	int len;
	disassemble_wrapper *dis_wrapper = (disassemble_wrapper*)info->stream;
	if ((long)addr >= 0)
		len = sprintf(dis_wrapper->buf + dis_wrapper->buf_inx, "#{pc}+%ld", addr);
	else
		len = sprintf(dis_wrapper->buf + dis_wrapper->buf_inx, "#{pc}%ld", addr);
	dis_wrapper->buf_inx += len;
}


static int buf_stream_printf(void *stream, const char *format, ...)
{
	int len = 0;
	disassemble_wrapper *dis_wrapper = (disassemble_wrapper*)stream;
	 va_list ap;
	 va_start(ap, format);
	 len = vsprintf(dis_wrapper->buf + dis_wrapper->buf_inx, format, ap);
	 va_end(ap);
	 dis_wrapper->buf_inx += len;
}

static void local_init_disassemble_info(struct disassemble_info *dis, unsigned long arch, unsigned long mach)
{
    init_disassemble_info (dis, stdout, (fprintf_ftype) buf_stream_printf);

    // dis->buffer_vma = pc;
    // dis->buffer = buf;
    // dis->buffer_length = buflen;
    dis->print_address_func = override_print_address;
    // dis->disassembler_options = disas_options;
    dis->fprintf_func = buf_stream_printf;
    // dis->stream = stdout;
    // dis->arch = bfd_arch_aarch64;
    // dis->mach = bfd_mach_aarch64;
    // dis->arch = bfd_arch_i386;
    // dis->mach = bfd_mach_x86_64;
    dis->arch = arch;
    dis->mach = mach;
}

static const char *print_byte(const unsigned char *bytes, size_t len, char *ref_buf)
{
	int inx = 0;
	for(int i=0; i<len; i++){
		inx += sprintf(ref_buf+inx, "%02x", bytes[i]);
	}
	ref_buf[inx] = 0;
	return ref_buf;
}

static void dump_buf(disassemble_wrapper *dis_wrapper)
{
	int res = 0;
	int len = 0;
	int vma_buf_inx = 0;
	char tmp_buf[32];
	for(int i=0; i<dis_wrapper->dis_info.buffer_length; i += len) {
		dis_wrapper->buf_inx = 0;
		bfd_vma cur_pc = dis_wrapper->dis_info.buffer_vma + i;

		len = print_insn_i386(cur_pc, &dis_wrapper->dis_info);
		dis_wrapper->buf[dis_wrapper->buf_inx] = 0;
		fprintf(dis_wrapper->stream, "%8x: %-20s  %s\n", cur_pc, 
			print_byte(dis_wrapper->dis_info.buffer + i, len, tmp_buf),
			dis_wrapper->buf);
	}
}

void disassemble_buf(FILE *stream, unsigned long arch, unsigned long mach, 
	bfd_vma pc, size_t buf_len, void *buf)
{
	disassemble_wrapper dis_wrapper;
	dis_wrapper.buf_inx = 0;
	dis_wrapper.buf[0] = 0;
	dis_wrapper.stream = stream;
	local_init_disassemble_info(&dis_wrapper.dis_info, arch, mach);
	dis_wrapper.dis_info.stream = &dis_wrapper;

	// buf base addr
	dis_wrapper.dis_info.buffer_vma = pc;
	dis_wrapper.dis_info.buffer = buf;
	dis_wrapper.dis_info.buffer_length = buf_len;
	dis_wrapper.dis_info.stream = &dis_wrapper;

	dump_buf(&dis_wrapper);
}

// int main() {

// 	long pc;
// 	struct disassemble_info dis_info;
// 	struct disassemble_info *dis = &dis_info;
// 	bfd_byte buf[120];
// 	long *vma = &pc;
// 	int buflen = 120;
// 	char *disas_options = "";
// 	memset(&dis_info, 0, sizeof(dis_info));

//     init_disassemble_info (&dis_info, stdout, (fprintf_ftype) fprintf);

//     pc = 0;
//     dis->buffer_vma = pc;
//     dis->buffer = buf;
//     dis->buffer_length = buflen;
//     dis->print_address_func = override_print_address;
//     // dis->disassembler_options = disas_options;
//     dis->fprintf_func = fprintf;
//     // dis->stream = stdout;
//     // dis->arch = bfd_arch_aarch64;
//     // dis->mach = bfd_mach_aarch64;
//     dis->arch = bfd_arch_i386;
//     dis->mach = bfd_mach_x86_64;

//     // dis->endian = BFD_ENDIAN_LITTLE;
//     // dis->endian_code = BFD_ENDIAN_LITTLE;
//     // dis->insn_sets = ???
//     // dis->section = ???
//     // dis->octets_per_byte = 4;
// 	pc = 0;
// 	unsigned int mov_inst[] = {
// 		0xaa0203e1,
// 		0x14000000,
// 		0x17ffffff,
// 		0x94000002
// 	};

// 	unsigned char t_buf[] = {0x55, 0x48, 0x8d, 0x15, 0xfa, 0xec, 0x76, 0x01, 0x48, 0x89, 0xe5, 0x5d, 0xe9, 0x8f, 0x79, 0xfe, 0xff, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x1f, 0x44, 0x00, 0x00};
// 	disassemble_buf(stdout, bfd_arch_i386, bfd_mach_x86_64, pc, sizeof(t_buf), t_buf);

// 	// printf("len: %d\n", sizeof(t_buf));
// 	// // dis->disassembler_needs_relocs = 1;
// 	// // memcpy(dis->buffer, t_buf, sizeof(t_buf));
// 	// pc = 0x7fcec70;
// 	// dis->buffer = t_buf;
// 	// dis->buffer_length = sizeof(t_buf);
// 	// dis->buffer_vma = pc;
// 	// int res = 0;
// 	// int len = 0;
// 	// for(int i=0; i<sizeof(t_buf); i += len) {
// 	// 	len = print_insn_i386(pc+i, &dis_info);
// 	// 	printf("\n");
// 	// }
//     return 0;
// }