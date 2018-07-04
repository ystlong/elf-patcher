
BINUTILS_HOME := /mnt/soft/bbb

CC := gcc
# CFLAGS := -std=gnu99 -g -I$(BINUTILS_HOME)/include -I`pwd`
# LDFLAGS += -L$(BINUTILS_HOME)/lib64 -lbfd  -liberty -ldl -lc -lz 
CFLAGS := -std=gnu99 -g 
LDFLAGS += -lbfd  -liberty -ldl -lc -lz -lopcodes

test: patch-elf-bfd patch-elf-bfd.a
	./patch-elf-bfd patch-elf-bfd rd --func main 31

patch-elf-bfd: patch-elf-bfd.o parse_elf_bfd.o elf-dis.o
	$(CC) $^  $(CFLAGS) $(LDFLAGS) -o $@

patch-elf-bfd.a: patch-elf-bfd.o parse_elf_bfd.o
	$(AR) -rc $@ $^
	objdump -d $@ > $@.asm

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm *.o patch-elf-bfd *.asm *.a
