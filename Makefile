
BINUTILS_HOME := $(PWD)/binutils.o

BINUTILS_HOME := $(PWD)/binutils.o
LDFLAGS := -L$(BINUTILS_HOME)/lib64 -L$(BINUTILS_HOME)/lib -lopcodes -lbfd  -lz -liberty -ldl
CFLAGS := -I$(BINUTILS_HOME)/include -std=gnu99 -Werror

CC := gcc

test: patch-elf-bfd
	objdump -d patch-elf-bfd > patch-elf-bfd.asm
	./patch-elf-bfd patch-elf-bfd rd --hex ......e54883ec30897ddc488975d0c745ec00000000c745f002000000837ddc 31
	# ./patch-elf-bfd patch-elf-bfd rd --hex 554889e54883ec30897ddc488975d0c745ec00000000c745f002000000837ddc 31
	# ./patch-elf-bfd patch-elf-bfd rd --func main 31

patch-elf-bfd: patch-elf-bfd.o parse_elf_bfd.o elf-dis.o
	$(CC) $^  $(CFLAGS) $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm *.o patch-elf-bfd *.asm *.a
