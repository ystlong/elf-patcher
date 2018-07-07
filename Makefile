
BINUTILS_HOME := $(PWD)/binutils.o

BINUTILS_HOME := $(PWD)/binutils.o
LDFLAGS := -L$(BINUTILS_HOME)/lib64 -L$(BINUTILS_HOME)/lib -lopcodes -lbfd  -lz -liberty -ldl
CFLAGS := -I$(BINUTILS_HOME)/include -std=gnu99 -Werror

CC := gcc


build: $(BINUTILS_HOME) patch-elf-bfd
	@echo "******build finish********"

patch-elf-bfd: patch-elf-bfd.o parse_elf_bfd.o elf-dis.o
	$(CC) $^  $(CFLAGS) $(LDFLAGS) -o $@

$(BINUTILS_HOME):
	sh ./build_binutils.sh

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@
	
test: patch-elf-bfd
	./patch-elf-bfd patch-elf-bfd rd --hex 85c0740f8b059a97420083 31
	./patch-elf-bfd patch-elf-bfd rd --func main 31
	./patch-elf-bfd patch-elf-bfd rd --key 554889e54883ec30897d 31
	./patch-elf-bfd patch-elf-bfd rd --addr 40c3ba 31
	./patch-elf-bfd patch-elf-bfd rd --addr 40c3ba 31 --func main 31



clean:
	rm *.o patch-elf-bfd *.asm *.a
