
## elf-patcher

tool for elf file binrary bytes addr and  function find or modify

### usage

使用方式： `./patch-elf-bfd elf_file command options`

```
./patch-elf-bfd elf_file [r|w|rd|wd|wdf|wf] \
    [--func fun_name replace_hex_bytes] \
    [--key find_hex_bytes replace_hex_bytes] \
    [--hex find_hex_bytes replace_hex_bytes] \
    [--addr hex_addr replace_hex_bytes]
```

command: 

- r  :    读取指定options的数据
- rd :   读取指定options的数据，并反汇编
- w  :   读取指定options的数据，并将replace_hex_bytes写入到查找的位置
- wd :   读取指定options的数据，并反汇编，并将replace_hex_bytes写入到查找的位置，当查找到多个位置时不写入
- wdf:   读取指定options的数据，并反汇编，并将replace_hex_bytes强制写入到查找的所有位置

options:

- `--func` :  在符号表中查找函数名
- `--key`  :  匹配所有符号表每一项对应数据开头的bytes，
- `--hex`  :  在`.text`section中搜索`find_hex_bytes`
- `--addr` :  搜索对应地址

`find_hex_bytes`: 可以使用`.`代替任意byte。


### bfd library doc

https://sourceware.org/binutils/docs-2.30/bfd/index.html