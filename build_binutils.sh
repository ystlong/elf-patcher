# @Author: slp
# @Date:   2018-06-12 10:54:55
# @Last Modified by:   ystlong
# @Last Modified time: 2018-07-04 17:38:25

get_script_real_file()
{
  real_entry_dir=`pwd`
  script_real_file=$BASH_SOURCE
  i=0
  while [[ `ls -l $script_real_file|grep -e '->'` != "" ]]; do
    # get link file
    link_script_real_file=`ls $script_real_file -l|awk -F '->' '{print $2}'`
    # delete blank char
    link_script_real_file=`echo $link_script_real_file`
    # check link symbol file abs path or relative path
    cg_link_script_real_file=`dirname $script_real_file`/$link_script_real_file
    if [ ! -e $cg_link_script_real_file ]; then
      #  link symbol use abs path
      cg_link_script_real_file=$link_script_real_file
    fi
    script_real_file=$cg_link_script_real_file
    echo "find-link-file: $cg_link_script_real_file"
    i=$((i+1))
    if [[ $i -gt 10 ]]; then
      echo "can not find the sublime start cmd, maybe much symbol link"
      exit 1
    fi
  done
  script_real_dir=`dirname $script_real_file`
  script_abs_real_dir=`cd $script_real_dir&&pwd`
  cd $real_entry_dir
}
get_script_real_file

cd $script_abs_real_dir

binutils_src_path=`pwd`/tmp/binutils-2.30
install_path=`pwd`/binutils.o

rm -rf tmp

set -e
mkdir -p tmp
cd tmp
if [ ! -e binutils-2.30.tar.xz ]; then
	wget https://ftp.gnu.org/gnu/binutils/binutils-2.30.tar.xz
fi
tar -xf binutils-2.30.tar.xz

export CFLAGS=-fPIC

cd $binutils_src_path/bfd
./configure --prefix=$install_path --enable-targets=x86_64-unkown-linux --with-arch_32=i686 
make -j4 && make install

cd $binutils_src_path/opcodes
./configure --prefix=$install_path --enable-targets=x86_64-unkown-linux --with-arch_32=i686 
make -j4 && make install
cp disassemble.h $install_path/include

cd $binutils_src_path/libiberty 
./configure --prefix=$install_path --enable-targets=x86_64-unkown-linux --with-arch_32=i686 
make -j4 && make install
mkdir -p $install_path/lib64
cp libiberty.a $install_path/lib64/

cd $binutils_src_path/zlib
./configure --prefix=$install_path --enable-targets=x86_64-unkown-linux --with-arch_32=i686 
make -j4 && make install

# cd $binutils_src_path
# ./configure --prefix=$install_path --enable-targets=x86_64-unkown-linux --with-arch_32=i686 
# make -j5 && make install

cd $script_abs_real_dir
rm -rf tmp
