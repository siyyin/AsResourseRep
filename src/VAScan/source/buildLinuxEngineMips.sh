#!/bin/bash
export ENGINE=akeng
export LIB_PATH=$PWD/lib
export BIN_PATH=$PWD/bin

export LD_LIBRARY_PATH=/opt/crosstool/gcc-4.8.3-d197-n64-loongson-mips64el/x86_64-unknown-linux-gnu/mips64el-redhat-linux/lib:/opt/crosstool/gcc-4.8.3-d197-n64-loongson-mips64el/lib
export PATH=/opt/crosstool/gcc-4.8.3-d197-n64-loongson-mips64el/bin:$PATH
export INCLUDE_PATH=$PWD/include
export CC=mips64el-redhat-linux-gcc
export CPP=mips64el-redhat-linux-g++
export AR=ar
mkdir -p bin 
mkdir -p lib 
mkdir -p output
echo $LIB_PATH
export DIR=$PWD
RED='\033[0;31m'
NC='\033[0m' # No Color
export BUILD_NUMBER=$1
export MACHINE=loongson

function build_lua()
{
	
	echo "==================Build LuaJit=================================="
	cd $DIR/3rd-party/lua/luajit/LuaJIT-2.1.0
	make clean
	make 
	cp src/libluajit.a $LIB_PATH/
}

function build_lua_arm()
{
	echo "===============build luaJit for arm============================"
	cd $DIR/3rd-party/lua/luajit/LuaJIT-2.1.0
	make clean
	make HOST_CC="gcc" CROSS=mips64el-redhat-linux-
	pwd
	cp src/libluajit.a $LIB_PATH/

}

function build_attackio()
{
	echo "==================Build AttacIO=================================="
	cd $DIR/AttackIO
	rm -rf *.o
	ENGINE=AttacIO  make clean
	make   
	cd $DIR
}

function build_test()
{
	echo "==================Build AttackIOTest============================="

	cd $DIR/AttackIOTest
	echo $PWD
	rm -rf *.o
	make
	echo "==================Build Encrypt=================================="
}

function build_encrypt()
{
	echo "==================Build Encrypt=================================="
	cd $DIR/Encrypt
	make 
}

function build_pattern()
{
	echo "==================Build Pattern=================================="
	cd $DIR/pattern
	echo $1
	python3 buildrules.py -v $1 -p

	cd $DIR
	chmod +x ./bin/PatternEncrypt
}

function build_test_case(){
	cd $DIR/AttackIOTestLinux
	echo $PWD	
	$CC  main.cpp  base.cpp *_linux.cpp -I$DIR/include -lgtest -ljsoncpp  -L$DIR/lib -lakeng   -llua -lPatternCypherX64 -lz  -fPIC -ldl -o $DIR/bin/AttackIOTestSuite	
}

function build_ut_test(){
	cd $DIR/AttackIOUTTest/AttackIOTestLinux
	make 
	cd $DIR
}


function add_file_version(){
	cd $DIR/pattern
	python3 buildrules.py -v $1 -e
	cd $DIR 
}

function add_zip_file()
{
	cd $DIR/pattern
	python3 buildrules.py -v $1 -z
}


function test_case()
{
	echo "===============================Test===================================="
	
	       
	SUCCESS="${RED}******************************Engine Run Success！****************************${NC}\n"
	cd $DIR/bin	
	./akengTest $DIR/pattern/TestJson/Linux_WebShell.json 
	status=$?
	$DIR/bin/AttackIOTestSuite 
	echo $status
	[ $status -eq 0 ] && printf $SUCCESS || printf $FAILED
	printf "\033[0m\n\n"	
}

if [ $# -eq 0 ];
then 
	echo $0 "build_number"
	exit
fi
chmod +x ./tools/PatternEncrypt

echo $PATH

add_file_version $1
build_lua_arm
build_attackio
add_zip_file $1
build_test

