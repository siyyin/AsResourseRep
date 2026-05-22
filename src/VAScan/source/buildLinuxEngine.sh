#!/bin/bash
export LIB_PATH=$PWD/lib
export INCLUDE_PATH=$PWD/include
export CC=gcc
export CPP=g++ 
export AR=ar
echo $LIB_PATH
export DIR=$PWD
export BUILD_NUMBER=$1
export MACHINE=x86_64

function build_luaJit()
{
    echo "==================Build LuaJit=================================="
    cd $DIR/3rd-party/lua/luajit/LuaJIT-2.1.0/src
    sed -i 's/\r$//' *.*
    make clean
    make
    cp libluajit.a $LIB_PATH/x64/Release
    cd $DIR
}

function build_lua()
{
    echo "==================Build Lua=================================="
    cd  $DIR/3rd-party && tar -xzvf lua-5.1.5.tar.gz
    cd $DIR/3rd-party/lua-5.1.5
    make clean
    make linux
    cp src/liblua.a $LIB_PATH/x64/Release
    rm -r $DIR/3rd-party/lua-5.1.5
    cd $DIR
}

function build_vascan()
{
    echo "==================Build VAScan ================================"
    cd VAScan
    sed -i 's/\r$//' *.*
    make clean
    make   
    cp libvaeng.so ../../output/x64
    cp libvaeng.a ../../output/x64
    make clean
    cd ../
    echo "OK        Successfully build libvaeng"
}

function build_vascantest()
{
    echo "==================Build VAScanTest============================="
    cd VAScanTest
    sed -i 's/\r$//' *.*
    make clean
    make
    cp VAScanTest ../../output/x64
    make clean
    cd ../
    echo "OK        Successfully build VAScanTest"
}

function build_pattern()
{
    echo "==================Build Pattern ================================"
    cd pattern
    cp va*[$]* ../../output/x64
    cd ../
    echo "OK        Successfully  build_pattern"
}

mkdir ../output/x64
rm -rf ../output/x64/*
# build_lua
build_vascan
build_pattern
build_vascantest
