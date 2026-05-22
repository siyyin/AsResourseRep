#===========================================================================================================================================
#
# Makefile: compiling the VAScan engine.
#
# Author: liko_huang
#
# Date: 9/8/2021
#
#===========================================================================================================================================

LLIB = -L../lib/x64/Release
COMMON_HEADER = -I ../include/lua -I ../include/zlib -I ./ExtendFunc

DEBUGFLAGS   = -g -O0 -fPIC
RELEASEFLAGS = -g -O3 -fPIC
TARGET = libvaeng

objects =  ExtendFunc.o VAScan.o cypher.o cpbf.o md5.o

all = $(TARGET)

.PHONY: copy clean

.PHONY: release
release: CCFLAGS += $(RELEASEFLAGS) -std=c++0x -D_GLIBCXX_USE_NANOSLEEP $(COMMON_HEADER) 
release: CFLAGS += $(RELEASEFLAGS) -D_GLIBCXX_USE_NANOSLEEP $(COMMON_HEADER)
release: $(TARGET)

.PHONY: debug
debug: CCFLAGS += $(DEBUGFLAGS) -std=c++0x -D_GLIBCXX_USE_NANOSLEEP $(COMMON_HEADER)
debug: CFLAGS += $(DEBUGFLAGS) -D_GLIBCXX_USE_NANOSLEEP $(COMMON_HEADER)
debug: $(TARGET)

$(TARGET): $(objects)
	$(CC) $(objects) -Bstatic $(LLIB) -llua -lz -shared -fPIC -o $(TARGET).so
	$(AR) rcs $(TARGET).a $(objects)

cypher.o: ../cypher/cypher.c
	$(CC) $(CFLAGS) -c ../cypher/cypher.c

cpbf.o: ../cypher/cpbf.c
	$(CC) $(CFLAGS) -c ../cypher/cpbf.c

md5.o:  ../md5/md5.cpp
	$(CC) $(CFLAGS) -c ../md5/md5.cpp

ExtendFunc.o: ./ExtendFunc/ExtendFunc.cpp
	$(CC) $(CCFLAGS) -c ./ExtendFunc/ExtendFunc.cpp
	
VAScan.o: VAScan.cpp
	$(CC) $(CCFLAGS) -c VAScan.cpp

.IGNORE: clean
clean:
	rm -f *.so *.o *.a
