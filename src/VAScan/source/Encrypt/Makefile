DEBUGFLAGS = -g -O0 -fPIC -L$(LIB_PATH) -lPatternCypherX64 
RELEASEFLAGS = -g -O3 -fPIC -L$(LIB_PATH) -lPatternCypherX64  -funroll-loops

TARGET = PatternEncrypt
objects = main.o ini.o

all = $(TARGET)

.PHONY: release 

release:CCFLAGS += $(RELEASEFLAGS) -std=c++0x -D_GLIBCC_USE_NANOSLEEP -I$(INCLUDE_PATH)
release:$(TARGET)

.PHONY: debug 
debug: CCFLAGS += $(DEBUGFLAGS) -std=c++ -I$(INCLUDE_PATH)

$(TARGET): $(objects)
	$(CC) $(objects)  -L$(LIB_PATH) -lPatternCypherX64 -o$(BIN_PATH)/$(TARGET)

ini.o: ini.cpp 
	$(CC) $(CCFLAGS) -c ini.cpp 

main.o: main.cpp
	$(CC) $(CCFLAGS) -c main.cpp

