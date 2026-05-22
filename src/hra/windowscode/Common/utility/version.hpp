#pragma once

// for cmake
#define HRA_VER_MAJOR 3
#define HRA_VER_MINOR 3
#define HRA_VER_PATCH 0
#define HRA_VER_BUILD 1

#define HRA_VERSION (HRA_VER_MAJOR * 10000 + HRA_VER_MINOR * 100 + HRA_VER_PATCH)
#define HRA_VERSION_BUILD (HRA_VER_MAJOR * 1000000 + HRA_VER_MINOR * 10000 + HRA_VER_PATCH*100 + HRA_VER_BUILD)
#define HRA_VERSION_BUILD_MAKE(a,b,c,d) (a*1000000 + b*10000 + c*100 + d)

// for source code
#define _HRA_STR(s) #s
#define HRA_PROJECT_VERSION(major, minor, patch, build)    _HRA_STR(major.minor.patch.build)
#define HRA_VERSION_STRING  HRA_PROJECT_VERSION(HRA_VER_MAJOR,HRA_VER_MINOR,HRA_VER_PATCH,HRA_VER_BUILD)

//#define HRA_CONN(major, minor, patch, build)        major##,##minor##,##patch##,##build
//#define HRA_VERSION_CONN                            HRA_CONN(HRA_VER_MAJOR,HRA_VER_MINOR,HRA_VER_PATCH,HRA_VER_BUILD)