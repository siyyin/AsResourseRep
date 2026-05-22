#pragma once
//#ifndef __HRA_PATTERN_UPDATE_H__
//#define __HRA_PATTERN_UPDATE_H__

#include <string>
#include "utility/comm.h"

//导入导出宏定义
#ifdef HRA_PATTERNUPDATE_API_COMPILED
#ifdef WIN32
#define HRA_PATTERNUPDATE_EXPORT __declspec(dllexport)
#else
#define HRA_PATTERNUPDATE_EXPORT
#endif
#else
#ifdef WIN32
#define HRA_PATTERNUPDATE_EXPORT __declspec(dllimport)
#else
#define HRA_PATTERNUPDATE_EXPORT extern
#endif
#endif

HRA_PATTERNUPDATE_EXPORT std::string PatternUpdateHandleJsonData(char *pscJsonData, unsigned int ulJsonDataLen);

//#endif