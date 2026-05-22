#pragma once

//导入导出宏定义
#ifdef HRA_LOGMGR_API_COMPILED
#ifdef WIN32
#define HRA_LOGMGR_EXPORT __declspec(dllexport)
#else
#define HRA_LOGMGR_EXPORT
#endif
#else
#ifdef WIN32
#define HRA_LOGMGR_EXPORT __declspec(dllimport)
#else
#define HRA_LOGMGR_EXPORT extern
#endif
#endif

#include "json/json.h"

int HRA_LOGMGR_EXPORT LogMgrInit();
int HRA_LOGMGR_EXPORT LogMgrDestroy();
int HRA_LOGMGR_EXPORT LogMgrCfgHandle(const Json::Value& jsContect);
