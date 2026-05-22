#pragma once

//导入导出宏定义
#ifdef HRA_REGREPORT_API_COMPILED
#ifdef WIN32
#define HRA_REGREPORT_EXPORT __declspec(dllexport)
#else
#define HRA_REGREPORT_EXPORT
#endif
#else
#ifdef WIN32
#define HRA_REGREPORT_EXPORT __declspec(dllimport)
#else
#define HRA_REGREPORT_EXPORT extern
#endif
#endif

#include "json/json.h"

int HRA_REGREPORT_EXPORT RegReportInit();
int HRA_REGREPORT_EXPORT RegReportDestroy();
int HRA_REGREPORT_EXPORT RegReportCfgHandle(const Json::Value& jsContect);