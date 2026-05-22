#pragma once

//########################################################
//注意：为了免杀，将原先的WPScan改成了Dolphin，我也很无奈
//########################################################

//导入导出宏定义
#ifdef HRA_DOLPHIN_API_COMPILED
#ifdef WIN32
#define HRA_DOLPHIN_EXPORT __declspec(dllexport)
#else
#define HRA_DOLPHIN_EXPORT
#endif
#else
#ifdef WIN32
#define HRA_DOLPHIN_EXPORT __declspec(dllimport)
#else
#define HRA_DOLPHIN_EXPORT extern
#endif
#endif

#include "json/json.h"

int HRA_DOLPHIN_EXPORT DolphinInit();
int HRA_DOLPHIN_EXPORT DolphinDestroy();
int HRA_DOLPHIN_EXPORT DolphinCfgHandle(const Json::Value& jsContect);
int HRA_DOLPHIN_EXPORT DolphinPatternUpdate(const std::string& strPatternFile, const std::string& strTempDir);
int HRA_DOLPHIN_EXPORT DolphinCopyPattPack(std::string& strTmpDir, const std::string& strPatternFile);

int HRA_DOLPHIN_EXPORT DolphinCancelInit();
int HRA_DOLPHIN_EXPORT DolphinCancelDestroy();
int HRA_DOLPHIN_EXPORT DolphinCancelHandle(const Json::Value& jsContect);
