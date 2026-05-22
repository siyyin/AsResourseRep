#pragma once

//导入导出宏定义
#ifdef HRA_BASELINE_API_COMPILED
#ifdef WIN32
#define HRA_BASELINE_EXPORT __declspec(dllexport)
#else
#define HRA_BASELINE_EXPORT
#endif
#else
#ifdef WIN32
#define HRA_BASELINE_EXPORT __declspec(dllimport)
#else
#define HRA_BASELINE_EXPORT extern
#endif
#endif

