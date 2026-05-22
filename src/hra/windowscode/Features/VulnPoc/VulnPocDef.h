#pragma once

//导入导出宏定义
#ifdef HRA_VULNPOC_API_COMPILED
#define HRA_VULNPOC_EXPORT __declspec(dllexport)
#else
#define HRA_VULNPOC_EXPORT __declspec(dllimport)
#endif