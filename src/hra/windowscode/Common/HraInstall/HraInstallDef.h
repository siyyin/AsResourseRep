#pragma once

#ifdef HRA_INSTALL_API_EXPORTS
#ifdef _WIN32
#define HRA_INSTALL_API __declspec(dllexport)
#else
#define HRA_INSTALL_API
#endif
#else
#ifdef _WIN32
#define HRA_INSTALL_API __declspec(dllimport)
#else
#define HRA_INSTALL_API extern
#endif
#endif

//安装方式，集成部署或者是独立部署
#define HRA_INSTALL_TYPE_INTEGRATED 0  //集成安装，随产品安装
#define HRA_INSTALL_TYPE_INDEPENDENT 1 //独立部署
#define HRA_INSTALL_TYPE_FORCE 2 //强制更新（危险，请勿使用，主要是用来测试）

//安装后处理动作
#define HRA_INSTALL_ACTION_NONE 0           // 无任何动作
#define HRA_INSTALL_ACTION_START_SERVER 1   // 安装后立即启动服务

#define HRA_UNINSTALL_ACTION_DELETE_DATA 0  // 卸载HRA,删除数据文件
#define HRA_UNINSTALL_ACTION_UPDATE      1  // 更新HRA,保留数据文件


//命令起始符，不用-是为了防止有些路径中带-号
#define HRA_INSTALL_PARAM_START L"--"
// hra服务传参
#define HRA_INSTALL_PARAM_UUID L"uuid"         // uuid
#define HRA_INSTALL_PARAM_PRO_IPC_NAME L"pro_ipc_name" // pro_ipc_name
#define HRA_INSTALL_PARAM_HRA_IPC_NAME L"hra_ipc_name" // hra_ipc_name
#define HRA_INSTALL_PARAM_HRA_SERVICE_NAME L"hra_service_name" // hra服务名