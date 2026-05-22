//--------------------------------------------------------------------------
// (C) Copyright (C) 2021 亚信科技（成都）有限公司
// All Rights Reserved.
//
// 文件名称 :	AsiEsmIpcServerPlugin.h
// 
// 描述：声明IPC Server组件的导出接口
//
// 作者:	songhy3
//
// 时间 :	2021.08.06
//
// 修改记录
//
#ifndef ASIESMIPCSERVERPLUGIN_H
#define ASIESMIPCSERVERPLUGIN_H

#ifdef __cplusplus
	extern "C" {
#endif

#define ASIESMIPCSERVERPLUGINDLL_API
#define _IN
#define _OUT

typedef int (*Cmd_Handler)(
	_IN int iType, 
	_IN unsigned char *params,
	_IN int paramsLen,
	_OUT unsigned char *pOutBuf,
	_IN int iOutBufLen);

// 导出接口类型定义
#ifndef INIT_PLUGIN_FUN_DEFINE
#define INIT_PLUGIN_FUN_DEFINE
typedef int (*PINIT_PLUGIN_FUN)(const char* pszName);
typedef int (*PREGISTER_CALLBACK_FUN)(int iType, Cmd_Handler* pCmdHandler);
typedef int (*PSTART_LISTEN_SERVICE)(void);
typedef int (*PSTOP_LISTEN_SERVICE)(void);
#endif

//--------------------------------------------------------------------------
/******************************** define  interface ********************************/
//--------------------------------------------------------------------------
//
// 函数名称：Init_Plugin		
//
// 描述：初始化服务名称，调试日志对象	
//
// 输入参数：资源名	
//
// 输出参数：无
//
// 返回值：int：返回码，具体含义参见AsiEsmIpcCommonDefine.h
//
// 修改记录：
//
// 其它：				
//--------------------------------------------------------------------------
ASIESMIPCSERVERPLUGINDLL_API int Init_Plugin(_IN const char* pszName);

//--------------------------------------------------------------------------
//
// 函数名称：Register_CallBack_Fun
//
// 描述：注册命令处理函数		
//
// 输入参数：1.命令类型；2.命令处理函数	
//
// 输出参数：无
//
// 返回值：int：返回码，具体含义参见AsiEsmIpcCommonDefine.h
//
// 修改记录：
//
// 其它：				
//--------------------------------------------------------------------------
ASIESMIPCSERVERPLUGINDLL_API int Register_CallBack_Fun(_IN int iType, 
                                                       _IN Cmd_Handler pCmdHandler);

//--------------------------------------------------------------------------
//
// 函数名称：Start_Listen_Service		
//
// 描述：启动监听服务		
//
// 输入参数：无	
//
// 输出参数：无
//
// 返回值：int：返回码，具体含义参见AsiEsmIpcCommonDefine.h
//
// 修改记录：
//
// 其它：				
//--------------------------------------------------------------------------
ASIESMIPCSERVERPLUGINDLL_API int Start_Listen_Service(void);

/// <summary>
/// 停止监听服务
/// </summary>
/// <returns></returns>
ASIESMIPCSERVERPLUGINDLL_API int Stop_Listen_Service(void);


#ifdef __cplusplus
}
#endif
#endif