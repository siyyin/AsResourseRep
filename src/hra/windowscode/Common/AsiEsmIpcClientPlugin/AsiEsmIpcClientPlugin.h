//--------------------------------------------------------------------------
// (C) Copyright (C) 2021 亚信科技（成都）有限公司
// All Rights Reserved.
//
// 文件名称 :	AsiEsmIpcClientPlugin.h
// 
// 描述：声明IPC Client组件的导出接口
//
// 作者:	songhy3
//
// 时间 :	2021.08.06
//
// 修改记录
//
#ifndef ASIESMIPCCLIENTPLUGIN_H
#define ASIESMIPCCLIENTPLUGIN_H

#ifdef __cplusplus
	extern "C" {
#endif

#define ASIESMIPCCLIENTPLUGINDLL_API
#define _IN
#define _OUT

// 导出接口类型定义
#ifndef CONNECTTO_SERVER_DEFINE
#define CONNECTTO_SERVER_DEFINE
typedef int (*PSENDCMDDATA)(
			_IN const char* module,
			_IN int iType, 
			_IN const char* params,
			_IN unsigned int paramsLen,
			_OUT char* pOutBuf,
			_IN unsigned int iOutBufLen);
#endif

//--------------------------------------------------------------------------
/******************************** define  interface ********************************/
//--------------------------------------------------------------------------
//
// 函数名称：SendMsg		
//
// 描述：给指定模块发送命令和参数信息		
//
// 输入参数：1.module：要发送给的对象模块
//          2.iType：命令类型，枚举类型
//          3.params：输入buffer
//          4.paramsLen：输入buffer长度
//          5.iOutBufLen：输出buffer长度
// 输出参数：pOutBuf：输出buffer
//
// 返回值：int：返回码，具体含义参见AsiEsmIpcCommonDefine.h
//
// 修改记录：
//
// 其它：			
//--------------------------------------------------------------------------
ASIESMIPCCLIENTPLUGINDLL_API int SendCmdData(
			_IN const char* module,
			_IN int iType, 
			_IN const char* params,
			_IN unsigned int paramsLen,
			_OUT char* pOutBuf,
			_IN unsigned int iOutBufLen);
#ifdef __cplusplus
}
#endif
#endif