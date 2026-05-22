#ifndef ASIESMIPCCOMMONDEFINE_H
#define ASIESMIPCCOMMONDEFINE_H

#include <string.h>
#include <string>

#ifndef __Global
#define __Global

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	通信命令类型. </summary>
///
/// <remarks>	siyuan_yin, 2022/1/13. </remarks>
////////////////////////////////////////////////////////////////////////////////////////////////////

enum CMD_HRA_TYPE
{
	/// <summary>	通信模块回调的总命令. </summary>
	HRA_CMD_HANDLE			=	100,

	///// <summary>	DSA->HRA feature执行. </summary>
	//HRA_CMD_FEATURE			=	101,

	///// <summary>	DSA->HRA pattern更新. </summary>
	//HRA_CMD_UPDATE			=	102,

	///// <summary>	HRA->DSA feature执行结果. </summary>
	//HRA_CMD_FEATURE_RESULT	=	103,

	///// <summary>	HRA->DSA Agent注册. </summary>
	//HRA_CMD_REGISTER		=	104,

	///// <summary>	HRA->DSA 解析回告. </summary>
	//HRA_CMD_RESPONSE		=	105,

	///// <summary>	DSA->HRA 检查状态. </summary>
	//HRA_CMD_CHECKSTATUS		=	106,
};

#endif

#ifndef __RPC_Global
#define __RPC_Global

// 各模块RPC服务名称定义
//#define RPC_HRA_SERVICE_NAME "AsiDSIpcHRA"
//#define RPC_DSA_Plugin_SERVICE_NAME "AsiDSIpcDSAPlugin"


// 错误描述定义
#define SUCCESS "success."
#define PARAMETER_NULL "parameter is null."
#define CREATE_RPC_SERVICE_THREAD_ERROR "create rpc service thread error."
#define RPC_STOP_SERVER_LISTENING_ERROR "rpc stop server listening error."
#define RPC_SERVER_UNREGISTERIF_ERROR "rpc server unregister error."
#define RPC_SERVER_USE_PROTSEQEP_ERROR "call rpcServerUseProtseqEp return error."
#define RPC_SERVER_REGISTERIF_ERROR "rpc server register error."
#define RPC_SERVER_LISTEN_ERROR "start rpc server listen error."
#define CALL_REGISTERED_FUN_ERROR "call registered function error."
#define CALL_REGISTERED_FUN_ERROR "call registered function error."
#define RPC_STRING_BINDING_COMPOSE_ERROR "call RpcStringBindingCompose return error."
#define RPC_BINGDING_FROM_STRINGBINDING_ERROR "call RpcBindingFromStringBinding return error."
#define RPC_SEND_MSG_EXCEPTION "send msg exception."
#define RPC_STRING_FREE_ERROR "call RpcStringFree return error."
#define RPC_BINDING_FREE_ERROR "call RpcBindingFree return error."

// 命令来源
enum ENUM_CMD_REQ_SOURCE
{
	// 从UI客户端来的命令
	CMD_REQ_FROM_CLIENT = 1,
	// 从服务端来下发的命令
	CMD_REQ_FROM_SERVER,
};

// 错误码定义
enum ERROR_CODE
{
	RPC_ERROR_SUCCESS = 0,
	RPC_ERROR_PARAMETER_NULL = 1,
	RPC_ERROR_CREATE_RPC_SERVICE_THREAD_ERROR,
	RPC_ERROR_RPC_STOP_SERVER_LISTENING_ERROR,
	RPC_ERROR_RPC_SERVER_UNREGISTERIF_ERROR,
	RPC_ERROR_RPC_SERVER_USE_PROTSEQEP_ERROR,
	RPC_ERROR_RPC_SERVER_REGISTERIF_ERROR,
	RPC_ERROR_RPC_SERVER_LISTEN_ERROR,
	RPC_ERROR_CALL_REGISTERED_FUN_ERROR,
	RPC_ERROR_RPC_STRING_BINDING_COMPOSE_ERROR,
	RPC_ERROR_RPC_BINGDING_FROM_STRINGBINDING_ERROR,
	RPC_ERROR_RPC_SEND_MSG_EXCEPTION,
	RPC_ERROR_RPC_STRING_FREE_ERROR,
	RPC_ERROR_RPC_BINDING_FREE_ERROR,
	RPC_ERROR_RPC_NO_BINDINGS_ERROR,
	RPC_ERROR_RPC_EP_REGISTER_ERROR,
	RPC_ERROR_RPC_EP_UNREGISTER_ERROR,
	RPC_ERROR_RPC_MAX_VALUE
};

enum RPC_DATABASE_ERROR_CODE
{
	DATABASE_PARAM_ERROR = RPC_ERROR_RPC_MAX_VALUE,

	DATABASE_ALLOCATION_MEMORY_INSUFFICIENT,

	DATABASE_INTERNAL_FUNCTION_ERROR,

	DATABASE_NOT_SUPPORT_METHOD,

	DATABASE_INTERNAL_FUNCTION_ALLOCATION_MEMORY_INSUFFICIENT,

	DATABASE_ERROR_CODE_MAX_VALUE
};


enum RPC_API_ERROR_CODE
{
	API_PARAM_ERROR = DATABASE_ERROR_CODE_MAX_VALUE,
	API_EXECUTE_FAIL,
	API_ERROR_CODE_MAX_VALUE
};

enum UPDATE_CODE 
{
	UP_TO_DATE = API_ERROR_CODE_MAX_VALUE,   //是最新的
	START_UPDATE,      //开始更新
	NOT_DOWNLOAD,     //无法下载
	INTER_ERR,	      //内部错误
	UPDATE_FINISH,   //更新成功
	MAX_ERR_CODE,	//最大错误类型， 无实际意义
};

// 根据错误码获取错误描述函数定义
static std::string GetLogMsgByRtnCode(const int & iRtnCode)
{
	std::string sRtnMsg;
	switch (iRtnCode)
	{
	case RPC_ERROR_SUCCESS:    // 成功
		sRtnMsg = SUCCESS;
		break;
	case RPC_ERROR_PARAMETER_NULL:    // 参数错误
		sRtnMsg = PARAMETER_NULL;
		break;
	case RPC_ERROR_CREATE_RPC_SERVICE_THREAD_ERROR:    // 创建rpc服务线程失败
		sRtnMsg = CREATE_RPC_SERVICE_THREAD_ERROR;
		break;
	case RPC_ERROR_RPC_STOP_SERVER_LISTENING_ERROR:    // 停止rpc监听服务失败
		sRtnMsg = RPC_STOP_SERVER_LISTENING_ERROR;
		break;
	case RPC_ERROR_RPC_SERVER_UNREGISTERIF_ERROR:      // 注销rpc服务失败
		sRtnMsg = RPC_SERVER_UNREGISTERIF_ERROR;
		break;
	case RPC_ERROR_RPC_SERVER_USE_PROTSEQEP_ERROR:     // 定义RPC通信协议失败
		sRtnMsg = RPC_SERVER_USE_PROTSEQEP_ERROR;
		break;
	case RPC_ERROR_RPC_SERVER_REGISTERIF_ERROR:        // 注册RPC服务失败
		sRtnMsg = RPC_SERVER_REGISTERIF_ERROR;
		break;
	case RPC_ERROR_RPC_SERVER_LISTEN_ERROR:            // 启动RPC服务监听失败
		sRtnMsg = RPC_SERVER_LISTEN_ERROR;
		break;
	case RPC_ERROR_CALL_REGISTERED_FUN_ERROR:          // 调用命令注册函数失败
		sRtnMsg = CALL_REGISTERED_FUN_ERROR;
		break;
	case RPC_ERROR_RPC_STRING_BINDING_COMPOSE_ERROR:   // 创建字符串绑定句柄失败
		sRtnMsg = RPC_STRING_BINDING_COMPOSE_ERROR;
		break;
	case RPC_ERROR_RPC_BINGDING_FROM_STRINGBINDING_ERROR:   // 调用RpcBindingFromStringBinding失败
		sRtnMsg = RPC_BINGDING_FROM_STRINGBINDING_ERROR;
		break;
	case RPC_ERROR_RPC_SEND_MSG_EXCEPTION:             // 调用RPC接口异常
		sRtnMsg = RPC_SEND_MSG_EXCEPTION;
		break;
	case RPC_ERROR_RPC_STRING_FREE_ERROR:                    // 释放StringBinding失败
		sRtnMsg = RPC_STRING_FREE_ERROR;
		break;
	case RPC_ERROR_RPC_BINDING_FREE_ERROR:                   // 释放Binding失败
		sRtnMsg = RPC_BINDING_FREE_ERROR;
		break;
	default:
		break;
	}

	return sRtnMsg;
}
#endif
#endif