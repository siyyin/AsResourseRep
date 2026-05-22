#pragma once
#include <Windows.h>

#ifdef HRA_IPC_INTERFACE_EXPORTS
#ifdef _WIN32
#define HRA_IPC_INTERFACE_API __declspec(dllexport)
#else
#define HRA_IPC_INTERFACE_API
#endif
#else
#ifdef _WIN32
#define HRA_IPC_INTERFACE_API __declspec(dllimport)
#else
#define HRA_IPC_INTERFACE_API extern
#endif
#endif

#ifdef __cplusplus
extern "C"
{
#endif

//hra IPC接口版本号
#define HRA_IPC_INTERFACE_VERSION 2

/// <summary>
/// 产品-->hra消息头
/// </summary>
struct ProMsgHead
{
    enum MsgType : __int32
    {
        NOTIFIER,       //扫描任务
        PATTERN_UPDATE, // pattern更新分流
        KB_DATA = 90001, //补丁数据
    };

    unsigned int nVersion;
    unsigned int nSeq;
    MsgType emMsgType;
    unsigned int nDataLen;
};

/// <summary>
/// 消息结构体
/// </summary>
struct ProMsgPacket
{
    ProMsgHead sHead; //消息头
    unsigned char* pData;      //消息体
};

/// <summary>
/// hra-->产品消息头
/// </summary>
struct HraMsgHead
{
    enum MsgType : __int32
    {
        REGISTER,       //注册消息
        FEED_BACK,      //解析回告
        FEATURE_RESULT, //执行结果
        KB_REQ = 90001, //补丁数据请求
    };

    unsigned int nVersion;
    unsigned int nSeq;
    MsgType emMsgType;
    unsigned int nDataLen;
};

/// <summary>
/// 消息结构体
/// </summary>
struct HraMsgPacket
{
    HraMsgHead sHead; //消息头
    unsigned char* pData;      //消息体
};

#ifdef __cplusplus
}
#endif