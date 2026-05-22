/*****************************************************************
* Copyright (C) 2021 Asia info security Technology Co.,Ltd.*
******************************************************************
* HraReport.h
*
* DESCRIPTION:
*     
* AUTHOR:
*     qinyong
* CREATED DATE:
*     2021-8-15
* REVISION:
*     1.0
*
* MODIFICATION HISTORY
* --------------------
* $Log:$
*
*****************************************************************/
//#include <unistd.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <fcntl.h>
//#include <errno.h>
#include <time.h>
#include "HraReport.h"
//#include "HraUnixSocket.h"
//#include "HraMain.h"
#include "HraJson.h"
#include "Logger.h"
//#include "ConfigSave.h"
#include "HraUtils.h"
//#include "HraCmdPkg.h"
//#include "HRARpcClientManager/HRARpcClientManager.h"
#include "HraIpcInterface/HraIpcClient.h"

CReportInfo::CReportInfo() 
{
    m_ucCompress = NO_COMPRESSION;
}

CReportInfo::~CReportInfo() 
{
}

void CReportInfo::SetCompress(enum CompressionMode enCompressionMode)
{
    m_ucCompress = enCompressionMode;
}

int CReportInfo::SetPkgHdr(unsigned char* pucData, unsigned int ulDataLen, const HraMsgHead::MsgType& emMsgType)
{
    HraMsgHead* pstHraEvtRqHdr = NULL;

    if (!pucData || ulDataLen < sizeof(HraMsgHead))
    {
        LOG_ERROR("Set unix socket header parameters err.");
        return HRA_BAD_PARAM;
    }

    srand((unsigned int)(time(NULL)));
    unsigned int ulSeq = rand()%100;

    memset(pucData, 0, ulDataLen);
    pstHraEvtRqHdr            = (HraMsgHead*)pucData;
    pstHraEvtRqHdr->nVersion  = HRA_IPC_INTERFACE_VERSION;
    pstHraEvtRqHdr->nSeq      = ulSeq;
    pstHraEvtRqHdr->emMsgType = emMsgType;
    pstHraEvtRqHdr->nDataLen  = ulDataLen - sizeof(HraMsgHead);

    LOG_INFO("Set unix socket header parameters finish.");

    return HRA_OK;
}

void CReportInfo::ShowRspHdr()
{
}

/*****************************************************************
* DESCRIPTION: Request
*     上报结果
* INPUTS:
*     ucMsgType         : msg 类型
*     ucMsgCompression  : context 压缩标记
*     pscContent        ：context数据
*     ulContentLen      ：ulContentLen数据长度
* OUTPUTS:
*     无
* RETURNS:
*     0 : 成功
*     other : 参数错误
* CAUTIONS:
* 发送数据情况
* {
*   "msg_type": 0/1/2/3/4/5,
*   "msg_size": 89,
*   "msg_compression": 0/1,
*   "msg_content": "xxxxxx"
*  }
*  {  // msg_type = 0
*   "client_info": {
*       "device_id": "09C6D6BF02D64A1CB3C8",
*       "time_stamp": "xxxxxxxx",
*       "system_info": "xxxxx",
*       "program_version":"1.0",
*       "appscan_pattern_version": "1000.01",
*       "sysscan_pattern_version": "1000.01",
*       "baseline_pattern_version": "1000.01"
*   },
*  }
*  { // msg_type = 1/2/3/4
*   "result": { 
*        "device_id": "09C6D6BF02D64A1CB3C8",
*        "time_stamp": "xxxxxxxx",
*        "task_id": "1234567890", 
*        "error_code": 0,
*        "error_info": "succeeded",
*        "result_info"："xxxxxxxxxxxxxxxxxxxxxxxxxxx"
*    }
*  }
*****************************************************************/
int CReportInfo::Request(const HraMsgHead::MsgType& emMsgType, unsigned char ucMsgType, const char* pscContent,
                         unsigned int ulContentLen)
{
    int lRet = HRA_OK;
    unsigned char* pucReportData = nullptr;
    char outBuf[1024];
    memset(outBuf, 0, sizeof(outBuf));
    std::string strReportJsonBody;
    std::string strProIpcName = UtilsGetProIpcName();
    if (strProIpcName.empty())
    {
        LOG_ERROR("UtilsGetProIpcName error!");
        lRet = HRA_FAILED;
        goto _err;
    }

    /* 1. 获取上报json body信息 */
    strReportJsonBody = GetReportJsonBody(ucMsgType, pscContent, ulContentLen, m_ucCompress);
    if ("" == strReportJsonBody)
    {
        LOG_ERROR("Get report json body is null.");
        lRet = HRA_FAILED;
        goto _err;
    }

    /* 2. 封装unix socket head */
    LOG_DEBUG("strReportJsonBody len %u, msg %s", (unsigned int)(strReportJsonBody.length()), strReportJsonBody.c_str());
    unsigned int ulReportLen = (unsigned int)sizeof(HraMsgHead) + (unsigned int)strReportJsonBody.length();
    pucReportData = (unsigned char*)malloc(ulReportLen + 1);
    if (!pucReportData)
    {
        LOG_ERROR("Malloc report result data fail.");
        lRet = HRA_MALLOC_FAIL;
        goto _err;
    }
    memset(pucReportData, 0, ulReportLen + 1);

    lRet = SetPkgHdr(pucReportData, ulReportLen, emMsgType);
    if (HRA_OK != lRet)
    {
        LOG_ERROR("Set unix socket header failed.");
        lRet = HRA_FAILED;
        goto _err;
    }

    memcpy(pucReportData + sizeof(HraMsgHead), strReportJsonBody.c_str(), strReportJsonBody.length());

    /* 3. 调用数据发送接口 */
    //int iRet = HRARpcClientManager::Instance().SendHRAMsgData(iRpcCmdType, (const char*)pucReportData, ulReportLen,
    //                                                          outBuf, sizeof(outBuf));
    lRet = HraIpcSendMsg(strProIpcName.c_str(), HRA_CMD_HANDLE, (unsigned char*)pucReportData, ulReportLen,
                         (unsigned char*)outBuf, sizeof(outBuf) - 1);
    if (lRet != 0)
    {
        LOG_ERROR("Send report result data fail. name:%s, error(%d)", strProIpcName.c_str(), lRet);
        lRet = HRA_FAILED;
        goto _err;
    }

    LOG_INFO("Send data to dsa ok. name:%s. MsgType:%d, Send data len %u", strProIpcName.c_str(), (int)ucMsgType,
             ulReportLen);

_err:
    if (pucReportData != nullptr)
    {
        free(pucReportData);
        pucReportData = nullptr;
    }

    return lRet;
}

/// <summary>
/// 请求KB数据
/// </summary>
/// <param name="nSeq"></param>
/// <returns></returns>
int CReportInfo::KbRequest(unsigned long long nSeq)
{
    int lRet                     = HRA_OK;
    unsigned char* pucReportData = nullptr;
    char outBuf[1024];
    memset(outBuf, 0, sizeof(outBuf));
    char szMsgTmp[1024];
    memset(szMsgTmp, 0, sizeof(szMsgTmp));

    std::string strReportJsonBody;
    std::string strProIpcName = UtilsGetProIpcName();
    if (strProIpcName.empty())
    {
        LOG_ERROR("UtilsGetProIpcName error!");
        lRet = HRA_FAILED;
        goto _err;
    }

    /* 1. 获取上报json body信息 */
    _snprintf_s(szMsgTmp, sizeof(szMsgTmp), "{\"command_seq\":%llu}", nSeq);
    strReportJsonBody = szMsgTmp;

    /* 2. 封装unix socket head */
    LOG_DEBUG("strReportJsonBody len %u, msg %s", (unsigned int)(strReportJsonBody.length()), strReportJsonBody.c_str());
    unsigned int ulReportLen = (unsigned int)sizeof(HraMsgHead) + (unsigned int)strReportJsonBody.length();
    pucReportData            = (unsigned char*)malloc(ulReportLen + 1);
    if (!pucReportData)
    {
        LOG_ERROR("Malloc report result data fail.");
        lRet = HRA_MALLOC_FAIL;
        goto _err;
    }
    memset(pucReportData, 0, ulReportLen + 1);

    lRet = SetPkgHdr(pucReportData, ulReportLen, HraMsgHead::MsgType::KB_REQ);
    if (HRA_OK != lRet)
    {
        LOG_ERROR("Set unix socket header failed.");
        lRet = HRA_FAILED;
        goto _err;
    }

    memcpy(pucReportData + sizeof(HraMsgHead), strReportJsonBody.c_str(), strReportJsonBody.length());

    /* 3. 调用数据发送接口 */
    // int iRet = HRARpcClientManager::Instance().SendHRAMsgData(iRpcCmdType, (const char*)pucReportData, ulReportLen,
    //                                                           outBuf, sizeof(outBuf));
    lRet = HraIpcSendMsg(strProIpcName.c_str(), HRA_CMD_HANDLE, (unsigned char*)pucReportData, ulReportLen,
                         (unsigned char*)outBuf, sizeof(outBuf) - 1);
    if (lRet != 0)
    {
        LOG_ERROR("Send report result data fail. name:%s, error(%d)", strProIpcName.c_str(), lRet);
        lRet = HRA_FAILED;
        goto _err;
    }

    LOG_INFO("Send data to pro agent ok. name:%s. MsgType:%d, Send data len %u", strProIpcName.c_str(),
             (int)HraMsgHead::MsgType::KB_REQ, ulReportLen);

_err:
    if (pucReportData != nullptr)
    {
        free(pucReportData);
        pucReportData = nullptr;
    }

    return lRet;
}