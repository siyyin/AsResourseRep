// HraRpcCommModule.cpp : Defines the exported functions for the DLL application.
//

#include "pch.h"
#include "HraRpcCommModule.h"
#include "json/json.h"
//#include "utility/HraCmdPkg.h"
#include "utility/Logger.h"
#include "utility/HraReport.h"
#include "utility/HraJson.h"
#include "utility/HraUtils.h"
#include "utility/HraKbDataMgr.h"
#include "utility/HraTaskType.h"
//#include "HRARpcServerManager/HRARpcServerManager.h"
#include "HRAModuleInterface/HRAModuleInterface.h"
#include "PatternUpdate/HraPatternUpdate.h"
#include "HraIpcInterface/HraIpcServer.h"

#include "utility/HraAssetDef.h"
#include "AssetScan/AssetScan.h"

/// <summary>
/// 在指令中添加hra的信息
/// </summary>
/// <param name="arrayCmdObj"></param>
/// <returns></returns>
void CmdJsonAddPreTaskSeq(Json::Value& jsCmdObj, uint64_t nPreTaskSeq)
{
    jsCmdObj["pre_task_seq"] = nPreTaskSeq;
}

/// <summary>
/// 添加资产任务
/// </summary>
/// <returns></returns>
uint64_t AddPreAssetTask()
{
    //依赖资产
    Json::Value jsCmdJson;
    jsCmdJson["task_id"] = ASSETS_VULN_DEPENDENT_TASK;
    uint64_t nAssetTaskSeq = AssetScanAddTask(jsCmdJson);
    LOG_INFO("Add pre asset task, task_seq:%llu, task_id:%s", nAssetTaskSeq, ASSETS_VULN_DEPENDENT_TASK);
    return nAssetTaskSeq;
}

int hraHandleCommandData(Json::Value arrayCmdObj, uint64_t nPreTaskSeq)
{
    struct HraModuleElmtFunMap *pstHraModuleElmtFunMap = NULL;

    if (!(arrayCmdObj.isMember("command_type") && arrayCmdObj.isMember("command_data")))
    {
        LOG_ERROR("There is command_type or command_data in json data.");
        return HRA_BAD_PARAM;
    }

    pstHraModuleElmtFunMap = FindElmtHandler(arrayCmdObj["command_type"].asInt());
    if (!pstHraModuleElmtFunMap)
    {
        LOG_ERROR("This command(%d) does not support.", arrayCmdObj["command_type"].asInt());
        return HRA_NOT_SUPPORTED;
    }
    if (pstHraModuleElmtFunMap->handle)
    {
        Json::Value jsCmdObj = arrayCmdObj["command_data"];
        //如果有前置任务，添加额外信息
        if (nPreTaskSeq > 0)
        {
            CmdJsonAddPreTaskSeq(jsCmdObj, nPreTaskSeq);
        }
        return pstHraModuleElmtFunMap->handle(jsCmdObj);
    }
    else
    {
        LOG_WARN("This command(%d) does not handle functions.", arrayCmdObj["command_type"].asInt());
        return HRA_NOT_FOUND;
    }
}

std::string hraHandleJsonData(char *pscJsonData, unsigned int ulJsonDataLen)
{
    Json::Reader reader;
    Json::Value jsRoot;
    Json::Value jsItemObj;
    Json::Value jsBodyObj;
    Json::Value jsResultArrayObj;
    uint64_t nAssetTaskSeq = 0;

    if (pscJsonData == NULL)
    {
        LOG_ERROR("Json data is null.\n");
        return "";
    }

    LOG_INFO(">>>>>>>>>>>>>request:\n%s", pscJsonData);
    jsRoot = StringToJson(pscJsonData, ulJsonDataLen);
    if ((jsRoot.isMember("cmd_data")) && (jsRoot["cmd_data"].isArray()))
    {
        const Json::Value jsArrayObj = jsRoot["cmd_data"];
        for (int i = 0; i < jsArrayObj.size(); i++)
        {
            Json::Value jsCmdObj = jsArrayObj[i];
            if (jsCmdObj.isMember("command_type") && jsCmdObj.isMember("command_data"))
            {
                int nCmdType = jsCmdObj["command_type"].asInt();
                LOG_INFO("Handle command_type:%d", nCmdType);

                int nPreTaskSeq = 0;
                //应用漏扫和POC依赖资产，资产先扫描
                //同时有6003和6009时，只添加一次资产扫描
                // 管理端现在系统漏扫也依赖, 管理端使用资产进行计算
                if (nCmdType == HRA_ELMT_APP_SCAN_CFG || nCmdType == HRA_ELMT_VULN_POC_CFG ||
                    nCmdType == HRA_ELMT_OS_SCAN_CFG)
                {
                    if (nAssetTaskSeq <= 0)
                    {
                        nAssetTaskSeq = AddPreAssetTask();
                    }
                    nPreTaskSeq = nAssetTaskSeq;
                }

                //处理正常任务
                int lHandleCommandRet = HRA_FAILED;
                lHandleCommandRet     = hraHandleCommandData(jsCmdObj, nPreTaskSeq);
                // 记录处理数据
                jsItemObj["command_type"] = jsCmdObj["command_type"];
                jsItemObj["error_code"] = lHandleCommandRet;
                jsItemObj["error_info"] = (lHandleCommandRet==HRA_OK) ? "succeeded" : "command parse failed";
                if (jsCmdObj["command_data"].isMember("task_id") && jsCmdObj["command_data"]["task_id"].isString())
                {
                    jsItemObj["other_info"]["task_id"] = jsCmdObj["command_data"]["task_id"];
                }
                else
                {
                    jsItemObj["other_info"]["task_id"] = "";
                }
                jsResultArrayObj.append(jsItemObj);
            }
            else
            {
                // 本地记录异常
                LOG_ERROR("There is not command_type Json data.");
            }
        }

        /* json header */
        jsBodyObj.clear();
        jsBodyObj["device_id"] = UtilsGetUUID();
        jsBodyObj["time_stamp"] = UtilsGetRunTime();
        jsBodyObj["results"] = jsResultArrayObj;
    }
    else
    {
        // 记录异常
        LOG_ERROR("There is no cmd_data array object in Json data.");
    }
    LOG_INFO("feedback>>>>>>>>>>>>:\n%s", jsBodyObj.toStyledString().c_str());

    return JsonToString(jsBodyObj);
}

/// <summary>
/// 接收补丁数据
/// </summary>
/// <param name="pscJsonData"></param>
/// <param name="ulJsonDataLen"></param>
/// <returns></returns>
std::string hraHandleKbData(char* pscJsonData, unsigned int ulJsonDataLen)
{
    Json::Reader reader;
    Json::Value jsRoot;
    Json::Value jsItemObj;
    Json::Value jsBodyObj;
    Json::Value jsResultArrayObj;

    if (pscJsonData == NULL)
    {
        LOG_ERROR("Json data is null.\n");
        return "";
    }

    LOG_INFO(">>>>>>>>>>>>>request:\n%s", pscJsonData);
    jsRoot = StringToJson(pscJsonData, ulJsonDataLen);
    if (jsRoot.isMember("command_seq") && jsRoot["command_seq"].isInt64())
    {
        HraKbDataMgr::KbData data;
        data.nSeq = (unsigned long long)jsRoot["command_seq"].asInt64();
        data.strData = pscJsonData;
        HraKbDataMgr::getInstance().clear();
        bool bRet = HraKbDataMgr::getInstance().pushData(data);
        if (!bRet)
        {
            LOG_ERROR("Push KB data error! seq:%llu", data.nSeq);
            return "";
        }
        LOG_INFO("Push KB data succeed! seq:%llu", data.nSeq);
    }

    return "";
}

int HraPacketDispatch(ProMsgPacket* pstHraPacket)
{
    int lRet = HRA_OK;
    int lDataLen = 0;
    char *pscData = NULL;

    std::string strHandleJsonResult;
    ProMsgHead* pstPkt = NULL;

    LOG_INFO("Start dispatch data pkg.");
    if (!pstHraPacket)
    {
        LOG_ERROR("Hra packet point is null.");
        lRet = HRA_BAD_PARAM;
        goto _out;
    }

    pstPkt   = &(pstHraPacket->sHead);
    pscData  = (char*)pstHraPacket->pData;
    lDataLen = pstPkt->nDataLen;
    LOG_INFO("Handle packet: version=%u, seq=%u, emMsgType=%d, data len=%u.",
        pstPkt->nVersion, pstPkt->nSeq, pstPkt->emMsgType, pstPkt->nDataLen);

    /* 数据处理 */
    switch (pstPkt->emMsgType)
    {
    case ProMsgHead::NOTIFIER:
        LOG_INFO("Handle Type: %d(len %d).", pstPkt->emMsgType, lDataLen);
        strHandleJsonResult = hraHandleJsonData(pscData, lDataLen);
        break;
    case ProMsgHead::PATTERN_UPDATE:
        LOG_INFO("Handle Type: %d(len %d).", pstPkt->emMsgType, lDataLen);
        strHandleJsonResult = PatternUpdateHandleJsonData(pscData, lDataLen);
        break;
    case ProMsgHead::KB_DATA:
        LOG_INFO("Handle Type: %d(len %d).", pstPkt->emMsgType, lDataLen);
        strHandleJsonResult = hraHandleKbData(pscData, lDataLen);
        break;
    default :
        LOG_ERROR("Unsupported type: %d.", pstPkt->emMsgType);
        lRet = HRA_NOT_SUPPORTED;
        break;
    }

_out:
    LOG_INFO("Dispatch data pkg end, ret[%d]", lRet);
    /* 结果回复 */
    if (pstPkt->emMsgType != ProMsgHead::KB_DATA)
    {
        CReportInfo cRspResult;
        cRspResult.Request(HraMsgHead::MsgType::FEED_BACK, CONFIG_RESULT, strHandleJsonResult.c_str(),
                           strHandleJsonResult.length());
    }
    return lRet;
}

int HraPacketDestory(ProMsgPacket** ppPacket)
{
    if (ppPacket == NULL || *ppPacket == NULL)
    {
        return HRA_OK;
    }

    if (*ppPacket != NULL)
    {
        size_t len = sizeof(ProMsgPacket) + (*ppPacket)->sHead.nDataLen;
        if ((*ppPacket)->pData != NULL)
        {
            free((*ppPacket)->pData);
            (*ppPacket)->pData = NULL;
        }

        free((*ppPacket));
        *ppPacket = NULL;
        LOG_INFO("Release HRA_PACKET buffer! Size(%u)",(unsigned int)len);
    }
    return HRA_OK;
}

int HraComandHandler(int iType, unsigned char *params, int paramsLen, unsigned char *pOutBuf, int iOutBufLen)
{
    if (iType != HRA_CMD_HANDLE)
    {
        LOG_ERROR("iType(%d) error!",iType);
        return HRA_BAD_PARAM;
    }

    if (paramsLen < sizeof(ProMsgHead))
    {
        LOG_ERROR("Param len(%d) error!",paramsLen);
        return HRA_BAD_PARAM;
    }

    ProMsgPacket* pPacket = (ProMsgPacket*)malloc(sizeof(ProMsgPacket));
    if (!pPacket)
    {
        LOG_ERROR("malloc error! size(%u)", sizeof(ProMsgPacket));
        return HRA_MALLOC_FAIL;
    }
    memset(pPacket, 0, sizeof(ProMsgPacket));

    //数据拷贝
    memcpy(&(pPacket->sHead), params, sizeof(ProMsgHead));
    if (pPacket->sHead.nDataLen <= 0 || paramsLen != (sizeof(ProMsgHead) + pPacket->sHead.nDataLen))
    {
        LOG_ERROR("Packeg length(%d) or data length(%u) error!", paramsLen, pPacket->sHead.nDataLen);
        HraPacketDestory(&pPacket);
        return HRA_BAD_PARAM;
    }
    pPacket->pData = (unsigned char*)malloc(pPacket->sHead.nDataLen + 1);
    memset(pPacket->pData, 0, pPacket->sHead.nDataLen + 1);
    memcpy(pPacket->pData, params + sizeof(ProMsgHead), pPacket->sHead.nDataLen);

    //分发命令
    int ret = HraPacketDispatch(pPacket);
    HraPacketDestory(&pPacket);

    LOG_INFO("HraComandHandler end! type:%d, len:%d", iType, paramsLen);
    return ret;
}

//监听DSA下发指令线程函数
int DsaCmd_StartThread(const char* pszHraIpcName)
{
    int iRet = HraIpcRegistCallbackFun(pszHraIpcName, HRA_CMD_HANDLE, HraComandHandler);
    if (0 != iRet)
    {
        LOG_ERROR("HraIpcRegistCallbackFun error! name:%s", pszHraIpcName);
        return HRA_FAILED;
    }

    iRet = HraIpcStartListenService();
    if (0 != iRet)
    {
        LOG_ERROR("HraIpcStartListenService error! name:%s", pszHraIpcName);
        return HRA_FAILED;
    }

    ////HRARpcServerManager rpcSrvMgr;
    //if (!g_rpcSrvMgr.InitAisRpcServer(HRA_CMD_HANDLE, RPC_HRA_SERVICE_NAME, (Cmd_Handler*)HraComandHandler))
    //{
    //    LOG_ERROR("Init RPC server error! type:%d, name:%s", HRA_CMD_HANDLE, RPC_HRA_SERVICE_NAME);
    //}
    //if (!g_rpcSrvMgr.StartServer())
    //{
    //    LOG_ERROR("Start RPC server error! type:%d, name:%s", HRA_CMD_HANDLE, RPC_HRA_SERVICE_NAME);
    //}
    LOG_INFO("Hra IPC server:%s started!", pszHraIpcName);
    return HRA_OK;
}