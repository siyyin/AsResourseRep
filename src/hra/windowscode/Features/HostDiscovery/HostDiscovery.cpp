// HostDiscovery.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "HostDiscovery.h"
#include "HostDiscoveryHelper.h"
#include "IpRangeParser.h"

#include <utility/Logger.h>
#include <utility/HraCtrlCmd.h>
#include <utility/HraJson.h>
#include <utility/HraUtils.h>

#include <stdio.h>

#include <set>

#include <Windows.h>

// input parameter
#define JSON_KEY_TO_BE_SCAN_IP_RANGE "scan_ip_range"
#define JSON_KEY_DISCOVERY_METHOD "scan_method"
#define JSON_KEY_NMAP_PARAMETER "nmap_parameters"
#define JSON_KEY_NMAP_OSSCAN "os_scan"
#define JSON_KEY_NMAP_AGENT_PORT "agent_port"
#define JSON_KEY_NMAP_PROTOCOLS "protocol"
#define JSON_KEY_NMAP_PORTS "ports"
#define JSON_KEY_SERVER_DOMAIN "server_domain"
#define JSON_KEY_SERVER_IP "server_ip"
#define JSON_KEY_SERVER_PORT "server_port"

// result key
#define JSON_KEY_DISCOVERY_HOST_INFO "discovery_host_info"
#define JSON_KEY_UNIQUE_CLIENT_KEY "unique_client_key"
#define JSON_KEY_ASSET_ADD_TYPE "add"
#define JSON_KEY_ASSET_DEL_TYPE "del"
#define JSON_KEY_ASSET_RESET "reset"
#define JSON_KEY_SCAN_IP_RANGE "scan_ip_range"

#define JSON_VALUE_ASSET_NEED_RESET 1
#define JSON_VALUE_ASSET_NOT_NEED_RESET 0

enum UniqueClientKey
{
    Mac = 0,
    IpAddr
};

class CHostDiscoveryWorkEntry
{
public:
    CHostDiscoveryWorkEntry()
        : iUniqueClientKey(-1)
        , iServerPort(-1)
    {
    }

public:
    std::string strTaskId; // task id
    int iUniqueClientKey;
    std::set<std::string> setToBeScanIpRange;
    std::set<HostDiscoveryMethod> setHostDiscoveryMethod;
    HostDiscoveryScanParam cScanParameter;
    std::string strServerDomain;
    int iServerPort;
};

//////////////////////////////////////////////////////////////////////

static void UploadFailedResult(const std::string& strTaskId, int iRet)
{
    std::string strScanResult;

    LOG_INFO("Get report result info start, size %d!", strScanResult.size());
    std::string strResultInfo = GetReportResultInfo(strTaskId.c_str(), iRet, strScanResult.c_str(), LOG_LEVEL_INFO);

    // upload scan result
    CReportInfo cReportAppInfo;
    cReportAppInfo.SetCompress(NEED_COMPRESSION);
    cReportAppInfo.Request(HraMsgHead::MsgType::FEATURE_RESULT, HOST_DISCOVERY_RESULT, strResultInfo.c_str(),
                           strResultInfo.size());
    cReportAppInfo.ShowRspHdr();
}

static void UploadSuccessResult(const std::string& strTaskId, const std::string& strData)
{
    LOG_DEBUG("IN UploadSuccessResult");

    std::string strResultInfo = GetReportResultInfo(strTaskId.c_str(), HRA_OK, strData.c_str(), LOG_LEVEL_INFO);

    CReportInfo cReportAssetInfo;
    cReportAssetInfo.SetCompress(NEED_COMPRESSION);
    cReportAssetInfo.Request(HraMsgHead::MsgType::FEATURE_RESULT, HOST_DISCOVERY_RESULT, strResultInfo.c_str(),
                             strResultInfo.size());
    cReportAssetInfo.ShowRspHdr();

    LOG_DEBUG("OUT UploadSuccessResult");
}

static void ConstructJsonResult(std::vector<HostDiscoveryResult>& vecHostDiscoveryResult, int iUniqueClientKey,
                                Json::Value& jsonResult, std::set<std::string> setToBeScanIpRange)
{
    LOG_DEBUG("IN ConstructJsonResult");

    jsonResult = Json::objectValue;

    Json::Value jsonDiscoveryHostInfo = Json::objectValue;

    // echo scan ip address space to hrm
    Json::Value jsonIpSpace = Json::arrayValue;
    for (auto iter = setToBeScanIpRange.begin(); iter != setToBeScanIpRange.end(); ++iter)
    {
        jsonIpSpace.append(*iter);
    }
    jsonDiscoveryHostInfo[JSON_KEY_SCAN_IP_RANGE] = jsonIpSpace;

    // unique client key
    jsonDiscoveryHostInfo[JSON_KEY_UNIQUE_CLIENT_KEY] = iUniqueClientKey;

    // need add result
    Json::Value jsonAddResult = Json::arrayValue;

    // remove duplicat result firstly
    std::set<CHostDiscoveryInfo> setHostDiscoveryInfo;
    for (auto iter = vecHostDiscoveryResult.begin(); iter != vecHostDiscoveryResult.end(); ++iter)
    {
        HostDiscoveryResult& hostDiscoveryResult = *iter;

        for (auto iterResult = hostDiscoveryResult.begin(); iterResult != hostDiscoveryResult.end(); ++iterResult)
        {
            CHostDiscoveryInfo hostDiscoveryInfo = *iterResult;

            setHostDiscoveryInfo.insert(hostDiscoveryInfo);
        }
    }

    // convert to json array
    for (auto iter = setHostDiscoveryInfo.begin(); iter != setHostDiscoveryInfo.end(); ++iter)
    {
        CHostDiscoveryInfo hostDiscoveryInfo = *iter;

        Json::Value jsonVal;
        hostDiscoveryInfo.ToJson(jsonVal);

        jsonAddResult.append(jsonVal);
    }

    jsonDiscoveryHostInfo[JSON_KEY_ASSET_ADD_TYPE] = jsonAddResult;

    // need delete result
    jsonDiscoveryHostInfo[JSON_KEY_ASSET_DEL_TYPE] = Json::arrayValue;

    // need reset
    jsonDiscoveryHostInfo[JSON_KEY_ASSET_RESET] = JSON_VALUE_ASSET_NEED_RESET;

    // discovery_host_info
    jsonResult[JSON_KEY_DISCOVERY_HOST_INFO] = jsonDiscoveryHostInfo;

    LOG_DEBUG("OUT ConstructJsonResult");
}

static bool VerifyHostDiscoveryJson(const std::string& strJson)
{
    Json::Value jsonVal = StringToJson(strJson.c_str(), strJson.length());

    if (!jsonVal.isMember("task_id") || !jsonVal["task_id"].isString())
    {
        LOG_WARN("task_id not found!");
        return false;
    }

    // check unique_client_key
    if (!jsonVal.isMember(JSON_KEY_UNIQUE_CLIENT_KEY) || !jsonVal[JSON_KEY_UNIQUE_CLIENT_KEY].isInt())
    {
        LOG_WARN("can not find unique client key!");
        return false;
    }

    // check scan_method key is exist
    if (!jsonVal.isMember(JSON_KEY_DISCOVERY_METHOD) || !jsonVal[JSON_KEY_DISCOVERY_METHOD].isArray())
    {
        LOG_WARN("can not find discovery method!");
        return false;
    }

    // check scan_method array is empty
    Json::Value jsonDiscoveryMethod = jsonVal[JSON_KEY_DISCOVERY_METHOD];
    if (jsonDiscoveryMethod.empty())
    {
        LOG_WARN("discovery method list is empty!");
        return false;
    }

    // check to_be_scan_ip_range is exist
    // scan scanner's network ip range if to_be_scan_ip_range array is empty
    if (!jsonVal.isMember(JSON_KEY_TO_BE_SCAN_IP_RANGE) || !jsonVal[JSON_KEY_TO_BE_SCAN_IP_RANGE].isArray())
    {
        LOG_WARN("to be scan ip range not found!");
        return false;
    }


    // check server_domain and server_ip
    bool bContainsServerDomain = false;

    if (jsonVal.isMember(JSON_KEY_SERVER_DOMAIN) && jsonVal[JSON_KEY_SERVER_DOMAIN].isString())
    {
        std::string strServerDomain = jsonVal[JSON_KEY_SERVER_DOMAIN].asString();

        if (!strServerDomain.empty())
        {
            bContainsServerDomain = true;
        }
    }

    bool bContainsServerIp = false;

    if (jsonVal.isMember(JSON_KEY_SERVER_IP) && jsonVal[JSON_KEY_SERVER_IP].isString())
    {
        std::string strServerIP = jsonVal[JSON_KEY_SERVER_IP].asString();

        if (!strServerIP.empty())
        {
            bContainsServerIp = true;
        }
    }

    // neither server domain nor server ip not exists
    if (!bContainsServerDomain && !bContainsServerIp)
    {
        LOG_WARN("lack server domain name or server ip");
        return false;
    }

    // check server_port
    if (!jsonVal.isMember(JSON_KEY_SERVER_PORT) || !jsonVal[JSON_KEY_SERVER_PORT].isInt())
    {
        LOG_WARN("lack server port!");
        return false;
    }
    
    // check nmap parameter
    if (jsonVal.isMember(JSON_KEY_NMAP_PARAMETER) && jsonVal[JSON_KEY_NMAP_PARAMETER].isArray() &&
        jsonVal[JSON_KEY_NMAP_PARAMETER].size() > 0)
    {
        unsigned int iNmapParameters     = jsonVal[JSON_KEY_NMAP_PARAMETER].size();
        Json::Value& jsonNmapParameters  = jsonVal[JSON_KEY_NMAP_PARAMETER];

        for (int i = 0; i < iNmapParameters; ++i)
        {
            Json::Value& curJsonNmapVal = jsonNmapParameters[i];

            if (!curJsonNmapVal.isMember(JSON_KEY_NMAP_PROTOCOLS) || !curJsonNmapVal[JSON_KEY_NMAP_PROTOCOLS].isInt())
            {
                LOG_WARN("invalid nmap scan protcol!");
                return false;
            }
            if (!curJsonNmapVal.isMember(JSON_KEY_NMAP_PORTS) || !curJsonNmapVal[JSON_KEY_NMAP_PORTS].isArray())
            {
                LOG_WARN("invalid nmap scan ports!");
                return false;
            }
        }
    }

    return true;
}

static bool ParseHostDiscoveryJson(const std::string& strJson, CHostDiscoveryWorkEntry& workEntry)
{
    LOG_DEBUG("%s", strJson.c_str());

    if (!VerifyHostDiscoveryJson(strJson))
    {
        LOG_WARN("incorrect host discovery json format.");
        return false;
    }

    Json::Value jsonVal = StringToJson(strJson.c_str(), strJson.length());


    // get task_id
    std::string strTaskId = jsonVal["task_id"].asString();

    workEntry.strTaskId = strTaskId;

    // get unique_client_key
    workEntry.iUniqueClientKey = jsonVal[JSON_KEY_UNIQUE_CLIENT_KEY].asInt();

    // get scan_ip_range
    unsigned int iTobeScanIpRangeSize = jsonVal[JSON_KEY_TO_BE_SCAN_IP_RANGE].size();

    Json::Value& jsonToBeScanIpRange = jsonVal[JSON_KEY_TO_BE_SCAN_IP_RANGE];

    for (int i = 0; i < iTobeScanIpRangeSize; ++i)
    {
        Json::Value& curlJsonVal = jsonToBeScanIpRange[i];

        if (curlJsonVal.isString())
        {
            workEntry.setToBeScanIpRange.insert(curlJsonVal.asString());
        }
    }

    // get scan_method 
    unsigned int iDiscoveryMethod    = jsonVal[JSON_KEY_DISCOVERY_METHOD].size();
    Json::Value& jsonDiscoveryMethod = jsonVal[JSON_KEY_DISCOVERY_METHOD];

    for (int i = 0; i < iDiscoveryMethod; ++i)
    {
        Json::Value& curJsonVal = jsonDiscoveryMethod[i];

        if (curJsonVal.isInt())
        {
            HostDiscoveryMethod eHostDiscoveryMethod = static_cast<HostDiscoveryMethod>(curJsonVal.asInt());
            workEntry.setHostDiscoveryMethod.insert(eHostDiscoveryMethod);
            if (eHostDiscoveryMethod == Nmap && jsonVal.isMember(JSON_KEY_NMAP_PARAMETER) && jsonVal[JSON_KEY_NMAP_PARAMETER].size() > 0)
            {
                unsigned int iNmapParameters    = jsonVal[JSON_KEY_NMAP_PARAMETER].size();
                Json::Value& jsonNmapParameters = jsonVal[JSON_KEY_NMAP_PARAMETER];

                for (int i = 0; i < iNmapParameters; ++i)
                {
                    Json::Value& curJsonNmapVal = jsonNmapParameters[i];
                    HostDiscoveryScanProtocol eNmapProtocol =
                        static_cast<HostDiscoveryScanProtocol>(curJsonNmapVal[JSON_KEY_NMAP_PROTOCOLS].asInt());

                    std::vector<std::string> vecPort;
                    unsigned int iCurPorts    = curJsonNmapVal[JSON_KEY_NMAP_PORTS].size();
                    Json::Value& jsonCurPorts = curJsonNmapVal[JSON_KEY_NMAP_PORTS];
                    for (int j = 0; j < iCurPorts; j++)
                    {
                        Json::Value& curPortItem = jsonCurPorts[j];
                        vecPort.push_back(curPortItem.asString());
                    }

                    HostDiscoveryScanParamItem scanParamItem;
                    scanParamItem.eProtocol    = eNmapProtocol;
                    scanParamItem.vecPorts  = vecPort;
                    workEntry.cScanParameter.vecScanItem.push_back(scanParamItem);
                }
                if (jsonVal.isMember(JSON_KEY_NMAP_OSSCAN) && jsonVal[JSON_KEY_NMAP_OSSCAN].isBool() &&
                    jsonVal[JSON_KEY_NMAP_OSSCAN].asBool())
                {
                    workEntry.cScanParameter.bDeepScan = true;
                }
                
                
                if (jsonVal.isMember(JSON_KEY_NMAP_AGENT_PORT) && jsonVal[JSON_KEY_NMAP_AGENT_PORT].size() > 0)
                {
                    unsigned int iNmapAgentPorts    = jsonVal[JSON_KEY_NMAP_AGENT_PORT].size();
                    Json::Value& jsonNmapAgentPorts = jsonVal[JSON_KEY_NMAP_AGENT_PORT];

                    for (int i = 0; i < iNmapAgentPorts; ++i)
                    {
                        Json::Value& curJsonAgentPortVal = jsonNmapAgentPorts[i];

                        if (curJsonAgentPortVal.isInt())
                        {
                            workEntry.cScanParameter.vecAgentPorts.push_back(curJsonAgentPortVal.asInt());
                        }
                    }
                }
            }
        }
    }
    
    // get server_domain and server_ip
    bool bContainsServerDomain = false;

    if (jsonVal.isMember(JSON_KEY_SERVER_DOMAIN) && jsonVal[JSON_KEY_SERVER_DOMAIN].isString())
    {
        bContainsServerDomain = true;
    }

    bool bContainsServerIp = false;

    if (jsonVal.isMember(JSON_KEY_SERVER_IP) && jsonVal[JSON_KEY_SERVER_IP].isString())
    {
        bContainsServerIp = true;
    }

    // use server ip preferentially
    if (bContainsServerIp)
    {
        workEntry.strServerDomain = jsonVal[JSON_KEY_SERVER_IP].asString();
    }
    else if (bContainsServerDomain)
    {
        workEntry.strServerDomain = jsonVal[JSON_KEY_SERVER_DOMAIN].asString();
    }
    else
    {
        LOG_WARN("lack server domain name or server ip");
        return false;
    }

    workEntry.iServerPort = jsonVal[JSON_KEY_SERVER_PORT].asInt();

    return true;
}

/// <summary>
/// task worker function
/// </summary>
/// <param name="pArg"></param>
/// <returns></returns>
static void* HostDiscoveryWorker(void* pArg)
{
    int iRet = HRA_OK;

    if (pArg == NULL)
    {
        return NULL;
    }

    CHostDiscoveryWorkEntry hostDiscoveryWorkEntry;

    // start scan
    LOG_INFO("HostDiscovery scan(%d) start.", HRA_ELMT_HOST_DISCOVERY_CFG);

    char* pszJsonContent = reinterpret_cast<char*>(pArg);

    std::string strJsonContent = pszJsonContent;

    if (!ParseHostDiscoveryJson(strJsonContent, hostDiscoveryWorkEntry))
    {
        LOG_WARN("parse json failed...");
        return NULL;
    }

  

    std::string strTaskId                            = hostDiscoveryWorkEntry.strTaskId;
    std::set<HostDiscoveryMethod> setDiscoveryMethod = hostDiscoveryWorkEntry.setHostDiscoveryMethod;
    std::set<std::string> setToBeScanIpRange         = hostDiscoveryWorkEntry.setToBeScanIpRange;
    int iUniqueClientKey                             = hostDiscoveryWorkEntry.iUniqueClientKey;
    HostDiscoveryScanParam scanParameter         = hostDiscoveryWorkEntry.cScanParameter;
    std::string strServerDomain                      = hostDiscoveryWorkEntry.strServerDomain;
    int iServerPort                                  = hostDiscoveryWorkEntry.iServerPort;

    int iCtrlCmd = HraCtrlCmd::getInstance()->getCmd(::GetCurrentThreadId());
    if (iCtrlCmd == HraCtrlCmd::CmdDef::cmd_cancel)
    {
        iRet = HRA_Code::HRA_USER_CANCEL;

        UploadFailedResult(strTaskId, iRet);

        return NULL;
    }
    // get NIC which is communicate with server
    CNICInfoHelper nicInfoHelper;

    CNICNetInfo scannerNicInfo;
    iRet = nicInfoHelper.FindAcitveNICByIp(strServerDomain, iServerPort, scannerNicInfo);

    if (iRet != HRA_OK)
    {
        LOG_ERROR("find active nic by peer ip failed, retCode: %d", iRet);
        UploadFailedResult(strTaskId, iRet);

        return NULL;
    }

    // init hostDiscoveryHelper to Scan
    CHostDiscoveryHelper hostDiscoveryHelper(::GetCurrentThreadId());

    std::vector<HostDiscoveryResult> vecHostDiscoveryResult;
    // enum discovery method one by one
    for (auto& iterDiscoveryMethod = setDiscoveryMethod.begin(); iterDiscoveryMethod != setDiscoveryMethod.end();
         ++iterDiscoveryMethod)
    {
        HostDiscoveryMethod discoveryMethod = *iterDiscoveryMethod;

        HostDiscoveryResult hostDiscoveryResult;

        if (setToBeScanIpRange.empty()) // scan scanner's subnet if toBeScanIpRange is empty
        {
            HRA_Code curRetCode = hostDiscoveryHelper.DiscoveryHostInScannerSubnet(
                scannerNicInfo, discoveryMethod, hostDiscoveryResult, scanParameter);

            // termiate by user cancel
            if (curRetCode == HRA_USER_CANCEL)
            {
                LOG_WARN("discovery method: %d, canceled, retCode: %d", discoveryMethod, curRetCode);

                UploadFailedResult(strTaskId, curRetCode);

                return NULL;
            }

            // scan failed, continue next
            if (curRetCode != HRA_OK)
            {
                LOG_WARN("discovery method: %d, failed, retCode: %d", discoveryMethod, curRetCode);
                continue;
            }

            // scan success
            vecHostDiscoveryResult.push_back(hostDiscoveryResult);
        }
        else // scan every toBeScanIpRange
        {
            for (auto iterToBeScanIpRange = setToBeScanIpRange.begin(); iterToBeScanIpRange != setToBeScanIpRange.end();
                 ++iterToBeScanIpRange)
            {
                std::string strToBeScanIpRange = *iterToBeScanIpRange;

                HRA_Code curRetCode = hostDiscoveryHelper.DiscoveryHost(scannerNicInfo, strToBeScanIpRange, discoveryMethod, hostDiscoveryResult, scanParameter);

                // termiate by user cancel
                if (curRetCode == HRA_USER_CANCEL)
                {
                    LOG_WARN("discovery method: %d, canceled, retCode: %d", discoveryMethod, curRetCode);

                    UploadFailedResult(strTaskId, curRetCode);

                    return NULL;
                }

                // scan failed, continue next
                if (curRetCode != HRA_OK)
                {
                    LOG_WARN("discovery method: %d, failed, retCode: %d", discoveryMethod, curRetCode);
                    continue;
                }

                // scan success
                vecHostDiscoveryResult.push_back(hostDiscoveryResult);
            }
        }
    }

    Json::Value jsonResult = Json::objectValue;

    if (setToBeScanIpRange.empty())
    {
        std::string strScannerSubnetRangeCidrStyle;
        HRA_Code curRetCode =
            hostDiscoveryHelper.GetScannerSubnetRangeCidr(scannerNicInfo, strScannerSubnetRangeCidrStyle);
        if (HRA_OK == curRetCode)
        {
            setToBeScanIpRange.insert(strScannerSubnetRangeCidrStyle);
        }
    }

    ConstructJsonResult(vecHostDiscoveryResult, iUniqueClientKey, jsonResult, setToBeScanIpRange);

    LOG_DEBUG("result: %s", jsonResult.toStyledString().c_str());

    std::string strHostDiscoveryResult = JsonToString(jsonResult);

    // success, upload result
    UploadSuccessResult(strTaskId, strHostDiscoveryResult);

    return NULL;
}

int HRA_HOST_DISCOVERY_EXPORT HostDiscoveryInit(void)
{
    return HRA_OK;
}

int HRA_HOST_DISCOVERY_EXPORT HostDiscoveryDestroy(void)
{
    return HRA_OK;
}

int HRA_HOST_DISCOVERY_EXPORT HostDiscoveryCfgHandle(const Json::Value& jsContent)
{
    LOG_DEBUG("IN HostDiscoveryCfgHandle");

    // parse task id
    if (!jsContent.isMember("task_id") || !jsContent["task_id"].isString())
    {
        LOG_WARN("task_id not found!");
        return HRA_BAD_PARAM;
    }

    std::string strTaskId = jsContent["task_id"].asString();

    std::string strJsonContent = JsonToString(jsContent);

    if (!VerifyHostDiscoveryJson(strJsonContent))
    {
        return HRA_BAD_PARAM;
    }

    size_t size = strJsonContent.length() + 1;

    char* pszTemp = new (std::nothrow) char[size];

    if (pszTemp == NULL)
    {
        LOG_ERROR("alloc mem failed");
        return HRA_MALLOC_FAIL;
    }

    memset(pszTemp, 0, size * sizeof(char));

    strncpy_s(pszTemp, size, strJsonContent.c_str(), strJsonContent.length());

    LOG_DEBUG("%s", pszTemp);

    uint64_t nTaskSeq = HraTask_AddWorker(strTaskId.c_str(), HRA_ELMT_HOST_DISCOVERY_CFG, ProMsgHead::MsgType::NOTIFIER,
                                 HostDiscoveryWorker, pszTemp, size);

    // free memory
    delete[] pszTemp;
    pszTemp = NULL;

    LOG_INFO("Hra Task add HostDiscovery Worker end.");
    if (nTaskSeq <= 0)
    {
        LOG_ERROR("Hra Task pool add worker failed!");
        return HRA_FAILED;
    }

    LOG_DEBUG("OUT HostDiscoveryCfgHandle");
    return HRA_OK;
}

////////////////////////////////////////////
int HRA_HOST_DISCOVERY_EXPORT HostDiscoveryCancelInit(void)
{
    return HRA_OK;
}

int HRA_HOST_DISCOVERY_EXPORT HostDiscoveryCancelDestroy(void)
{
    return HRA_OK;
}

int HRA_HOST_DISCOVERY_EXPORT HostDiscoveryCancelHandle(const Json::Value& jsContent)
{
    std::string task_id;
    if (!jsContent.isMember("task_id") || !jsContent["task_id"].isString())
    {
        LOG_WARN("task_id not found!");
        return HRA_BAD_PARAM;
    }
    else
    {
        task_id = jsContent["task_id"].asString();
    }

    HraTask_CancelWorker(task_id.c_str(), HRA_ELMT_HOST_DISCOVERY_CFG, ProMsgHead::MsgType::NOTIFIER);
    return HRA_OK;
}
////////////////////////////////////////////
