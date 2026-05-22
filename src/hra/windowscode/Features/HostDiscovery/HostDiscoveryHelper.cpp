#include "HostDiscoveryHelper.h"
#include "NICInfoHelper.h"
#include "IpRangeParser.h"
#include "ArpRequestHelper.h"
#include "PingIcmpHelper.h"
#include "ArpTableParser.h"

#include <utility/comm.h>
#include <utility/Logger.h>
#include <utility/HraCtrlCmd.h>
#include <utility/SocketTcp.h>

#include <json/json.h>

#include <process.h>

#include <mutex>
#include <thread>
#include <memory>
#include <sstream>
#include <utility/HraUtils.h>


// MAXIMUM_WAIT_OBJECTS = 64
// https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitformultipleobjects
#define TOTAL_THREAD_COUNT 10

//////////////////////////////////////////////////////////////////////////
void CHostPortInfo::ToString(std::string& str) const
{
    std::stringstream ss;
    ss << strProtocol << ":" << iPortNum;

    str = ss.str();
}

//////////////////////////////////////////////////////////////////////////
#define JSON_HOST_DISCOVERY_INFO_KEY_HOST_MAC "mac"
#define JSON_HOST_DISCOVERY_INFO_KEY_HOST_IP "ip"
#define JSON_HOST_DISCOVERY_INFO_KEY_HOST_MAC_VENDOR "mac_vendor"
#define JSON_HOST_DISCOVERY_INFO_KEY_SCANNER_IP "scanner_ip"
#define JSON_HOST_DISCOVERY_INFO_KEY_SCANNER_MAC "scanner_mac"
#define JSON_HOST_DISCOVERY_INFO_KEY_HOST_NAME "hostname"
#define JSON_HOST_DISCOVERY_INFO_KEY_OPEN_AGENT_PORT "open_agent_port"
#define JSON_HOST_DISCOVERY_INFO_KEY_ASSIGN_IP "assign_ip"
#define JSON_HOST_DISCOVERY_INFO_KEY_OS_MATCH "os_match"

#define JSON_HOST_DISCOVERY_INFO_KEY_OS_MATCH_OS_TYPE "os_type"
#define JSON_HOST_DISCOVERY_INFO_KEY_OS_MATCH_DEVICE_TYPE "device_type"
#define JSON_HOST_DISCOVERY_INFO_KEY_OS_MATCH_VENDOR "vendor"
#define JSON_HOST_DISCOVERY_INFO_KEY_OS_MATCH_OS_FAMILY "os_family"
#define JSON_HOST_DISCOVERY_INFO_KEY_OS_MATCH_ACCURACY "accuracy"

#define JSON_HOST_DISCOVERY_INFO_KEY_DISCOVERY_METHOD "discovery_method"
#define JSON_HOST_DISCOVERY_INFO_KEY_COMMON_INFO "common_info"
void CHostDiscoveryInfo::ToJson(Json::Value& jsonVal)
{
    jsonVal = Json::objectValue;
    jsonVal[JSON_HOST_DISCOVERY_INFO_KEY_HOST_MAC]         = strMacAddr;
    jsonVal[JSON_HOST_DISCOVERY_INFO_KEY_HOST_MAC_VENDOR]  = strMacVendor;
    jsonVal[JSON_HOST_DISCOVERY_INFO_KEY_HOST_IP]          = strIP;
    jsonVal[JSON_HOST_DISCOVERY_INFO_KEY_SCANNER_IP]       = strScannerIp;
    jsonVal[JSON_HOST_DISCOVERY_INFO_KEY_SCANNER_MAC]      = strScannerMac;
    jsonVal[JSON_HOST_DISCOVERY_INFO_KEY_HOST_NAME]        = strHostName;
    jsonVal[JSON_HOST_DISCOVERY_INFO_KEY_OPEN_AGENT_PORT]       = iOpenAgentPort;
    jsonVal[JSON_HOST_DISCOVERY_INFO_KEY_ASSIGN_IP]             = iAssignIp;
    Json::Value jOsMatch                                        = Json::objectValue;
    jOsMatch[JSON_HOST_DISCOVERY_INFO_KEY_OS_MATCH_OS_TYPE]     = osProbablyInfo.strOsType;
    jOsMatch[JSON_HOST_DISCOVERY_INFO_KEY_OS_MATCH_DEVICE_TYPE] = osProbablyInfo.strDeviceType;
    jOsMatch[JSON_HOST_DISCOVERY_INFO_KEY_OS_MATCH_VENDOR]      = osProbablyInfo.strVendor;
    jOsMatch[JSON_HOST_DISCOVERY_INFO_KEY_OS_MATCH_OS_FAMILY]   = osProbablyInfo.strOsFamily;
    jOsMatch[JSON_HOST_DISCOVERY_INFO_KEY_OS_MATCH_ACCURACY]    = osProbablyInfo.iAccuracy;
    jsonVal[JSON_HOST_DISCOVERY_INFO_KEY_OS_MATCH] = jOsMatch;

    jsonVal[JSON_HOST_DISCOVERY_INFO_KEY_DISCOVERY_METHOD] = static_cast<int>(eHostDiscoveryMethod);

    // TODO: do not support portscan now
    jsonVal[JSON_HOST_DISCOVERY_INFO_KEY_COMMON_INFO] = Json::arrayValue;
}

void CHostDiscoveryInfo::ToString(std::string& str) const
{
    std::stringstream ss;
    ss << eHostDiscoveryMethod << "@@" << strIP << "@@" << strMacAddr  << "@@" << strScannerIp
       << "@@" << strScannerMac << "@@";
    for (auto& iter = vecPortInfo.begin(); iter != vecPortInfo.end(); ++iter)
    {
        std::string strCurPort;
        (*iter).ToString(strCurPort);
        ss << strCurPort;
    }

    str = ss.str();
}

bool operator<(const CHostPortInfo& left, const CHostPortInfo& right)
{
    return (left.strProtocol < right.strProtocol) && (left.iPortNum < right.iPortNum);
}

bool operator<(const CHostDiscoveryInfo& left, const CHostDiscoveryInfo& right)
{
    std::string strLeft;
    std::string strRight;

    left.ToString(strLeft);
    right.ToString(strRight);

    return strLeft < strRight;
}

////////////////////////////////////////////////////////////////////////////
namespace HostDiscoveryHelper
{
void HostDiscoveryResultToJson(const HostDiscoveryResult& hostDiscoveryResult, Json::Value& jsonResult)
{
    jsonResult = Json::arrayValue;

    for (auto iter = hostDiscoveryResult.begin(); iter != hostDiscoveryResult.end(); ++iter)
    {
        Json::Value curJsonVal;

        CHostDiscoveryInfo hostDiscoveryInfo = *iter;

        hostDiscoveryInfo.ToJson(curJsonVal);

        jsonResult.append(curJsonVal);
    }
}
} // namespace HostDiscoveryHelper

///////////////////////////////////////////////////////////////////////////
unsigned __stdcall CHostDiscoveryHelper::ProbeHostByArpThread(void* pArguments)
{
    if (pArguments == NULL)
    {
        LOG_DEBUG("thread arg is null...");
        return 1;
    }

    // convert to actual object
    std::shared_ptr<CProbeHostThreadArg> shptrProbeHostThreadArg(reinterpret_cast<CProbeHostThreadArg*>(pArguments));

    std::string strScannerMacAddr    = shptrProbeHostThreadArg->strScannerMac;
    std::string strScannerSrcIp      = shptrProbeHostThreadArg->strScannerIp;
    std::string strScannerGatewayIp  = shptrProbeHostThreadArg->strScannerGatewayIp;
    std::string strScannerGatewayMac = shptrProbeHostThreadArg->strScannerGatewayMac;

    if (shptrProbeHostThreadArg->ptrThis == NULL)
    {
        LOG_DEBUG("HostDiscoveryHelper is null...");
        return 1;
    }

    CHostDiscoveryHelper* pHostDiscoveryHelper =
        reinterpret_cast<CHostDiscoveryHelper*>(shptrProbeHostThreadArg->ptrThis);

    // while until toBeScanIp is empty
    std::string strDestIp;
    while (pHostDiscoveryHelper->PopToBeScanIp(strDestIp))
    {
        if (pHostDiscoveryHelper->IsNeedCancel())
        {
            break;
        }

        CHostDiscoveryInfo hostDiscoveryInfo;

        CArpRequestHelper arpRequestHelper(strScannerSrcIp, strScannerMacAddr, strDestIp);

        if (arpRequestHelper.SendArpReq(hostDiscoveryInfo) != HRA_OK)
        {
            LOG_DEBUG("send arp failed, src ip: %s, dest ip: %s", strScannerSrcIp.c_str(), strDestIp.c_str());

            continue;
        }

        // filter item which mac addr same as scanner gateway but ip not, because of arp proxy
        if ((hostDiscoveryInfo.strMacAddr == strScannerGatewayMac) && (strDestIp != strScannerGatewayIp))
        {
            continue;
        }

        hostDiscoveryInfo.iOpenAgentPort = -1;
        hostDiscoveryInfo.iAssignIp      = 1;

        // save scan result
        pHostDiscoveryHelper->InsertScanResult(hostDiscoveryInfo);
    }

    LOG_DEBUG("tid: %d terminated", GetCurrentThreadId());

    return 0;
}

unsigned __stdcall CHostDiscoveryHelper::ProbeHostByPingThread(void* pArguments)
{
    if (pArguments == NULL)
    {
        LOG_DEBUG("thread arg is null...");
        return 1;
    }

    // convert to actual object
    std::shared_ptr<CProbeHostThreadArg> shptrProbeHostThreadArg(reinterpret_cast<CProbeHostThreadArg*>(pArguments));

    std::string strScannerMacAddr    = shptrProbeHostThreadArg->strScannerMac;
    std::string strScannerSrcIp      = shptrProbeHostThreadArg->strScannerIp;
    std::string strScannerGatewayIp  = shptrProbeHostThreadArg->strScannerGatewayIp;
    std::string strScannerGatewayMac = shptrProbeHostThreadArg->strScannerGatewayMac;

    if (shptrProbeHostThreadArg->ptrThis == NULL)
    {
        LOG_DEBUG("HostDiscoveryHelper is null...");
        return 1;
    }

    CHostDiscoveryHelper* pHostDiscoveryHelper =
        reinterpret_cast<CHostDiscoveryHelper*>(shptrProbeHostThreadArg->ptrThis);

    // init ping helper
    CPingIcmpHelper pingIcmpHelper;

    if (!pingIcmpHelper.Init())
    {
        LOG_DEBUG("init icmp failed...");
        return 1;
    }

    // init os arp table parser
    CArpTableParser arpTableParser;

    // while until toBeScanIp is empty
    std::string strDestIp;
    while (pHostDiscoveryHelper->PopToBeScanIp(strDestIp))
    {
        if (pHostDiscoveryHelper->IsNeedCancel())
        {
            break;
        }

        bool bHasEcho    = false;
        HRA_Code retCode = pingIcmpHelper.Ping(strDestIp, bHasEcho);

        if (retCode != HRA_OK)
        {
            LOG_DEBUG("ping %s failed...", strDestIp.c_str());
            continue;
        }

        if (!bHasEcho)
        {
            LOG_DEBUG("host %s not reachable", strDestIp.c_str());
            continue;
        }

        // ping success, read its mac addr from os arp table
        std::string strMacAddr;
        if (!arpTableParser.FindMacAddrByIpAddress(strDestIp, strMacAddr))
        {
            LOG_DEBUG("can not find mac of host %s from os arp table", strDestIp.c_str());
            continue;
        }

        // filter item which mac addr same as scanner gateway but ip not, because of arp proxy
        if ((strMacAddr == strScannerGatewayMac) && (strDestIp != strScannerGatewayIp))
        {
            continue;
        }

        CHostDiscoveryInfo hostDiscoveryInfo;

        hostDiscoveryInfo.eHostDiscoveryMethod = Ping;
        hostDiscoveryInfo.strHostName          = "";
        hostDiscoveryInfo.strIP                = strDestIp;
        hostDiscoveryInfo.strMacAddr           = strMacAddr;
        hostDiscoveryInfo.strScannerIp         = strScannerSrcIp;
        hostDiscoveryInfo.strScannerMac        = strScannerMacAddr;
        hostDiscoveryInfo.iOpenAgentPort       = -1;
        hostDiscoveryInfo.iAssignIp            = 1;

        // save scan result
        pHostDiscoveryHelper->InsertScanResult(hostDiscoveryInfo);
    }

    LOG_DEBUG("tid: %d terminated", GetCurrentThreadId());

    return 0;
}

unsigned __stdcall CHostDiscoveryHelper::ProbeHostByNmapThread(void* pArguments)
{
    if (pArguments == NULL)
    {
        LOG_DEBUG("thread arg is null...");
        return 1;
    }

    // convert to actual object
    std::shared_ptr<CProbeHostThreadArg> shptrProbeHostThreadArg(reinterpret_cast<CProbeHostThreadArg*>(pArguments));

    std::string strScannerMacAddr    = shptrProbeHostThreadArg->strScannerMac;
    std::string strScannerSrcIp      = shptrProbeHostThreadArg->strScannerIp;
    std::string strScannerGatewayIp  = shptrProbeHostThreadArg->strScannerGatewayIp;
    std::string strScannerGatewayMac = shptrProbeHostThreadArg->strScannerGatewayMac;
    HostDiscoveryScanParam & scanParameter = shptrProbeHostThreadArg->ptrScanParameter;

    if (shptrProbeHostThreadArg->ptrThis == NULL)
    {
        LOG_DEBUG("HostDiscoveryHelper is null...");
        return 1;
    }
    CHostDiscoveryHelper* pHostDiscoveryHelper =
        reinterpret_cast<CHostDiscoveryHelper*>(shptrProbeHostThreadArg->ptrThis);

    // init ping helper
    CPingIcmpHelper pingIcmpHelper;

    if (!pingIcmpHelper.Init())
    {
        LOG_DEBUG("init icmp failed...");
        return 1;
    }
    const int portScanTimeout     = 3;
    const int portScanfixedList[] = {7,    9,    13,   21,   22,   23,   25,   26,   37,    53,    79,    80,    81,   88,
                               106,  110,  111,  113,  119,  135,  139,  143,  144,   179,   199,   389,   427,  443,
                               444,  445,  465,  513,  514,  515,  543,  544,  548,   554,   587,   631,   646,  873,
                               990,  993,  995,  1025, 1026, 1027, 1028, 1029, 1110,  1433,  1720,  1723,  1755, 1900,
                               2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389,  3986,  4899,  5000,  5009, 5051,
                               5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900,  6000,  6001,  6646,  7070, 8000,
                               8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 33331, 34057, 37048};
    // init os arp table parser
    CArpTableParser arpTableParser;
    // while until toBeScanIp is empty
    std::string strDestIp;
    while (pHostDiscoveryHelper->PopToBeScanIp(strDestIp))
    {
        if (pHostDiscoveryHelper->IsNeedCancel())
        {
            break;
        }
        std::string strMacAddr = "";
        bool bHasEcho          = false;
        // port scan
        for (auto& iterCurScanItem = scanParameter.vecScanItem.begin();
             ! bHasEcho && iterCurScanItem != scanParameter.vecScanItem.end(); ++iterCurScanItem)
        {
            HostDiscoveryScanParamItem curScanItem = *iterCurScanItem;
            if (curScanItem.eProtocol == TCP)
            {
                SocketTcpClient sockClient;

                std::vector<int> vecPorts(portScanfixedList,
                                          portScanfixedList + sizeof(portScanfixedList) / sizeof(int));
                for (auto& iterCurPort = curScanItem.vecPorts.begin(); iterCurPort != curScanItem.vecPorts.end();
                     ++iterCurPort)
                {
                    std::string strCurPort = *iterCurPort;
                    int iCurPort           = atoi(strCurPort.c_str());
                    vecPorts.push_back(iCurPort);
                }
                // unique list
                std::set<int> deDuplicateSet(vecPorts.begin(), vecPorts.end());
                vecPorts.assign(deDuplicateSet.begin(), deDuplicateSet.end());

                LOG_DEBUG("begin connect %s, nPorts = %d, timeout = %d", strDestIp.c_str(), vecPorts.size(), portScanTimeout);
                int nReady = sockClient.connectTestPorts(strDestIp.c_str(), vecPorts, portScanTimeout);
                if (nReady > 0)
                {
                    LOG_DEBUG("connect succefully! %s", strDestIp.c_str());
                    bHasEcho = true;
                    break;
                }
                LOG_DEBUG("failed to connect.... %s", strDestIp.c_str());
            }
            else
            {
                // other protocol, which is connectless and unstable, use icmp instead
                HRA_Code retCode = pingIcmpHelper.Ping(strDestIp, bHasEcho);
                if (retCode != HRA_OK)
                {
                    LOG_DEBUG("ping %s failed...", strDestIp.c_str());
                    continue;
                }

                // this is alive addr
                bHasEcho = true;
                break;
            }
        }


        if (! bHasEcho)
        {
            continue;
        }


        CHostDiscoveryInfo hostDiscoveryInfo;
        hostDiscoveryInfo.eHostDiscoveryMethod = Nmap;
        hostDiscoveryInfo.strIP                = strDestIp;
        hostDiscoveryInfo.strScannerIp         = strScannerSrcIp;
        hostDiscoveryInfo.strScannerMac        = strScannerMacAddr;
        hostDiscoveryInfo.strHostName          = "";
        hostDiscoveryInfo.iOpenAgentPort       = -1;
        hostDiscoveryInfo.iAssignIp            = 1;
        // test agent port connectivity
        LOG_DEBUG("begin agent port connectivity testing: %s, nPorts = %d, timeout = %d", strDestIp.c_str(),
                  scanParameter.vecAgentPorts.size(), portScanTimeout);
        if (scanParameter.vecAgentPorts.size() > 0)
        {
            hostDiscoveryInfo.iOpenAgentPort = 0;

            SocketTcpClient sockClient;
            int nReady = sockClient.connectTestPorts(strDestIp.c_str(), scanParameter.vecAgentPorts, portScanTimeout);
            if (nReady > 0)
            {
                LOG_DEBUG("agent port connectivity testing succefully! %s", strDestIp.c_str());
                hostDiscoveryInfo.iOpenAgentPort = 1;
            }
        }
        
        // send success, read its mac addr from os arp table
        if (!arpTableParser.FindMacAddrByIpAddress(strDestIp, strMacAddr))
        {
            LOG_DEBUG("can not find mac of host %s from os arp table", strDestIp.c_str());
        }
        // filter item which mac addr same as scanner gateway but ip not, because of arp proxy
        if ((strMacAddr == strScannerGatewayMac) && (strDestIp != strScannerGatewayIp))
        {
            continue;
        }

        hostDiscoveryInfo.strMacAddr           = strMacAddr;
        
        // osscan
        if (scanParameter.bDeepScan)
        {
            std::string strOsVersion;
            std::string strHostName;
            // use a bit small timeout val for adjacent joint net
            int nRet = PseudoNmapProbe(strDestIp, 2, 2, strOsVersion, strHostName);
            if (nRet < 0)
            {
                LOG_DEBUG("failed to call PseudoNmapProbe");
            }
            else
            {
                CHostOsProbablyInfo hostOsProbablyInfo;
                hostOsProbablyInfo.strOsType     = strOsVersion;
                // follow nmap
                hostOsProbablyInfo.strOsFamily   = "Windows";
                hostOsProbablyInfo.strVendor     = "Microsoft";
                hostOsProbablyInfo.strDeviceType = "general purpose";
                // absolute confidence in this deterministic discovery method
                hostOsProbablyInfo.iAccuracy     = 100; 

                hostDiscoveryInfo.osProbablyInfo = hostOsProbablyInfo;
                hostDiscoveryInfo.strHostName    = strHostName;
            }
        }
        // save scan result
        pHostDiscoveryHelper->InsertScanResult(hostDiscoveryInfo);
    }

    LOG_DEBUG("tid: %d terminated", GetCurrentThreadId());

    return 0;
}

int __stdcall CHostDiscoveryHelper::PseudoNmapProbe(std::string strIP, int nWriteTimeOut, int nReadTimeout, std::string& strOsVersion, std::string& strHostName)
{
    int nRet = 1;

    // fixed parameter
    int nPort    = 135;

    SocketTcpClient sockClient;
    char* pszRcvBuff = NULL;

    do
    {
        if (sockClient.connect(strIP.c_str(), nPort, nWriteTimeOut) != 0)
        {
            // use debug to avoid swarmp log
            LOG_DEBUG("connect failed! %s", sockClient.getErrorMsg());
            return -6;
        }

        unsigned int payload_len = 0;
        // 1. get arch type of OS
        std::string strArch              = "x86";
        unsigned char payload_get_arch[] = {
            0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x10,
            0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x83, 0xaf, 0xe1,
            0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa, 0x03, 0x00, 0x00, 0x00, 0x33, 0x05,
            0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36, 0x01, 0x00, 0x00, 0x00};
        payload_len = sizeof(payload_get_arch);
        nRet        = sockClient.send(payload_get_arch, payload_len, nWriteTimeOut);
        if (nRet <= 0)
        {
            // use debug to avoid swarmp log
            LOG_DEBUG("send failed! %s", sockClient.getErrorMsg());
            nRet = -7;
            break;
        }

        pszRcvBuff = (char*)malloc(1024);
        if (pszRcvBuff == NULL)
        {
            LOG_ERROR("malloc error!");
            nRet = -8;
            break;
        }
        memset(pszRcvBuff, 0, 512);
        nRet = sockClient.receiveOnce(pszRcvBuff, 512, nReadTimeout);

        if (nRet <= 0)
        {
            LOG_WARN("receive 1st failed! %s", sockClient.getErrorMsg());
            nRet = -9;
            break;
        }

        // 2. decode arch info by payload search
        char strPtn[] = {0x33, 0x05, 0x71, 0x71, 0xBA, 0xBE, 0x37, 0x49,
                         0x83, 0x19, 0xB5, 0xDB, 0xEF, 0x9C, 0xCC, 0x36};
        int iSafeLoopGuard = 100;
        for (int i = nRet - sizeof(strPtn) - 1; i > 0 && iSafeLoopGuard > 0; i--, iSafeLoopGuard--)
        {
            if (0 == memcmp(&pszRcvBuff[i], strPtn, sizeof(strPtn)))
            {
                strArch = "x64";
                break;
            }
        }
        /*for (int i = 0; i < nRet; i++)
        {
            LOG_INFO("%02x ", static_cast<unsigned char>(pszRcvBuff[i]));
        }*/
        free(pszRcvBuff);
        pszRcvBuff = NULL;

        // 3. get netbios info
        sockClient.close();

        if (sockClient.connect(strIP.c_str(), nPort, nWriteTimeOut) != 0)
        {
            LOG_WARN("connect 2nd failed! %s", sockClient.getErrorMsg());
            return -10;
        }
        // ntmlssp challenge message
        char payload_get_nbtinfo[] = {
            0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x78, 0x00, 0x28, 0x00, 0x03, 0x00, 0x00, 0x00, 0xb8, 0x10,
            0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0xa0, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, 0x00, 0x00, 0x00, 0x00, 0x04, 0x5d,
            0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
            0x0a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x07, 0x82, 0x08, 0xa2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f};
        payload_len = sizeof(payload_get_nbtinfo);
        nRet        = sockClient.send(payload_get_nbtinfo, payload_len, nWriteTimeOut);
        if (nRet <= 0)
        {
            LOG_WARN("send 2nd failed! %s", sockClient.getErrorMsg());
            nRet = -11;
            break;
        }

        pszRcvBuff = (char*)malloc(4096);
        if (pszRcvBuff == NULL)
        {
            LOG_ERROR("malloc error!");
            nRet = -12;
            break;
        }
        memset(pszRcvBuff, 0, 4096);
        nRet = sockClient.receiveOnce(pszRcvBuff, 4096, nReadTimeout);
        if (nRet <= 0)
        {
            LOG_WARN("receive 2nd failed! %s", sockClient.getErrorMsg());
            nRet = -13;
            break;
        }
        int nReadCount = nRet;
        // 4. decode
        int iMajorVersion  = pszRcvBuff[0xa0 - 54 + 10];
        int iMinorVersion  = pszRcvBuff[0xa0 - 54 + 10 + 1];
        short iBuildNumber   = *(short*)&pszRcvBuff[0xa0 - 54 + 10 + 2];

        char osVersion[64] = {};
        sprintf_s(osVersion, "Microsoft Windows %d.%d Build %d %s", iMajorVersion, iMinorVersion, iBuildNumber, strArch.c_str());
        strOsVersion = std::string(osVersion);

        LOG_DEBUG("osVersion = %s", strOsVersion.c_str());

        short targetInfoLengthBytes = *(short*)&pszRcvBuff[0xa0 - 54 + 2];
        LOG_DEBUG("targetInfoLengthBytes = %d", targetInfoLengthBytes);

        char* pTargetInfo                  = pszRcvBuff + nReadCount - targetInfoLengthBytes;

        wchar_t* wszTargetInfo = (wchar_t*)pTargetInfo;

        std::string targetList[4];
        // cursor by step WORD
        int iCursorPos = 0;
        for (int i = 0; i < 4; i++)
        {
            short nAttLenByWord = *(short*)&wszTargetInfo[iCursorPos + 1];
            nAttLenByWord /= 2;
            
            std::wstring wstr = std::wstring(wszTargetInfo + iCursorPos + 2, nAttLenByWord);
            targetList[i] = UtilsUnicodeToString(wstr);

            iCursorPos += 2 + nAttLenByWord;
        }
        strHostName = targetList[1];
    } while (false);

    // 5. cleanup
    if (pszRcvBuff != NULL)
    {
        free(pszRcvBuff);
        pszRcvBuff = NULL;
    }
    sockClient.close();
    
    return nRet;
}


////////////////////////////////////////////////////////////////////////////////////////////

CHostDiscoveryHelper::CHostDiscoveryHelper(DWORD dwTaskThreadId)
    : m_dwTaskThreadId(dwTaskThreadId)
    , m_bIsRunning(false)

{
}

CHostDiscoveryHelper::~CHostDiscoveryHelper()
{
    LOG_DEBUG("In ~CHostDiscoveryHelper");

    WaitAllWorkThreadTerminate();

    m_bIsRunning = false;

    LOG_DEBUG("Out ~CHostDiscoveryHelper");
}

HRA_Code CHostDiscoveryHelper::GetScannerSubnetRangeCidr(const CNICNetInfo& scannerNicInfo,
                                                         std::string& strScannerSubnetRangeCidrStyle)
{
    HRA_Code retCode = HRA_FAILED;
    // covert ip and subnet mask to cidr style
    CIpRangeParser ipRangeParser(scannerNicInfo.strIPv4, scannerNicInfo.strIPv4Mask);

    if (!ipRangeParser.Parse())
    {
        LOG_ERROR("invalid scanner info, %s, %s", scannerNicInfo.strIPv4.c_str(), scannerNicInfo.strIPv4Mask.c_str());
        return retCode;
    }

    if (!ipRangeParser.ConvertSubnetStyleToCidrStyle(strScannerSubnetRangeCidrStyle))
    {
        LOG_ERROR("invalid scanner info, %s, %s", scannerNicInfo.strIPv4.c_str(), scannerNicInfo.strIPv4Mask.c_str());
        return retCode;
    }
    return HRA_OK;
}

HRA_Code CHostDiscoveryHelper::DiscoveryHostInScannerSubnet(const CNICNetInfo& scannerNicInfo,
                                                            HostDiscoveryMethod hostDiscoveryMethod,
                                                            HostDiscoveryResult& setScanResult,
                                                            HostDiscoveryScanParam& scanParameter)
{
    HRA_Code retCode = HRA_FAILED;

    if (m_bIsRunning)
    {
        LOG_DEBUG("another scan task is running");
        retCode = HRA_OP_IN_PROGRESS;
        return retCode;
    }

    m_bIsRunning = true;

    // clear last result
    m_setScanResult.clear();

    // covert ip and subnet mask to cidr style
    CIpRangeParser ipRangeParser(scannerNicInfo.strIPv4, scannerNicInfo.strIPv4Mask);

    if (!ipRangeParser.Parse())
    {
        LOG_ERROR("invalid scanner info, %s, %s", scannerNicInfo.strIPv4.c_str(), scannerNicInfo.strIPv4Mask.c_str());
        return retCode;
    }

    std::string strScannerSubnetRangeCidrStyle;
    if (!ipRangeParser.ConvertSubnetStyleToCidrStyle(strScannerSubnetRangeCidrStyle))
    {
        LOG_ERROR("invalid scanner info, %s, %s", scannerNicInfo.strIPv4.c_str(), scannerNicInfo.strIPv4Mask.c_str());
        return retCode;
    }

    switch (hostDiscoveryMethod)
    {
    case Arp: {
        // target ip range same as scanner ip range to scan scanner's ip range only
        if (DiscoveryByArp(scannerNicInfo, strScannerSubnetRangeCidrStyle) != HRA_OK)
        {
            std::string strTemp;
            scannerNicInfo.ToString(strTemp);
            LOG_DEBUG("discovery by arp failed, NIC info: %s", strTemp.c_str());
        }
        break;
    }

    case Ping: {
        // target ip range same as scanner ip range to scan scanner's ip range only
        if (DiscoveryByPing(scannerNicInfo, strScannerSubnetRangeCidrStyle) != HRA_OK)
        {
            std::string strTemp;
            scannerNicInfo.ToString(strTemp);
            LOG_DEBUG("discovery by ping failed, NIC info: %s", strTemp.c_str());
        }
        break;
    }

    case Nmap: {
        if (DiscoveryByNmap(scannerNicInfo, strScannerSubnetRangeCidrStyle, scanParameter) != HRA_OK)
        {
            std::string strTemp;
            scannerNicInfo.ToString(strTemp);
            LOG_DEBUG("discovery by nmap failed, NIC info: %s", strTemp.c_str());
        }
        break;
    }

    default: {
        LOG_DEBUG("unsupport discovery method");
        break;
    }
    }

    // terminate by user cancle??
    if (IsNeedCancel())
    {
        LOG_DEBUG("get cancel command, terminate task");

        m_bIsRunning = false;

        return HRA_USER_CANCEL;
    }

    LOG_DEBUG("host discovery success");
    setScanResult = m_setScanResult;

    m_bIsRunning = false;

    return HRA_OK;
}

HRA_Code CHostDiscoveryHelper::DiscoveryHost(const CNICNetInfo& scannerNicInfo, const std::string& strTargetIpRange,
                                             HostDiscoveryMethod hostDiscoveryMethod,
                                             HostDiscoveryResult& setScanResult,
                                             HostDiscoveryScanParam& scanParameter)
{
    HRA_Code retCode = HRA_FAILED;

    if (m_bIsRunning)
    {
        LOG_DEBUG("another scan task is running");
        retCode = HRA_OP_IN_PROGRESS;
        return retCode;
    }

    m_bIsRunning = true;

    // clear last result
    m_setScanResult.clear();

    LOG_DEBUG("scanner NIC MAC addr: %s", scannerNicInfo.strMac.c_str());
    LOG_DEBUG("scanner NIC ip addr: %s", scannerNicInfo.strIPv4.c_str());

    LOG_DEBUG("begin scan with scanner NIC");
    switch (hostDiscoveryMethod)
    {
    case Arp: {
        if (DiscoveryByArp(scannerNicInfo, strTargetIpRange) != HRA_OK)
        {
            std::string strTemp;
            scannerNicInfo.ToString(strTemp);
            LOG_DEBUG("discovery by arp failed, NIC info: %s", strTemp.c_str());
        }
        break;
    }

    case Ping: {
        if (DiscoveryByPing(scannerNicInfo, strTargetIpRange) != HRA_OK)
        {
            std::string strTemp;
            scannerNicInfo.ToString(strTemp);
            LOG_DEBUG("discovery by ping failed, NIC info: %s", strTemp.c_str());
        }
        break;
    }

    case Nmap: {
        if (DiscoveryByNmap(scannerNicInfo, strTargetIpRange, scanParameter) != HRA_OK)
        {
            std::string strTemp;
            scannerNicInfo.ToString(strTemp);
            LOG_DEBUG("discovery by nmap failed, NIC info: %s", strTemp.c_str());
        }
        break;
    }

    default: {
        LOG_DEBUG("unsupport discovery method");
        break;
    }
    }
    LOG_DEBUG("end scan with scanner NIC");

    // terminate by user cancle??
    if (IsNeedCancel())
    {
        LOG_DEBUG("get cancel command, terminate task");

        m_bIsRunning = false;

        return HRA_USER_CANCEL;
    }

    LOG_DEBUG("host discovery success");
    setScanResult = m_setScanResult;

    m_bIsRunning = false;

    return HRA_OK;
}

// use one ip of NIC to scan
HRA_Code CHostDiscoveryHelper::DiscoveryByArp(const CNICNetInfo& nicNetInfo, const std::string& strTargetIpRange)
{
    CNICNetInfo curNICNetInfo = nicNetInfo;

    // must contains ip, mac, mask, gateway
    if (curNICNetInfo.strGateWayIPv4.empty() || curNICNetInfo.strIPv4.empty() || curNICNetInfo.strIPv4Mask.empty() ||
        curNICNetInfo.strMac.empty())
    {
        LOG_DEBUG("do not contains enough info");
        return HRA_FAILED;
    }

    // calculate NIC ip range
    std::string strScannerIp          = curNICNetInfo.strIPv4;
    std::string strScannerNetworkMask = curNICNetInfo.strIPv4Mask;

    CIpRangeParser ipRangeParser(strScannerIp, strScannerNetworkMask);

    if (!ipRangeParser.Parse())
    {
        LOG_ERROR("ip: %s, mask: %s parse range failed", strScannerIp.c_str(), strScannerNetworkMask.c_str());
        return HRA_FAILED;
    }

    // get scanner gateway mac to filter ARP proxy
    std::string strGateWayIp  = curNICNetInfo.strGateWayIPv4;
    std::string strScannerMac = curNICNetInfo.strMac;

    CArpRequestHelper arpRequestHelper(strScannerIp, strScannerMac, strGateWayIp);

    CHostDiscoveryInfo gatewayHostInfo;

    LOG_DEBUG("begin fetch gateway mac address");
    if (arpRequestHelper.SendArpReq(gatewayHostInfo) != HRA_OK)
    {
        LOG_ERROR("get gate way mac by arp failed, gate way ip: %s", strGateWayIp.c_str());
        return HRA_FAILED;
    }

    std::string strGatewayMacAddr = gatewayHostInfo.strMacAddr;

    if (strGatewayMacAddr.empty())
    {
        LOG_ERROR("get gate way mac by arp failed, gate way ip: %s", strGateWayIp.c_str());
        return HRA_FAILED;
    }

    LOG_DEBUG("end fetch gateway mac address");

    LOG_DEBUG("scanner ip: %s, scanner mask: %s, sanncer gateway ip: %s, scanner gateway mac: %s", strScannerIp.c_str(),
              strScannerNetworkMask.c_str(), strGateWayIp.c_str(), strGatewayMacAddr.c_str());

    // merge src ip range with current NIC ip range
    std::vector<std::string> vecToBeScanIpRange;
    HRA_Code retCode =
        MergeScanRangeWithScannerNetInfo(strScannerIp, strScannerNetworkMask, strTargetIpRange, vecToBeScanIpRange);

    if (retCode != HRA_OK)
    {
        LOG_ERROR("src ip range: %s, ip: %s, mask: %s merge failed", strTargetIpRange.c_str(), strScannerIp.c_str(),
                  strScannerNetworkMask.c_str());
        return HRA_FAILED;
    }

    // scan one ip by one
    if (vecToBeScanIpRange.empty())
    {
        LOG_DEBUG("no ip need to be scan, ip range: %s, scanner ip: %s, scanner mask: %s", strTargetIpRange.c_str(),
                  strScannerIp.c_str(), strScannerNetworkMask.c_str());

        return HRA_OK;
    }

    // copy to member
    {
        std::unique_lock<std::mutex> lock(m_mutexToBeScanIp);
        m_vecToBeScanIp = vecToBeScanIpRange;
    }

    LOG_DEBUG("---------------------begin scan--------------------------");
    // create work thread
    for (int i = 0; i < TOTAL_THREAD_COUNT; ++i)
    {
        CProbeHostThreadArg* pProbeHostThreadArg = new (std::nothrow) CProbeHostThreadArg();
        if (pProbeHostThreadArg == NULL)
        {
            LOG_ERROR("alloc memory failed...");
            continue;
        }

        pProbeHostThreadArg->ptrThis              = this;
        pProbeHostThreadArg->strScannerMac        = strScannerMac;
        pProbeHostThreadArg->strScannerIp         = strScannerIp;
        pProbeHostThreadArg->strScannerGatewayIp  = strGateWayIp;
        pProbeHostThreadArg->strScannerGatewayMac = strGatewayMacAddr;

        unsigned int threadId = 0;

        HANDLE hThread = (HANDLE)::_beginthreadex(NULL, 0, CHostDiscoveryHelper::ProbeHostByArpThread,
                                                  pProbeHostThreadArg, 0, &threadId);

        if (hThread)
        {
            LOG_DEBUG("create thread success: tid: %d", threadId);
            m_vecHandle.push_back(hThread);
        }
    }

    WaitAllWorkThreadTerminate();

    return HRA_OK;
}

HRA_Code CHostDiscoveryHelper::DiscoveryByPing(const CNICNetInfo& nicNetInfo, const std::string& strTargetIpRange)
{
    CNICNetInfo curNICNetInfo = nicNetInfo;

    // must contains ip, mac, mask, gateway
    if (curNICNetInfo.strGateWayIPv4.empty() || curNICNetInfo.strIPv4.empty() || curNICNetInfo.strIPv4Mask.empty() ||
        curNICNetInfo.strMac.empty())
    {
        LOG_DEBUG("do not contains enough info");
        return HRA_FAILED;
    }

    // calculate NIC ip range
    std::string strScannerIp         = curNICNetInfo.strIPv4;
    std::string strScannerSubnetMask = curNICNetInfo.strIPv4Mask;
    CIpRangeParser ipRangeParser(strScannerIp, strScannerSubnetMask);

    if (!ipRangeParser.Parse())
    {
        LOG_ERROR("ip: %s, mask: %s parse range failed", strScannerIp.c_str(), strScannerSubnetMask.c_str());
        return HRA_FAILED;
    }

    // get scanner gateway mac to filter ARP proxy
    std::string strGateWayIp  = curNICNetInfo.strGateWayIPv4;
    std::string strScannerMac = curNICNetInfo.strMac;

    CArpRequestHelper arpRequestHelper(strScannerIp, strScannerMac, strGateWayIp);

    CHostDiscoveryInfo gatewayHostInfo;

    LOG_DEBUG("begin fetch gateway mac address");

    if (arpRequestHelper.SendArpReq(gatewayHostInfo) != HRA_OK)
    {
        LOG_ERROR("get gate way mac by arp failed, gate way ip: %s", strGateWayIp.c_str());
        return HRA_FAILED;
    }

    std::string strGatewayMacAddr = gatewayHostInfo.strMacAddr;

    if (strGatewayMacAddr.empty())
    {
        LOG_ERROR("get gate way mac by arp failed, gate way ip: %s", strGateWayIp.c_str());
        return HRA_FAILED;
    }

    LOG_DEBUG("end fetch gateway mac address");

    LOG_DEBUG("scanner ip: %s, scanner mask: %s, sanncer gateway ip: %s, scanner gateway mac: %s", strScannerIp.c_str(),
              strScannerSubnetMask.c_str(), strGateWayIp.c_str(), strGatewayMacAddr.c_str());

    // merge src ip range with current NIC ip range
    std::vector<std::string> vecToBeScanIpRange;
    HRA_Code retCode =
        MergeScanRangeWithScannerNetInfo(strScannerIp, strScannerSubnetMask, strTargetIpRange, vecToBeScanIpRange);

    if (retCode != HRA_OK)
    {
        LOG_ERROR("src ip range: %s, ip: %s, mask: %s merge failed", strTargetIpRange.c_str(), strScannerIp.c_str(),
                  strScannerSubnetMask.c_str());
        return HRA_FAILED;
    }

    // scan one ip by one
    if (vecToBeScanIpRange.empty())
    {
        LOG_DEBUG("no ip need to be scan, ip range: %s, scanner ip: %s, scanner mask: %s", strTargetIpRange.c_str(),
                  strScannerIp.c_str(), strScannerSubnetMask.c_str());

        return HRA_OK;
    }

    // copy to member
    {
        std::unique_lock<std::mutex> lock(m_mutexToBeScanIp);
        m_vecToBeScanIp = vecToBeScanIpRange;
    }

    LOG_DEBUG("---------------------begin scan--------------------------");
    // create work thread
    for (int i = 0; i < TOTAL_THREAD_COUNT; ++i)
    {
        CProbeHostThreadArg* pProbeHostThreadArg = new (std::nothrow) CProbeHostThreadArg();
        if (pProbeHostThreadArg == NULL)
        {
            LOG_ERROR("alloc memory failed...");
            continue;
        }

        pProbeHostThreadArg->ptrThis              = this;
        pProbeHostThreadArg->strScannerMac        = strScannerMac;
        pProbeHostThreadArg->strScannerIp         = strScannerIp;
        pProbeHostThreadArg->strScannerGatewayIp  = strGateWayIp;
        pProbeHostThreadArg->strScannerGatewayMac = strGatewayMacAddr;

        unsigned int threadId = 0;

        HANDLE hThread = (HANDLE)::_beginthreadex(NULL, 0, CHostDiscoveryHelper::ProbeHostByPingThread,
                                                  pProbeHostThreadArg, 0, &threadId);

        if (hThread)
        {
            LOG_DEBUG("create thread success: tid: %d", threadId);
            m_vecHandle.push_back(hThread);
        }
    }

    WaitAllWorkThreadTerminate();

    return HRA_OK;
}

HRA_Code CHostDiscoveryHelper::DiscoveryByNmap(const CNICNetInfo& scannerNicInfo, const std::string& strTargetIpRange,
                                               HostDiscoveryScanParam scanParameter)
{
    CNICNetInfo curNICNetInfo = scannerNicInfo;
    // must contains ip, mac, mask, gateway
    if (curNICNetInfo.strGateWayIPv4.empty() || curNICNetInfo.strIPv4.empty() || curNICNetInfo.strIPv4Mask.empty() ||
        curNICNetInfo.strMac.empty())
    {
        LOG_DEBUG("do not contains enough info");
        return HRA_FAILED;
    }

    // calculate NIC ip range
    std::string strScannerIp         = curNICNetInfo.strIPv4;
    std::string strScannerSubnetMask = curNICNetInfo.strIPv4Mask;
    CIpRangeParser ipRangeParser(strScannerIp, strScannerSubnetMask);
    if (!ipRangeParser.Parse())
    {
        LOG_ERROR("ip: %s, mask: %s parse range failed", strScannerIp.c_str(), strScannerSubnetMask.c_str());
        return HRA_FAILED;
    }
    // get scanner gateway mac to filter ARP proxy
    std::string strGateWayIp  = curNICNetInfo.strGateWayIPv4;
    std::string strScannerMac = curNICNetInfo.strMac;

    CArpRequestHelper arpRequestHelper(strScannerIp, strScannerMac, strGateWayIp);

    CHostDiscoveryInfo gatewayHostInfo;

    LOG_DEBUG("begin fetch gateway mac address");

    if (arpRequestHelper.SendArpReq(gatewayHostInfo) != HRA_OK)
    {
        LOG_ERROR("get gate way mac by arp failed, gate way ip: %s", strGateWayIp.c_str());
        return HRA_FAILED;
    }
    std::string strGatewayMacAddr = gatewayHostInfo.strMacAddr;

    if (strGatewayMacAddr.empty())
    {
        LOG_ERROR("get gate way mac by arp failed, gate way ip: %s", strGateWayIp.c_str());
        return HRA_FAILED;
    }

    LOG_DEBUG("end fetch gateway mac address");

    LOG_DEBUG("scanner ip: %s, scanner mask: %s, sanncer gateway ip: %s, scanner gateway mac: %s", strScannerIp.c_str(),
              strScannerSubnetMask.c_str(), strGateWayIp.c_str(), strGatewayMacAddr.c_str());

    // merge src ip range with current NIC ip range
    std::vector<std::string> vecToBeScanIpRange;
    HRA_Code retCode =
        MergeScanRangeWithScannerNetInfo(strScannerIp, strScannerSubnetMask, strTargetIpRange, vecToBeScanIpRange);

    if (retCode != HRA_OK)
    {
        LOG_ERROR("src ip range: %s, ip: %s, mask: %s merge failed", strTargetIpRange.c_str(), strScannerIp.c_str(),
                  strScannerSubnetMask.c_str());
        return HRA_FAILED;
    }
    // scan one ip by one
    if (vecToBeScanIpRange.empty())
    {
        LOG_DEBUG("no ip need to be scan, ip range: %s, scanner ip: %s, scanner mask: %s", strTargetIpRange.c_str(),
                  strScannerIp.c_str(), strScannerSubnetMask.c_str());

        return HRA_OK;
    }
    //vecToBeScanIpRange.push_back(strTargetIpRange);
       
    // copy to member
    {
        std::unique_lock<std::mutex> lock(m_mutexToBeScanIp);
        m_vecToBeScanIp = vecToBeScanIpRange;
    }
    LOG_DEBUG("---------------------begin scan--------------------------");
    // create work thread
    for (int i = 0; i < TOTAL_THREAD_COUNT; ++i)
    {
        CProbeHostThreadArg* pProbeHostThreadArg = new (std::nothrow) CProbeHostThreadArg();
        if (pProbeHostThreadArg == NULL)
        {
            LOG_ERROR("alloc memory failed...");
            return HRA_FAILED;
        }
        pProbeHostThreadArg->ptrThis       = this;
        pProbeHostThreadArg->strScannerMac = strScannerMac;
        pProbeHostThreadArg->strScannerIp  = strScannerIp;
        pProbeHostThreadArg->strScannerGatewayIp  = strGateWayIp;
        pProbeHostThreadArg->strScannerGatewayMac = strGatewayMacAddr;
        pProbeHostThreadArg->ptrScanParameter = scanParameter;
        unsigned int threadId = 0;

        HANDLE hThread = (HANDLE)::_beginthreadex(NULL, 0, CHostDiscoveryHelper::ProbeHostByNmapThread,
                                                  pProbeHostThreadArg, 0, &threadId);
        HANDLE hHandle = 0;
        if (hThread)
        {
            LOG_DEBUG("create thread success: tid: %d", threadId);
            m_vecHandle.push_back(hThread);
        }
    }

    WaitAllWorkThreadTerminate();

    return HRA_OK;
}

HRA_Code CHostDiscoveryHelper::GetNICInfo(std::vector<CNICNetInfo>& vecNICInfo)
{
    // clear result map
    vecNICInfo.clear();

    // get all network interface card info
    CNICInfoHelper nicInfoHelper;

    HRA_Code retCode = nicInfoHelper.GetAllNICInfo(vecNICInfo);

    if (retCode != HRA_OK)
    {
        LOG_ERROR("get NIC info failed...");
        return retCode;
    }

    // print NIC debug info
    LOG_DEBUG("=======================NIC BEGIN===================");
    for (auto& iter = vecNICInfo.begin(); iter != vecNICInfo.end(); ++iter)
    {
        CNICNetInfo& curNicNetInfo = *iter;

        LOG_DEBUG("ipv4: %s, mask: %s, gateway: %s, mac: %s", curNicNetInfo.strIPv4.c_str(),
                  curNicNetInfo.strIPv4Mask.c_str(), curNicNetInfo.strGateWayIPv4.c_str(),
                  curNicNetInfo.strMac.c_str());
    }
    LOG_DEBUG("=======================NIC END===================");

    return HRA_OK;
}

bool CHostDiscoveryHelper::IsNeedCancel()
{
    int iCtrlCmd = HraCtrlCmd::getInstance()->getCmd(m_dwTaskThreadId);
    if (iCtrlCmd == HraCtrlCmd::CmdDef::cmd_cancel)
    {
        return true;
    }

    return false;
}

HRA_Code CHostDiscoveryHelper::MergeScanRange(const std::set<std::string>& setIpRange,
                                              std::set<std::string>& setMergeResult)
{
    setMergeResult.clear();

    if (setIpRange.empty())
    {
        return HRA_OK;
    }

    // process first elem
    for (auto& iter = setIpRange.begin(); iter != setIpRange.end(); ++iter)
    {
        std::string strIpRange = *iter;

        CIpRangeParser ipRangeParser(strIpRange);

        if (!ipRangeParser.Parse())
        {
            LOG_ERROR("parse ip range failed, %s", strIpRange.c_str());
            return HRA_FAILED;
        }

        std::vector<std::string> vecIpList;
        ipRangeParser.RangeToList(vecIpList, false);

        setMergeResult.insert(vecIpList.begin(), vecIpList.end());
    }

    return HRA_OK;
}

HRA_Code CHostDiscoveryHelper::IsInAvailableIpRange(const std::string& strNICIp, const std::string& strNICSubNetMask,
                                                    const std::string& strTargetIp, bool& bIsInAvailableRange)
{
    bIsInAvailableRange = false;

    CIpRangeParser hostIpRangeParser(strNICIp, strNICSubNetMask);

    if (!hostIpRangeParser.Parse())
    {
        LOG_ERROR("parse ip range failed, ip: %s, subnetMask: %s", strNICIp.c_str(), strNICSubNetMask.c_str());
        return HRA_FAILED;
    }

    // is loopback
    if (IpAddrHelper::IsLoopback(strTargetIp))
    {
        LOG_DEBUG("loopback addr");
        return HRA_OK;
    }

    // is 0.0.0.0
    if (IpAddrHelper::IsUnspecified(strTargetIp))
    {
        LOG_DEBUG("Unspecified addr");
        return HRA_OK;
    }

    // is multi cast ip
    if (IpAddrHelper::IsMulticastAddress(strTargetIp))
    {
        LOG_DEBUG("multicast addr");
        return HRA_OK;
    }

    // check to be scan ip is in scanner's available ip range
    HRA_Code retCode = hostIpRangeParser.IsInAvailableRange(strTargetIp, bIsInAvailableRange);
    if (retCode != HRA_OK)
    {
        LOG_DEBUG("IsInAvailableRange failed, retCode: %d", retCode);
        return retCode;
    }

    return HRA_OK;
}

HRA_Code CHostDiscoveryHelper::MergeScanRangeWithScannerNetInfo(const std::string& strScannerIp,
                                                                const std::string& strScannerSubNetMask,
                                                                const std::string& strTargetIpRange,
                                                                std::vector<std::string>& vecToBeScanIP)
{
    CIpRangeParser targetIpRangeParser(strTargetIpRange);

    if (!targetIpRangeParser.Parse())
    {
        LOG_ERROR("parse ip range failed, %s", strTargetIpRange.c_str());
        return HRA_FAILED;
    }

    CIpRangeParser hostIpRangeParser(strScannerIp, strScannerSubNetMask);

    if (!hostIpRangeParser.Parse())
    {
        LOG_ERROR("parse ip range failed, ip: %s, subnetMask: %s", strScannerIp.c_str(), strScannerSubNetMask.c_str());
        return HRA_FAILED;
    }

    // convert to list
    std::vector<std::string> vecHostIpRange;

    // remove network addr and broadcast addr of scanner
    hostIpRangeParser.RangeToList(vecHostIpRange);

    // use target ip as key to check is in scanner subnet range or not
    // target ip can not same as scanner's network ip or broadcast ip
    for (auto& hostIpRangeIter = vecHostIpRange.begin(); hostIpRangeIter != vecHostIpRange.end(); ++hostIpRangeIter)
    {
        std::string strCurHostIp = *hostIpRangeIter;

        // is loopback
        if (IpAddrHelper::IsLoopback(strCurHostIp))
        {
            continue;
        }

        // is 0.0.0.0
        if (IpAddrHelper::IsUnspecified(strCurHostIp))
        {
            continue;
        }

        // is multi cast ip
        if (IpAddrHelper::IsMulticastAddress(strCurHostIp))
        {
            continue;
        }

        // check to be scan ip is in scanner's available ip range
        if (!targetIpRangeParser.IsInRange(strCurHostIp))
        {
            continue;
        }

        // is scanner ip
        if (strScannerIp == strCurHostIp)
        {
            continue;
        }

        vecToBeScanIP.push_back(strCurHostIp);
    }

    return HRA_OK;
}

void CHostDiscoveryHelper::InsertScanResult(const CHostDiscoveryInfo& hostDiscoveryInfo)
{
    std::unique_lock<std::mutex> lock(m_mutexScanResult);

    std::string strIpAddr  = hostDiscoveryInfo.strScannerIp;
    std::string strMacAddr = hostDiscoveryInfo.strScannerMac;

    LOG_DEBUG("InsertScanResult: scanner ip: %s, scanner mac: %s, host ip: %s, host mac: %s", strIpAddr.c_str(),
              strMacAddr.c_str(), hostDiscoveryInfo.strIP.c_str(), hostDiscoveryInfo.strMacAddr.c_str());

    m_setScanResult.insert(hostDiscoveryInfo);
}

bool CHostDiscoveryHelper::PopToBeScanIp(std::string& strToBeScanIp)
{
    std::unique_lock<std::mutex> lock(m_mutexToBeScanIp);

    if (m_vecToBeScanIp.empty())
    {
        LOG_DEBUG("no element in to be scan ip");
        return false;
    }

    strToBeScanIp = m_vecToBeScanIp.back();

    m_vecToBeScanIp.pop_back();

    return true;
}

void CHostDiscoveryHelper::WaitAllWorkThreadTerminate()
{
    if (m_vecHandle.empty() || m_vecHandle.size() != TOTAL_THREAD_COUNT)
    {
        return;
    }

    HANDLE hHandleList[TOTAL_THREAD_COUNT] = {0};

    for (int i = 0; i < TOTAL_THREAD_COUNT; ++i)
    {
        hHandleList[i] = m_vecHandle[i];
    }

    DWORD dwWait = WaitForMultipleObjects(TOTAL_THREAD_COUNT, hHandleList, TRUE, INFINITE);

    LOG_DEBUG("wait all work thread terminate, dwWait: %d", dwWait);
    if (dwWait == WAIT_FAILED)
    {
        LOG_ERROR("wait all work thread terminate failed, errCode: %d", GetLastError());
    }

    for (int i = 0; i < TOTAL_THREAD_COUNT; i++)
    {
        CloseHandle(hHandleList[i]);
    }

    m_vecHandle.clear();
}
