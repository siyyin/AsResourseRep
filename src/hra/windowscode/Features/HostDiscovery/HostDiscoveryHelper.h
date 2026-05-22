#pragma once
#include "NICInfoHelper.h"

#include <json/json.h>

#include <pugixml/pugixml.hpp>

#include <Windows.h>

#include <string>
#include <set>
#include <atomic>
#include <thread>
#include <vector>
#include <mutex>
#include <string>

enum HostDiscoveryMethod
{
    Arp  = 1,
    Ping = 2,
    Nmap = 3
};

enum HostDiscoveryScanProtocol
{
    TCP  = 1,
    UDP  = 2,
    STCP = 3
};

class HostDiscoveryScanParamItem
{
public:
    HostDiscoveryScanParamItem()
    {
    }

public:
    HostDiscoveryScanProtocol eProtocol;
    std::vector<std::string> vecPorts;
};

class HostDiscoveryScanParam
{
public:
    HostDiscoveryScanParam()
        : bDeepScan(false)
    {
    }

public:
    bool bDeepScan;
    std::vector<int> vecAgentPorts;
    std::vector<HostDiscoveryScanParamItem> vecScanItem;
};

class CHostPortInfo
{
public:
    std::string strProtocol;
    int iPortNum;

public:
    void ToString(std::string& str) const;
};

// the guess os info
class CHostOsProbablyInfo
{
public:
    std::string strOsType;
    std::string strDeviceType;
    std::string strVendor;
    std::string strOsFamily;
    // confidence value of probability
    int iAccuracy;
};

class CHostDiscoveryInfo
{
public:
    CHostDiscoveryInfo()
        : iOpenAgentPort(-1)
        ,iAssignIp(-1)
    {
    }

public:
    std::string strIP;
    std::string strMacAddr;
    std::string strMacVendor;
    std::string strHostName;
    CHostOsProbablyInfo osProbablyInfo;
    HostDiscoveryMethod eHostDiscoveryMethod;
    std::string strScannerIp;
    std::string strScannerMac;
    std::vector<CHostPortInfo> vecPortInfo;
    int iOpenAgentPort;
    int iAssignIp;

public:
    void ToJson(Json::Value& jsonVal);
    void ToString(std::string& str) const;
};
bool operator<(const CHostDiscoveryInfo& left, const CHostDiscoveryInfo& right);

class CProbeHostThreadArg
{
public:
    std::string strScannerMac;
    std::string strScannerIp;
    std::string strScannerGatewayIp;
    std::string strScannerGatewayMac;
    HostDiscoveryScanParam ptrScanParameter;
    void* ptrThis;
};

typedef std::set<CHostDiscoveryInfo> HostDiscoveryResult;

namespace HostDiscoveryHelper
{
void HostDiscoveryResultToJson(const HostDiscoveryResult& hostDiscoveryResult, Json::Value& jsonVal);
}

class CHostDiscoveryHelper
{
public:
    /// <summary>
    /// dwTaskThreadId: thread id of scan task
    /// we need this thread id to fetch is need to cancel or not
    /// from task pool
    /// </summary>
    /// <param name="dwTaskThreadId"></param>
    explicit CHostDiscoveryHelper(DWORD dwTaskThreadId);
    virtual ~CHostDiscoveryHelper();

private:
    CHostDiscoveryHelper(const CHostDiscoveryHelper&);
    CHostDiscoveryHelper& operator=(const CHostDiscoveryHelper&){};

public:
    HRA_Code DiscoveryHostInScannerSubnet(const CNICNetInfo& scannerNicInfo, HostDiscoveryMethod hostDiscoveryMethod,
                                          HostDiscoveryResult& setScanResult, HostDiscoveryScanParam& scanParameter);

    HRA_Code DiscoveryHost(const CNICNetInfo& scannerNicInfo, const std::string& strTargetIpRange,
                           HostDiscoveryMethod hostDiscoveryMethod, HostDiscoveryResult& setScanResult,
                           HostDiscoveryScanParam& scanParameter);

    // merge ip range with different ip range style
    HRA_Code MergeScanRange(const std::set<std::string>& setIpRange, std::set<std::string>& setMergeResult);

    HRA_Code IsInAvailableIpRange(const std::string& strNICIp, const std::string& strNICSubNetMask,
                                  const std::string& strTargetIp, bool& bIsInAvailableRange);

    HRA_Code MergeScanRangeWithScannerNetInfo(const std::string& strScannerIp, const std::string& strScannerSubNetMask,
                                              const std::string& strTargetIpRange,
                                              std::vector<std::string>& vecToBeScanIP);
    HRA_Code GetScannerSubnetRangeCidr(const CNICNetInfo& scannerNicInfo, std::string& strScannerSubnetRangeCidrStyle);

private:
    HRA_Code DiscoveryByArp(const CNICNetInfo& nicNetInfo, const std::string& strTargetIpRange);

    HRA_Code DiscoveryByPing(const CNICNetInfo& nicNetInfo, const std::string& strTargetIpRange);

    HRA_Code DiscoveryByNmap(const CNICNetInfo& scannerNicInfo,
                                                   const std::string& strTargetIpRange,
                                                   HostDiscoveryScanParam scanParameter);

    HRA_Code GetNICInfo(std::vector<CNICNetInfo>& vecNICInfo);

    bool IsNeedCancel();

private:
    static unsigned __stdcall ProbeHostByArpThread(void* pArguments);

    static unsigned __stdcall ProbeHostByPingThread(void* pArguments);

    static unsigned __stdcall ProbeHostByNmapThread(void* pArguments);

private:
    void InsertScanResult(const CHostDiscoveryInfo& hostDiscoveryInfo);

    bool PopToBeScanIp(std::string& strToBeScanIp);

    void WaitAllWorkThreadTerminate();

    static int __stdcall CHostDiscoveryHelper::PseudoNmapProbe(std::string strIP, int nWriteTimeOut,
                                                        int nReadTimeout, std::string& strOsVersion,
                                                        std::string& strHostName);

private:
    DWORD m_dwTaskThreadId;
    std::vector<HANDLE> m_vecHandle;

    std::atomic<bool> m_bIsRunning;

    std::vector<std::string> m_vecToBeScanIp;
    std::mutex m_mutexToBeScanIp;

    HostDiscoveryResult m_setScanResult;
    std::mutex m_mutexScanResult;
};
