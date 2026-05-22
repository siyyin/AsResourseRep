#pragma once
#include "utility/comm.h"
#include <string>
#include <vector>
#include <regex>

#include <WinSock2.h>

namespace IpAddrHelper
{
in_addr toInAddrNetworkOrder(unsigned int ipLittleEnd);

in_addr toInAddrHostOrder(unsigned int ipLittleEnd);

void ConvertHostOrderInAddrToString(const in_addr& inAddrHostOrder, std::string& strIP);
void ConvertNetOrderInAddrToString(const in_addr& inAddrNetOrder, std::string& strIP);

bool ConvertStrToNetWorkOrderBin(const std::string& strIP, in_addr& inAddr);
bool ConvertStrToHostOrderBin(const std::string& strIP, in_addr& inAddr);

int CompareHostOrderInAddr(const in_addr& inAddrA, const in_addr& inAddrB);

bool VerifySubNetMask(const std::string& strSubNetMask);

void ConvertNetworkOrderToHost(const in_addr& inAddrNetworkOrder, in_addr& inAddrHostOrder);

bool IsLoopback(const std::string& strIp);

bool IsUnspecified(const std::string& strIp);

bool IsMulticastAddress(const std::string& strIp);
}; // namespace IpAddrHelper

enum IpRangeType
{
    Invalid         = 0,
    SingleIp        = 1,
    CIDRStyle       = 2,
    DashStyle       = 3,
    SubNetMaskStyle = 4
};

class CIpRangeParser
{
public:
    // support format:
    // 192.168.1.121(single ip)
    // 192.168.1.0/24(ip range)
    // 192.168.1.1-192.168.1.245(ip range)
    explicit CIpRangeParser(const std::string& strIpRange);

    CIpRangeParser(const std::string& strIp, const std::string& strSubNetMask);

    virtual ~CIpRangeParser(){};

private:
    CIpRangeParser(const CIpRangeParser&){};
    CIpRangeParser& operator=(const CIpRangeParser&){};

public:
    bool Parse();
    bool IsInRange(const std::string& strIp);

    // network addr and boradcast addr is not available addr
    HRA_Code IsInAvailableRange(const std::string& strIp, bool& bIsInAvailableRange);

    void RangeToList(std::vector<std::string>& vecRangeList, bool bTryDelUnavailableAddr = true);

    bool CalcCidrNumOfSubnetMask(int& iCidrNum);

    bool ConvertSubnetStyleToCidrStyle(std::string& strCidrStyle);

private:
    bool ParseDashStyle(const std::string& strIpRange);
    bool ParseCIDRStyle(const std::string& strIpRange);
    bool ParseSubNetMaskStyle(const std::string& strIp, const std::string& strSubNetMask);

private:
    // support format:
    // 192.168.1.121(single ip)
    // 192.168.1.0/24(ip range)
    // 192.168.1.1-192.168.1.245(ip range)
    std::string m_strIpRange;

    std::string m_strIp;
    std::string m_strSubNetMask;

    in_addr m_ipStartHostOrder;
    in_addr m_ipEndHostOrder;

    IpRangeType m_eIpRangeType;
};
