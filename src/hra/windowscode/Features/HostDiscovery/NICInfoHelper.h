#pragma once

#include "utility/comm.h"
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#include <map>
#include <vector>
#include <string>

class CNICNetInfo
{
public:
    std::string strIPv4;
    std::string strMac;
    std::string strIPv4Mask;
    std::string strGateWayIPv4;

    void ToString(std::string& str) const;
};

union IPmask {
    ULONG ul;
    BYTE b[4];
};

class CNICInfoHelper
{
public:
    CNICInfoHelper(){};
    virtual ~CNICInfoHelper(){};

public:
    // key: mac addr(low case)
    HRA_Code GetAllNICInfo(std::vector<CNICNetInfo>& vecNICInfo);

    HRA_Code FindAcitveNICByIp(const std::string& strPeerIpAddr, int iPort, CNICNetInfo& nicInfo);

    HRA_Code GetActiveIpByPeerIp(const std::string& strPeerIpAddr, int iPort, std::string& strActiveIp);

private:
    // caller need free memory
    PIP_ADAPTER_ADDRESSES FetchAdaptersAddresses();
    HRA_Code ParseNetInfo(const IP_ADAPTER_ADDRESSES* pAdapterAddress, std::string& strMac,
                          std::vector<CNICNetInfo>& vecNetInfo);
};
