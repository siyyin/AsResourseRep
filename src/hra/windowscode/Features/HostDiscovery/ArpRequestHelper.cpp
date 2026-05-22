#include "ArpRequestHelper.h"
#include "HostDiscoveryHelper.h"
#include "MacAddrHelper.h"
#include <utility/Logger.h>

#include <Windows.h>
#include <WinSock2.h>
#include <iphlpapi.h>

#include <string>


CArpRequestHelper::CArpRequestHelper(const std::string& strScannerIp, const std::string& strScannerMac, const std::string& strDestIp)
    : m_strScannerIp(strScannerIp), m_strScannerMac(strScannerMac), m_strDestIp(strDestIp)
{
}

CArpRequestHelper::~CArpRequestHelper()
{
}

HRA_Code CArpRequestHelper::SendArpReq(CHostDiscoveryInfo& hostDiscoveryInfo)
{
    // check parameter
    if (m_strScannerIp.empty() || m_strDestIp.empty() || m_strScannerMac.empty())
    {
        LOG_DEBUG("invalid paramter");
        return HRA_BAD_PARAM;
    }

    DWORD dwRetVal    = 0;
    IPAddr DestIp     = 0;
    IPAddr SrcIp      = 0;   /* default for src ip */
    ULONG MacAddr[2]  = {0}; /* for 6-byte hardware addresses */
    ULONG PhysAddrLen = 6;   /* default to length of six bytes */
    BYTE* bPhysAddr   = NULL;
    unsigned int i    = 0;

    SrcIp  = inet_addr(m_strScannerIp.c_str());
    DestIp = inet_addr(m_strDestIp.c_str());

    memset(&MacAddr, 0xff, sizeof(MacAddr));

    // send arp request
    dwRetVal = SendARP(DestIp, SrcIp, &MacAddr, &PhysAddrLen);

    if (dwRetVal != NO_ERROR)
    {
        LOG_DEBUG("SendArp failed with error: %d, src ip: %s, host ip: %s", dwRetVal, m_strScannerIp.c_str(),
            m_strDestIp.c_str());
        return HRA_FAILED;
    }

    bPhysAddr = (BYTE*)&MacAddr;

    if (PhysAddrLen == 0)
    {
        LOG_DEBUG("SendArp succss, but mac address length is zero, src ip: %s, host ip: %s", m_strScannerIp.c_str(),
            m_strDestIp.c_str());
        return HRA_FAILED;
    }

    // convert mac addr to string
    std::string strMacAddr;

    MacAddrHelper::NormalizeMacAddr(bPhysAddr, PhysAddrLen, strMacAddr);

    LOG_DEBUG("send ARP success: src ip: %s, host ip: %s, host MAC addr: %s", m_strScannerIp.c_str(),
              m_strDestIp.c_str(), strMacAddr.c_str());

    hostDiscoveryInfo.strIP                = m_strDestIp;
    hostDiscoveryInfo.eHostDiscoveryMethod = HostDiscoveryMethod::Arp;
    hostDiscoveryInfo.strMacAddr           = strMacAddr;

    // arp can not known target os type now
    hostDiscoveryInfo.strHostName     = "";
    hostDiscoveryInfo.strScannerIp    = m_strScannerIp;
    
    MacAddrHelper::NormalizeMacAddr(m_strScannerMac, hostDiscoveryInfo.strScannerMac);

    return HRA_OK;
}
