#include "NICInfoHelper.h"
#include "MacAddrHelper.h"

#include <utility/comm.h>
#include <utility/Logger.h>

#include <stdlib.h>

#include <sstream>

#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3

////////////////////////////////////////////////////////////////////////////////
void CNICNetInfo::ToString(std::string& str) const
{
    std::stringstream ss;

    ss << strIPv4 << "@@" << strIPv4Mask << "@@" << strMac << "@@" << strGateWayIPv4 << "@@";
}
////////////////////////////////////////////////////////////////////////////////
HRA_Code CNICInfoHelper::GetAllNICInfo(std::vector<CNICNetInfo>& vecNICInfo)
{
    HRA_Code retCode = HRA_OK;

    vecNICInfo.clear();

    PIP_ADAPTER_ADDRESSES pAddresses = FetchAdaptersAddresses();
    if (pAddresses == NULL)
    {
        LOG_ERROR("get adapters addresses failed...");
        retCode = HRA_FAILED;
        return retCode;
    }

    // enum all NIC
    PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
    while (pCurrAddresses != NULL)
    {
        std::string strMacAddr;
        std::vector<CNICNetInfo> vecCurNetInfo;
        if (ParseNetInfo(pCurrAddresses, strMacAddr, vecCurNetInfo) == HRA_OK)
        {
            vecNICInfo.insert(vecNICInfo.end(), vecCurNetInfo.begin(), vecCurNetInfo.end());
        }

        pCurrAddresses = pCurrAddresses->Next;
    }

    free(pAddresses);

    return retCode;
}

PIP_ADAPTER_ADDRESSES CNICInfoHelper::FetchAdaptersAddresses()
{
    ULONG Iterations = 0;
    // Allocate a 15 KB buffer to start with.
    ULONG outBufLen                  = WORKING_BUFFER_SIZE;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;

    DWORD dwRetVal = NO_ERROR;

    // Set the flags to pass to GetAdaptersAddresses
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;

    // default is IPV4
    ULONG family = AF_INET;

    do
    {
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        if (pAddresses == NULL)
        {
            LOG_ERROR("Memory allocation failed for IP_ADAPTER_ADDRESSES struct");
            return NULL;
        }

        dwRetVal = GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen);

        if (dwRetVal == ERROR_BUFFER_OVERFLOW)
        {
            free(pAddresses);
            pAddresses = NULL;
        }
        else
        {
            break;
        }

        Iterations++;

    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

    if (dwRetVal != NO_ERROR)
    {
        LOG_ERROR("get adapter address failed, retval: %d", dwRetVal);
        return NULL;
    }

    return pAddresses;
}

HRA_Code CNICInfoHelper::ParseNetInfo(const IP_ADAPTER_ADDRESSES* pAdapterAddress, std::string& strMacAddr,
                                      std::vector<CNICNetInfo>& vecNetInfo)
{
    if (pAdapterAddress == NULL)
    {
        LOG_ERROR("invalid parameter");
        return HRA_BAD_PARAM;
    }

    // mac addr
    MacAddrHelper::NormalizeMacAddr(pAdapterAddress->PhysicalAddress, pAdapterAddress->PhysicalAddressLength,
                                    strMacAddr);

    if (strMacAddr.empty())
    {
        LOGW_ERROR(L"%s, can not get mac address", pAdapterAddress->FriendlyName);
        return HRA_FAILED;
    }

    // begin enum all ipv4, ipv4 mask and gateway address
    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pAdapterAddress->FirstUnicastAddress;
    PIP_ADAPTER_GATEWAY_ADDRESS pGateWay = pAdapterAddress->FirstGatewayAddress;
    PIP_ADAPTER_GATEWAY_ADDRESS pGateWayCursor;

    // no ip address means this card is not up
    // no gateway address means this card is a gateway
    if (pUnicast == NULL || pGateWay == NULL)
    {
        LOGW_WARN(L"%s, can not get unicast/gateway address", pAdapterAddress->FriendlyName);
        return HRA_FAILED;
    }

    // enumeration by unicaseIP
    while (pUnicast != NULL)
    {
        // need ip v4 only
        if (pUnicast->Address.lpSockaddr->sa_family != AF_INET)
        {
            continue;
        }

        CNICNetInfo netInfo;

        netInfo.strMac = strMacAddr;

        char szIP[MAX_PATH]   = {0};
        char szMask[MAX_PATH] = {0};
        
        inet_ntop(PF_INET, &((sockaddr_in*)pUnicast->Address.lpSockaddr)->sin_addr, szIP, sizeof(szIP));

        IPmask ipmask;
        ConvertLengthToIpv4Mask(pUnicast->OnLinkPrefixLength, &ipmask.ul);

        sprintf_s(szMask, "%d.%d.%d.%d", ipmask.b[0], ipmask.b[1], ipmask.b[2], ipmask.b[3]);

        netInfo.strIPv4     = szIP;
        netInfo.strIPv4Mask = szMask;

        // find related gateway IP
        pGateWayCursor = pGateWay;
        while (pGateWayCursor != NULL)
        {
            if (pGateWayCursor->Address.lpSockaddr->sa_family != AF_INET)
            {
                continue;
            }
            char szGateWayIP[MAX_PATH] = {0};
            inet_ntop(PF_INET, &((sockaddr_in*)pGateWayCursor->Address.lpSockaddr)->sin_addr, szGateWayIP,
                      sizeof(szGateWayIP));
            LOG_DEBUG("consider ip: %s, mask: %s, gateway: %s", szIP, szMask, szGateWayIP);
            // homogeneous subnet division testing
            IN_ADDR iaUnicast = ((sockaddr_in*)pUnicast->Address.lpSockaddr)->sin_addr;
            IN_ADDR iaGateway = ((sockaddr_in*)pGateWayCursor->Address.lpSockaddr)->sin_addr;
            
            if ((UCHAR)(ipmask.b[0] & iaUnicast.S_un.S_un_b.s_b1) ==
                    (UCHAR)(ipmask.b[0] & iaGateway.S_un.S_un_b.s_b1) &&
                (UCHAR)(ipmask.b[1] & iaUnicast.S_un.S_un_b.s_b2) ==
                    (UCHAR)(ipmask.b[1] & iaGateway.S_un.S_un_b.s_b2) &&
                (UCHAR)(ipmask.b[2] & iaUnicast.S_un.S_un_b.s_b3) ==
                    (UCHAR)(ipmask.b[2] & iaGateway.S_un.S_un_b.s_b3) &&
                (UCHAR)(ipmask.b[3] & iaUnicast.S_un.S_un_b.s_b4) == (UCHAR)(ipmask.b[3] & iaGateway.S_un.S_un_b.s_b4))
            {
                netInfo.strGateWayIPv4 = szGateWayIP;
                LOG_INFO("confirm local address info: %s , %s ", szIP, szGateWayIP);
                vecNetInfo.push_back(netInfo);
                break;
            }

            pGateWayCursor         = pGateWayCursor->Next;
            // assign a random gateway to this unicast ip
            if (pGateWayCursor == NULL)
            {
                netInfo.strGateWayIPv4 = szGateWayIP;
                LOG_INFO("confirm the random address info: %s , %s ", szIP, szGateWayIP);
                vecNetInfo.push_back(netInfo);
            }
        }

        pUnicast = pUnicast->Next;
    }

    return HRA_OK;
}

HRA_Code CNICInfoHelper::GetActiveIpByPeerIp(const std::string& strPeerIpAddr, int iPort, std::string& strActiveIp)
{
    HRA_Code retCode = HRA_FAILED;
#ifdef _WIN32
    SOCKET fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == INVALID_SOCKET)
    {
        LOG_DEBUG("socket init fd invalid");
        retCode = HRA_SOCKET_ERROR;
        return retCode;
    }
#else
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
    {
        LOG_DEBUG("socket init fd invalid");
        retCode = HRA_SOCKET_ERROR;
        return retCode;
    }
#endif

    int ret       = 0;
    socklen_t len = sizeof(struct sockaddr);
    struct sockaddr_in saddr;
    struct sockaddr_in name;

    memset(&saddr, 0, sizeof(struct sockaddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port   = htons(iPort);

#ifdef _WIN32
    saddr.sin_addr.s_addr = inet_addr(strPeerIpAddr.c_str()); // for xp/2003
#else
    char ip[IP_SIZE] = {0};
    int iRet         = GetIPByDomian(strPeerIpAddr.c_str(), ip);
    if (0 == iRet)
        saddr.sin_addr.s_addr = inet_addr(ip);
    else
        saddr.sin_addr.s_addr = inet_addr(strPeerIpAddr.c_str());
#endif

    ret = connect(fd, (struct sockaddr*)&saddr, len);

    if (ret == -1)
    {
        LOG_DEBUG("connect failed.");
        retCode = HRA_SOCKET_ERROR;
        goto out;
    }

    ret = getsockname(fd, (struct sockaddr*)&name, &len);

    if (ret == -1)
    {
        LOG_DEBUG("getsockname failed.");
        retCode = HRA_SOCKET_ERROR;
        goto out;
    }

    strActiveIp = inet_ntoa(name.sin_addr);
    LOG_DEBUG("get strActiveIp: %s", strActiveIp.c_str());

    retCode = HRA_OK;

out:
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif

    return retCode;
}

HRA_Code CNICInfoHelper::FindAcitveNICByIp(const std::string& strPeerIpAddr, int iPort, CNICNetInfo& nicInfo)
{
    std::string strActiveIp;
    HRA_Code retCode = GetActiveIpByPeerIp(strPeerIpAddr, iPort, strActiveIp);

    if (retCode != HRA_OK)
    {
        LOG_ERROR("get active ip failed, peerIp: %s, iPort: %d", strPeerIpAddr.c_str(), iPort);
        return retCode;
    }

    /////////////////////////////////////////////////////////
    std::vector<CNICNetInfo> vecNicInfo;
    retCode = GetAllNICInfo(vecNicInfo);

    if (retCode != HRA_OK)
    {
        LOG_ERROR("get all NIC info failed, peerIp: %s, iPort: %d", strPeerIpAddr.c_str(), iPort);
        return retCode;
    }

    if (vecNicInfo.empty())
    {
        LOG_DEBUG("nic info is empty");
        return HRA_FAILED;
    }

    typedef std::vector<CNICNetInfo>::iterator VecIter;
    for (VecIter iter = vecNicInfo.begin(); iter != vecNicInfo.end(); ++iter)
    {
        CNICNetInfo& curNicNetInfo = *iter;

        LOG_DEBUG("curNicNetInfo ip: %s", curNicNetInfo.strIPv4.c_str());

        if (strActiveIp == curNicNetInfo.strIPv4)
        {
            nicInfo = curNicNetInfo;
            return HRA_OK;
        }
    }

    return HRA_FAILED;
}