#include "IpRangeParser.h"
#include "utility/Logger.h"

#include <ws2tcpip.h>

#include <sstream>

#define IP_BODY_REGEX_STR                                                                                              \
    "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-"  \
    "9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"

#define IP_RANGE_SINGLE_IP "^" IP_BODY_REGEX_STR "$"

#define IP_RANGE_REGEX_LINK_STYLE "^(" IP_BODY_REGEX_STR ")-(" IP_BODY_REGEX_STR ")$"
#define IP_RANGE_REGEX_LINK_STYLE_CAPTURE_NUM 11

#define IP_RANGE_REGEX_CIDR_STYLE "^(" IP_BODY_REGEX_STR ")(\\/([0-9]|[1-2][0-9]|3[0-2]))$"
#define IP_RANGE_REGEX_CIDR_STYLE_CAPTURE_NUM 8

namespace IpAddrHelper
{
in_addr toInAddrNetworkOrder(unsigned int ipLittleEnd)
{
    in_addr addr;

    addr.S_un.S_un_b.s_b4 = 0xff & ipLittleEnd;
    ipLittleEnd >>= 8;
    addr.S_un.S_un_b.s_b3 = 0xff & ipLittleEnd;
    ipLittleEnd >>= 8;
    addr.S_un.S_un_b.s_b2 = 0xff & ipLittleEnd;
    ipLittleEnd >>= 8;
    addr.S_un.S_un_b.s_b1 = 0xff & ipLittleEnd;

    return addr;
}

in_addr toInAddrHostOrder(unsigned int ipLittleEnd)
{
    in_addr addr;

    addr.S_un.S_un_b.s_b1 = 0xff & ipLittleEnd;
    ipLittleEnd >>= 8;
    addr.S_un.S_un_b.s_b2 = 0xff & ipLittleEnd;
    ipLittleEnd >>= 8;
    addr.S_un.S_un_b.s_b3 = 0xff & ipLittleEnd;
    ipLittleEnd >>= 8;
    addr.S_un.S_un_b.s_b4 = 0xff & ipLittleEnd;

    return addr;
}

void ConvertHostOrderInAddrToString(const in_addr& inAddrHostOrder, std::string& strIP)
{
    char szTemp[MAX_PATH] = {0};

    sprintf_s(szTemp, "%d.%d.%d.%d", inAddrHostOrder.S_un.S_un_b.s_b4, inAddrHostOrder.S_un.S_un_b.s_b3,
              inAddrHostOrder.S_un.S_un_b.s_b2, inAddrHostOrder.S_un.S_un_b.s_b1);

    strIP = szTemp;
}

void ConvertNetOrderInAddrToString(const in_addr& inAddrNetOrder, std::string& strIP)
{
    char szTemp[MAX_PATH] = {0};

    sprintf_s(szTemp, "%d.%d.%d.%d", inAddrNetOrder.S_un.S_un_b.s_b1, inAddrNetOrder.S_un.S_un_b.s_b2,
              inAddrNetOrder.S_un.S_un_b.s_b3, inAddrNetOrder.S_un.S_un_b.s_b4);

    strIP = szTemp;
}

bool ConvertStrToNetWorkOrderBin(const std::string& strIP, in_addr& inAddr)
{
    int iRet = 0;
    in_addr addrIp;
    iRet = inet_pton(AF_INET, strIP.c_str(), &addrIp);

    if (iRet != 1)
    {
        LOG_ERROR("invalid ip address: %s", strIP.c_str());
        return false;
    }

    inAddr = addrIp;

    return true;
}
bool ConvertStrToHostOrderBin(const std::string& strIP, in_addr& inAddr)
{
    int iRet = 0;
    in_addr addrIp;
    iRet = inet_pton(AF_INET, strIP.c_str(), &addrIp);

    if (iRet != 1)
    {
        LOG_ERROR("invalid ip address: %s", strIP.c_str());
        return false;
    }

    unsigned long ulHostOrder = ntohl(addrIp.S_un.S_addr);

    inAddr.S_un.S_addr = ulHostOrder;

    return true;
}
int CompareHostOrderInAddr(const in_addr& inAddrA, const in_addr& inAddrB)
{
    if (inAddrA.S_un.S_un_b.s_b4 != inAddrB.S_un.S_un_b.s_b4)
    {
        return inAddrA.S_un.S_un_b.s_b4 - inAddrB.S_un.S_un_b.s_b4;
    }

    if (inAddrA.S_un.S_un_b.s_b3 != inAddrB.S_un.S_un_b.s_b3)
    {
        return inAddrA.S_un.S_un_b.s_b3 - inAddrB.S_un.S_un_b.s_b3;
    }

    if (inAddrA.S_un.S_un_b.s_b2 != inAddrB.S_un.S_un_b.s_b2)
    {
        return inAddrA.S_un.S_un_b.s_b2 - inAddrB.S_un.S_un_b.s_b2;
    }

    if (inAddrA.S_un.S_un_b.s_b1 != inAddrB.S_un.S_un_b.s_b1)
    {
        return inAddrA.S_un.S_un_b.s_b1 - inAddrB.S_un.S_un_b.s_b1;
    }

    return 0;
}
bool VerifySubNetMask(const std::string& strSubNetMask)
{
    std::stringstream smask(strSubNetMask);
    std::string temp;

    std::vector<int> vecOctetsMask;

    while (getline(smask, temp, '.'))
    {
        vecOctetsMask.push_back(atoi(temp.c_str()));
    }

    if (vecOctetsMask.size() != 4)
    {
        return false;
    }

    for (int i = 0; i < vecOctetsMask.size(); i++)
    {
        if (vecOctetsMask[i] == 0 || vecOctetsMask[i] == 128 || vecOctetsMask[i] == 192 || vecOctetsMask[i] == 224 ||
            vecOctetsMask[i] == 240 || vecOctetsMask[i] == 248 || vecOctetsMask[i] == 252 || vecOctetsMask[i] == 254 ||
            vecOctetsMask[i] == 255)
        {
            continue;
        }
        else
        {
            return false;
        }
    }

    return true;
}
void ConvertNetworkOrderToHost(const in_addr& inAddrNetworkOrder, in_addr& inAddrHostOrder)
{
    inAddrHostOrder.S_un.S_addr = ntohl(inAddrNetworkOrder.S_un.S_addr);
}

bool IsLoopback(const std::string& strIp)
{
    in_addr inAddrNetworkOrder = {0};
    if (!ConvertStrToNetWorkOrderBin(strIp, inAddrNetworkOrder))
    {
        return false;
    }

    return (0x0100007f /*LOOPBACK_ADDR network order*/ == inAddrNetworkOrder.S_un.S_addr);
}
bool IsUnspecified(const std::string& strIp)
{
    in_addr inAddrNetworkOrder = {0};
    if (!ConvertStrToHostOrderBin(strIp, inAddrNetworkOrder))
    {
        return false;
    }

    return (INADDR_ANY == inAddrNetworkOrder.S_un.S_addr);
}

// https://github.com/torvalds/linux/blob/master/include/uapi/linux/in.h#L290
// A valid multicast IPv4 address is between 224.0.0.0 and 239.255.255.255.
// Checking the leading byte to make sure it is between 224 and 239, inclusive, is the obvious answer.
// But recognizing that 224 = 0xE0 and 239 = 0xEF, checking the first nibble against 0xE is sufficient.
bool IsMulticastAddress(const std::string& strIp)
{
    in_addr addrHostOrder = {0};

    if (!ConvertStrToHostOrderBin(strIp, addrHostOrder))
    {
        return false;
    }

    unsigned long address = addrHostOrder.S_un.S_addr;

    return (address & 0xF0000000) == 0xE0000000;
}
}; // namespace IpAddrHelper

CIpRangeParser::CIpRangeParser(const std::string& strIpRange)
    : m_strIpRange(strIpRange)
    , m_eIpRangeType(IpRangeType::Invalid)
{
    memset(&m_ipStartHostOrder, 0, sizeof(m_ipStartHostOrder));
    memset(&m_ipEndHostOrder, 0, sizeof(m_ipEndHostOrder));
}

CIpRangeParser::CIpRangeParser(const std::string& strIp, const std::string& strSubNetMask)
    : m_strIp(strIp)
    , m_strSubNetMask(strSubNetMask)
    , m_eIpRangeType(IpRangeType::Invalid)
{
    memset(&m_ipStartHostOrder, 0, sizeof(m_ipStartHostOrder));
    memset(&m_ipEndHostOrder, 0, sizeof(m_ipEndHostOrder));
}

/// <summary>
/// 10.21.142.50-10.21.142.5
/// 10.21.142.50-10.21.142.50
/// 10.21.142.50/33
/// 10.21.142.50/24
/// 10.21.142.50-10.21.142.55
/// 10.21.142.50
/// </summary>
/// <returns></returns>
bool CIpRangeParser::Parse()
{
    std::regex ipBodyRegex(IP_RANGE_SINGLE_IP, std::regex_constants::ECMAScript | std::regex_constants::icase);

    std::regex ipRangeLinkStyleRegex(IP_RANGE_REGEX_LINK_STYLE,
                                     std::regex_constants::ECMAScript | std::regex_constants::icase);

    std::regex ipRangeCidrStyleRegex(IP_RANGE_REGEX_CIDR_STYLE,
                                     std::regex_constants::ECMAScript | std::regex_constants::icase);

    // ip and submask firstly
    if (!m_strIp.empty() && !m_strSubNetMask.empty())
    {
        if (std::regex_match(m_strIp, ipBodyRegex) && IpAddrHelper::VerifySubNetMask(m_strSubNetMask))
        {
            return ParseSubNetMaskStyle(m_strIp, m_strSubNetMask);
        }
        else
        {
            LOG_ERROR("unrecognize ip range: %s, %s", m_strIp.c_str(), m_strSubNetMask.c_str());

            return false;
        }
    }

    // single ip style
    if (std::regex_match(m_strIpRange, ipBodyRegex))
    {
        int iRet = 0;
        in_addr addr;
        iRet = inet_pton(AF_INET, m_strIpRange.c_str(), &addr);

        if (iRet != 1)
        {
            LOG_ERROR("invalid ip address: %s", m_strIpRange.c_str());
            return false;
        }

        IpAddrHelper::ConvertNetworkOrderToHost(addr, m_ipStartHostOrder);
        IpAddrHelper::ConvertNetworkOrderToHost(addr, m_ipEndHostOrder);

        std::string strIpStart;
        IpAddrHelper::ConvertHostOrderInAddrToString(m_ipStartHostOrder, strIpStart);

        std::string strIpEnd;
        IpAddrHelper::ConvertHostOrderInAddrToString(m_ipEndHostOrder, strIpEnd);

        LOG_DEBUG("ip start: %s, ip end: %s", strIpStart.c_str(), strIpEnd.c_str());

        m_eIpRangeType = IpRangeType::SingleIp;

        return true;
    }

    // link style ip range: a1.b1.c1.d1-a2.b2.c2.d2
    if (std::regex_match(m_strIpRange, ipRangeLinkStyleRegex))
    {
        return ParseDashStyle(m_strIpRange);
    }

    // DIDR style
    if (std::regex_match(m_strIpRange, ipRangeCidrStyleRegex))
    {
        return ParseCIDRStyle(m_strIpRange);
    }

    LOG_ERROR("unrecognize ip range: %s", m_strIpRange.c_str());

    return false;
}

bool CIpRangeParser::IsInRange(const std::string& strIp)
{
    // check is valid IP
    std::regex ipBodyRegex(IP_RANGE_SINGLE_IP, std::regex_constants::ECMAScript | std::regex_constants::icase);

    if (!std::regex_match(strIp, ipBodyRegex))
    {
        LOG_ERROR("invalid IP: %s", strIp.c_str());
        return false;
    }

    // convert to bin
    in_addr inAddr;
    memset(&inAddr, 0, sizeof(in_addr));
    if (!IpAddrHelper::ConvertStrToHostOrderBin(strIp, inAddr))
    {
        LOG_ERROR("invalid IP: %s", strIp.c_str());
        return false;
    }
    // start > strIP
    if (IpAddrHelper::CompareHostOrderInAddr(m_ipStartHostOrder, inAddr) > 0)
    {
        return false;
    }

    // end < strIp
    if (IpAddrHelper::CompareHostOrderInAddr(m_ipEndHostOrder, inAddr) < 0)
    {
        return false;
    }

    return true;
}

HRA_Code CIpRangeParser::IsInAvailableRange(const std::string& strIp, bool& bIsInAvailableRange)
{
    // check is valid IP
    std::regex ipBodyRegex(IP_RANGE_SINGLE_IP, std::regex_constants::ECMAScript | std::regex_constants::icase);

    if (!std::regex_match(strIp, ipBodyRegex))
    {
        LOG_ERROR("invalid IP: %s", strIp.c_str());
        return HRA_BAD_PARAM;
    }

    // convert to bin
    in_addr inAddr;
    memset(&inAddr, 0, sizeof(in_addr));
    if (!IpAddrHelper::ConvertStrToHostOrderBin(strIp, inAddr))
    {
        LOG_ERROR("invalid IP: %s", strIp.c_str());
        return HRA_BAD_PARAM;
    }

    in_addr ipStartHostOrder = m_ipStartHostOrder;
    in_addr ipEndHostOrder   = m_ipEndHostOrder;

    // only CIDR and subnet mask style can recognize network and broadcast addr
    if (m_eIpRangeType != IpRangeType::CIDRStyle && m_eIpRangeType != IpRangeType::SubNetMaskStyle)
    {
        LOG_ERROR("invalid IP RANGE STYLE: %d", m_eIpRangeType);
        return HRA_BAD_PARAM;
    }

    ipStartHostOrder.S_un.S_un_b.s_b1 += 1;
    ipEndHostOrder.S_un.S_un_b.s_b1 -= 1;

    // start > strIP
    if (IpAddrHelper::CompareHostOrderInAddr(ipStartHostOrder, inAddr) > 0)
    {
        bIsInAvailableRange = false;
        return HRA_OK;
    }

    // end < strIp
    if (IpAddrHelper::CompareHostOrderInAddr(ipEndHostOrder, inAddr) < 0)
    {
        bIsInAvailableRange = false;
        return HRA_OK;
    }

    bIsInAvailableRange = true;

    return HRA_OK;
}

void CIpRangeParser::RangeToList(std::vector<std::string>& vecRangeList, bool bTryDelUnavailableAddr)
{
    in_addr inAddrStartHostOrder = m_ipStartHostOrder;
    in_addr inAddrEndHostOrder   = m_ipEndHostOrder;

    unsigned long ulIpAddrStart = inAddrStartHostOrder.S_un.S_addr;
    unsigned long ulIpAddrEnd   = inAddrEndHostOrder.S_un.S_addr;

    // clear result set
    vecRangeList.clear();

    if (bTryDelUnavailableAddr)
    {
        // only CIDR and subnet mask style can recognize network and broadcast addr
        if (m_eIpRangeType == IpRangeType::CIDRStyle || m_eIpRangeType == IpRangeType::SubNetMaskStyle)
        {
            ulIpAddrStart = inAddrStartHostOrder.S_un.S_addr + 1;
            ulIpAddrEnd   = inAddrEndHostOrder.S_un.S_addr - 1;
        }
    }

    for (unsigned long ulIp = ulIpAddrStart; ulIp <= ulIpAddrEnd; ++ulIp)
    {
        in_addr inAddr;

        inAddr.S_un.S_addr = ulIp;

        std::string strIp;
        IpAddrHelper::ConvertHostOrderInAddrToString(inAddr, strIp);

        vecRangeList.push_back(strIp);
    }
}

bool CIpRangeParser::ParseDashStyle(const std::string& strIpRange)
{
    std::regex ipRangeLinkStyleRegex(IP_RANGE_REGEX_LINK_STYLE,
                                     std::regex_constants::ECMAScript | std::regex_constants::icase);

    std::smatch matchs;

    if (!std::regex_match(strIpRange, matchs, ipRangeLinkStyleRegex))
    {
        LOG_ERROR("invalid ip range: %s", strIpRange.c_str());
        return false;
    }

    size_t size = matchs.size();

    if (size != IP_RANGE_REGEX_LINK_STYLE_CAPTURE_NUM)
    {
        LOG_ERROR("invalid ip range: %s, %d", strIpRange.c_str(), size);
        return false;
    }

    /*
     *   regex capture group result:
     *   0	10.21.142.50-10.21.142.55
     *   1	10.21.142.50
     *   2	10
     *   3	21
     *   4	142
     *   5	50
     *   6	10.21.142.55
     *   7	10
     *   8	21
     *   9	142
     *   10	55
     */

    std::string strIpRangeStart = matchs[1];
    std::string strIpRangeEnd   = matchs[6];

    // convert ip to bin format
    in_addr addrIpRangeStart;
    memset(&addrIpRangeStart, 0, sizeof(in_addr));
    if (!IpAddrHelper::ConvertStrToHostOrderBin(strIpRangeStart, addrIpRangeStart))
    {
        LOG_ERROR("invalid IP: %s", strIpRangeStart.c_str());
        return false;
    }

    in_addr addrIpRangeEnd;
    memset(&addrIpRangeEnd, 0, sizeof(in_addr));
    if (!IpAddrHelper::ConvertStrToHostOrderBin(strIpRangeEnd, addrIpRangeEnd))
    {
        LOG_ERROR("invalid IP: %s", strIpRangeEnd.c_str());
        return false;
    }

    // copy to member attribute
    if (addrIpRangeStart.S_un.S_addr <= addrIpRangeEnd.S_un.S_addr)
    {
        m_ipStartHostOrder = addrIpRangeStart;
        m_ipEndHostOrder   = addrIpRangeEnd;
    }
    else
    {
        m_ipStartHostOrder = addrIpRangeEnd;
        m_ipEndHostOrder   = addrIpRangeStart;
    }

    std::string strIpStart;
    IpAddrHelper::ConvertHostOrderInAddrToString(m_ipStartHostOrder, strIpStart);

    std::string strIpEnd;
    IpAddrHelper::ConvertHostOrderInAddrToString(m_ipEndHostOrder, strIpEnd);

    LOG_DEBUG("ip start: %s, ip end: %s", strIpStart.c_str(), strIpEnd.c_str());

    m_eIpRangeType = IpRangeType::DashStyle;

    return true;
}

bool CIpRangeParser::ParseCIDRStyle(const std::string& strIpRange)
{
    std::regex ipRangeCidrStyleRegex(IP_RANGE_REGEX_CIDR_STYLE,
                                     std::regex_constants::ECMAScript | std::regex_constants::icase);

    std::smatch matchs;
    if (!std::regex_match(strIpRange, matchs, ipRangeCidrStyleRegex))
    {
        LOG_ERROR("invalid ip range: %s", strIpRange.c_str());
        return false;
    }

    size_t size = matchs.size();

    if (size != IP_RANGE_REGEX_CIDR_STYLE_CAPTURE_NUM)
    {
        LOG_ERROR("invalid ip range: %s, %d", strIpRange.c_str(), size);
        return false;
    }

    std::string strIp      = matchs[1].str();
    std::string strMaskBit = matchs[size - 1].str();

    LOG_DEBUG("ip: %s, mask bit: %s", strIp.c_str(), strMaskBit.c_str());

    // convert ip to bin format
    in_addr inAddrIP;
    memset(&inAddrIP, 0, sizeof(in_addr));
    if (!IpAddrHelper::ConvertStrToHostOrderBin(strIp, inAddrIP))
    {
        LOG_ERROR("invalid IP: %s", strIp.c_str());
        return false;
    }

    // check subnet mask range
    int iMaskBit = atoi(strMaskBit.c_str());

    // mask bit = [0,32]
    if (iMaskBit < 0 || iMaskBit > 33)
    {
        LOG_ERROR("invalid mask bit, %s", strMaskBit.c_str());
        return false;
    }

    // calculate ip range with mask
    unsigned long ulIpval      = inAddrIP.S_un.S_addr;
    unsigned long ulSubNetMask = ~(0xFFFFFFFF >> iMaskBit);

    // copy to member attribute
    m_ipStartHostOrder = IpAddrHelper::toInAddrHostOrder(ulIpval & ulSubNetMask);
    m_ipEndHostOrder   = IpAddrHelper::toInAddrHostOrder((ulIpval & ulSubNetMask) | ~ulSubNetMask);

    std::string strIpStart;
    IpAddrHelper::ConvertHostOrderInAddrToString(m_ipStartHostOrder, strIpStart);

    std::string strIpEnd;
    IpAddrHelper::ConvertHostOrderInAddrToString(m_ipEndHostOrder, strIpEnd);

    LOG_DEBUG("strIpRange: %s, ip start: %s, ip end: %s, ulSubNetMask: %lu", strIpRange.c_str(), strIpStart.c_str(),
              strIpEnd.c_str(), ulSubNetMask);

    m_eIpRangeType = IpRangeType::CIDRStyle;

    return true;
}

bool CIpRangeParser::ParseSubNetMaskStyle(const std::string& strIp, const std::string& strSubNetMask)
{
    std::regex ipBodyRegex(IP_RANGE_SINGLE_IP, std::regex_constants::ECMAScript | std::regex_constants::icase);

    if (!std::regex_match(m_strIp, ipBodyRegex))
    {
        return false;
    }

    if (!IpAddrHelper::VerifySubNetMask(m_strSubNetMask))
    {
        return false;
    }

    // convert ip to bin format
    in_addr inAddrIP;
    memset(&inAddrIP, 0, sizeof(in_addr));
    if (!IpAddrHelper::ConvertStrToHostOrderBin(strIp, inAddrIP))
    {
        LOG_ERROR("invalid IP: %s", strIp.c_str());
        return false;
    }

    // convert subnet mask to bin format
    in_addr inSubnetMask;
    memset(&inSubnetMask, 0, sizeof(inSubnetMask));
    if (!IpAddrHelper::ConvertStrToHostOrderBin(strSubNetMask, inSubnetMask))
    {
        LOG_ERROR("invalid subnet mask: %s", strSubNetMask.c_str());
        return false;
    }

    // calculate ip range with mask
    unsigned long ulIpVal      = inAddrIP.S_un.S_addr;
    unsigned long ulSubNetMask = inSubnetMask.S_un.S_addr;

    // copy to member attribute
    m_ipStartHostOrder = IpAddrHelper::toInAddrHostOrder(ulIpVal & ulSubNetMask);
    m_ipEndHostOrder   = IpAddrHelper::toInAddrHostOrder((ulIpVal & ulSubNetMask) | ~ulSubNetMask);

    std::string strIpStart;
    IpAddrHelper::ConvertHostOrderInAddrToString(m_ipStartHostOrder, strIpStart);

    std::string strIpEnd;
    IpAddrHelper::ConvertHostOrderInAddrToString(m_ipEndHostOrder, strIpEnd);

    LOG_DEBUG("source ip: %s, subnet mask: %s ,ip start: %s, ip end: %s, iSubNetMask: %lu", strIp.c_str(),
              strSubNetMask.c_str(), strIpStart.c_str(), strIpEnd.c_str(), ulSubNetMask);

    m_eIpRangeType = IpRangeType::SubNetMaskStyle;

    return true;
}

bool CIpRangeParser::CalcCidrNumOfSubnetMask(int& iCidrNum)
{
    if (m_eIpRangeType != IpRangeType::SubNetMaskStyle)
    {
        return false;
    }

    unsigned short netmaskCidr = 0;
    int ipbytes[4]             = {0};

    sscanf_s(m_strSubNetMask.c_str(), "%d.%d.%d.%d", &ipbytes[0], &ipbytes[1], &ipbytes[2], &ipbytes[3]);

    for (int i = 0; i < 4; i++)
    {
        switch (ipbytes[i])
        {
        case 0x80:
            netmaskCidr += 1;
            break;

        case 0xC0:
            netmaskCidr += 2;
            break;

        case 0xE0:
            netmaskCidr += 3;
            break;

        case 0xF0:
            netmaskCidr += 4;
            break;

        case 0xF8:
            netmaskCidr += 5;
            break;

        case 0xFC:
            netmaskCidr += 6;
            break;

        case 0xFE:
            netmaskCidr += 7;
            break;

        case 0xFF:
            netmaskCidr += 8;
            break;
        case 0x00:
            break;
        default:
            // not right subnet mask number
            return false;
        }
    }

    iCidrNum = netmaskCidr;

    return true;
}

bool CIpRangeParser::ConvertSubnetStyleToCidrStyle(std::string& strCidrStyle)
{
    int iCidrNum = -1;
    bool bRet    = CalcCidrNumOfSubnetMask(iCidrNum);

    if (!bRet)
    {
        return bRet;
    }

    std::stringstream ss;
    ss << m_strIp << "/" << iCidrNum;

    strCidrStyle = ss.str();

    return true;
}
