#include "ArpTableParser.h"
#include <utility/Logger.h>
#include "IpRangeParser.h"
#include "MacAddrHelper.h"

#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>

CArpTableParser::CArpTableParser()
{
}

CArpTableParser::~CArpTableParser()
{
}

bool CArpTableParser::FindMacAddrByIpAddress(const std::string& strIpAddr, std::string& strMacAddr)
{
    std::map<std::string, std::string> mapIpMacResult;

    if (!ParseArpTable(mapIpMacResult))
    {
        LOG_ERROR("parse system arp table failed");
        return false;
    }

    LOG_DEBUG("system arp table item count: %d", mapIpMacResult.size());

    if (mapIpMacResult.find(strIpAddr) == mapIpMacResult.end())
    {
        return false;
    }

    strMacAddr = mapIpMacResult[strIpAddr];

    return true;
}

bool CArpTableParser::ParseArpTable(std::map<std::string, std::string>& mapIpMacResult)
{
    // https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipnettable2
    unsigned long status = 0;

    PMIB_IPNET_TABLE2 pipTable = NULL;

    status = GetIpNetTable2(AF_INET, &pipTable);
    if (status != NO_ERROR)
    {
        LOG_ERROR("GetIpNetTable for IPv4 table returned error: %ld", status);
        return false;
    }

    for (int i = 0; (unsigned)i < pipTable->NumEntries; i++)
    {
        std::string strIpAddr;
        IpAddrHelper::ConvertNetOrderInAddrToString(pipTable->Table[i].Address.Ipv4.sin_addr, strIpAddr);

        if (pipTable->Table[i].PhysicalAddressLength == 0)
        {
            continue;
        }

        std::string strMacNormalized;

        MacAddrHelper::NormalizeMacAddr(pipTable->Table[i].PhysicalAddress, pipTable->Table[i].PhysicalAddressLength,
                                        strMacNormalized);

         if (MacAddrHelper::IsBroadcast(strMacNormalized) || MacAddrHelper::IsUnspecified(strMacNormalized))
        {
            continue;
        }

        // overwrite if exists
        mapIpMacResult[strIpAddr] = strMacNormalized;
    }

    FreeMibTable(pipTable);
    pipTable = NULL;

    return true;
}
