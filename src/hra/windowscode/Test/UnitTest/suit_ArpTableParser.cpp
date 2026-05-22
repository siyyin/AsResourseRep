#include "suit_ArpTableParser.h"
#include "HostDiscovery/ArpTableParser.h"
#include "HostDiscovery/NICInfoHelper.h"

#include <ctype.h>

TEST_F(suit_ArpTableParser, test_ArpTableParser_get_gateway_mac_addr_success)
{
    CNICInfoHelper nicInfoHelper;

    std::vector<CNICNetInfo> vecNicMacAndNetInfo;
    HRA_Code retCode = nicInfoHelper.GetAllNICInfo(vecNicMacAndNetInfo);

    ASSERT_TRUE(retCode == HRA_OK);
    ASSERT_FALSE(vecNicMacAndNetInfo.empty());

    auto firstIter = vecNicMacAndNetInfo.begin();

    CNICNetInfo& nicNetInfo = *firstIter;

    std::string strScannerIp  = nicNetInfo.strIPv4;
    std::string strScannerMac = nicNetInfo.strMac;
    std::string strDestIp     = nicNetInfo.strGateWayIPv4;

    ASSERT_FALSE(strScannerIp.empty());
    ASSERT_FALSE(strScannerMac.empty());
    ASSERT_FALSE(strDestIp.empty());

    CArpTableParser arpTableParser;

    std::string strMacAddrLowerCase;
    bool bRet = arpTableParser.FindMacAddrByIpAddress(strDestIp, strMacAddrLowerCase);

    ASSERT_TRUE(bRet);

    //mac addr is upper case or number
    for (auto& iter = strMacAddrLowerCase.begin(); iter != strMacAddrLowerCase.end(); ++iter)
    {
        char c = *iter;

        ASSERT_TRUE((isupper(c) == 0) || (isdigit(c) == 0));
    }

}

TEST_F(suit_ArpTableParser, test_ArpTableParser_get_mac_addr_failed)
{
    CArpTableParser arpTableParser;

    std::string strMacAddrLowerCase;
    bool bRet = arpTableParser.FindMacAddrByIpAddress("0.0.0.0", strMacAddrLowerCase);

    ASSERT_FALSE(bRet);
}