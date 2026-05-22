#include "suit_PingIcmpHelper.h"
#include "HostDiscovery/NICInfoHelper.h"
#include "HostDiscovery/PingIcmpHelper.h"


TEST_F(suit_PingIcmpHelper, test_ping_gateway_success)
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

    CPingIcmpHelper pingIcmpHelper;

    bool bRet = pingIcmpHelper.Init();
    ASSERT_TRUE(bRet);

    bool bHasEcho = false;
    retCode = pingIcmpHelper.Ping(strDestIp, bHasEcho);

    ASSERT_TRUE(retCode == HRA_OK);
    ASSERT_TRUE(bHasEcho);
}

TEST_F(suit_PingIcmpHelper, test_ping_gateway_failed_invalid_parameter)
{
    CPingIcmpHelper pingIcmpHelper;

    bool bRet = pingIcmpHelper.Init();
    ASSERT_TRUE(bRet);

    bool bHasEcho = false;
    HRA_Code retCode = pingIcmpHelper.Ping("", bHasEcho);

    ASSERT_TRUE(retCode == HRA_BAD_PARAM);
    ASSERT_FALSE(bHasEcho);
}

TEST_F(suit_PingIcmpHelper, test_ping_gateway_failed_not_init)
{
    CPingIcmpHelper pingIcmpHelper;

    bool bHasEcho    = false;
    HRA_Code retCode = pingIcmpHelper.Ping("", bHasEcho);

    ASSERT_TRUE(retCode == HRA_NOT_INIT);
    ASSERT_FALSE(bHasEcho);
}

TEST_F(suit_PingIcmpHelper, test_ping_gateway_failed_bad_ip_addr)
{
    CPingIcmpHelper pingIcmpHelper;

    bool bRet = pingIcmpHelper.Init();
    ASSERT_TRUE(bRet);

    bool bHasEcho    = false;
    HRA_Code retCode = pingIcmpHelper.Ping("256.256.256.256", bHasEcho);

    ASSERT_TRUE(retCode == HRA_BAD_PARAM);
    ASSERT_FALSE(bHasEcho);
}