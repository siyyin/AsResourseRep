#include "suit_ArpRequestHelper.h"
#include "HostDiscovery/NICInfoHelper.h"
#include "HostDiscovery/ArpRequestHelper.h"
#include "HostDiscovery/HostDiscoveryHelper.h"

TEST_F(suit_ArpRequestHelper, test_ArpRequestHelper_send_to_gateway_success)
{
    CNICInfoHelper nicInfoHelper;

    std::vector<CNICNetInfo> vecNicMacAndNetInfo;
    HRA_Code retCode = nicInfoHelper.GetAllNICInfo(vecNicMacAndNetInfo);

    ASSERT_TRUE(retCode == HRA_OK);
    ASSERT_FALSE(vecNicMacAndNetInfo.empty());

    auto firstIter = vecNicMacAndNetInfo.begin();

    CNICNetInfo& nicNetInfo = *firstIter;

    ASSERT_FALSE(nicNetInfo.strGateWayIPv4.empty());
    ASSERT_FALSE(nicNetInfo.strIPv4.empty());

    std::string strScannerIp = nicNetInfo.strIPv4;
    std::string strScannerMac = nicNetInfo.strMac;
    std::string strDestIp    = nicNetInfo.strGateWayIPv4;

    CArpRequestHelper arpRequestHelper(strScannerIp, strScannerMac, strDestIp);

    CHostDiscoveryInfo hostDiscoveryInfo;
    retCode = arpRequestHelper.SendArpReq(hostDiscoveryInfo);

    ASSERT_TRUE(retCode == HRA_OK);
    ASSERT_TRUE(hostDiscoveryInfo.strIP == strDestIp);
}


TEST_F(suit_ArpRequestHelper, test_ArpRequestHelper_send_to_gateway_bad_param1)
{
    CArpRequestHelper arpRequestHelper("", "00:50:56:a0:1b:46", "10.21.139.134");

    CHostDiscoveryInfo hostDiscoveryInfo;
    HRA_Code retCode = arpRequestHelper.SendArpReq(hostDiscoveryInfo);

    ASSERT_TRUE(retCode == HRA_BAD_PARAM);
}

TEST_F(suit_ArpRequestHelper, test_ArpRequestHelper_send_to_gateway_bad_param2)
{
    CArpRequestHelper arpRequestHelper("10.21.139.134", "", "10.21.139.134");

    CHostDiscoveryInfo hostDiscoveryInfo;
    HRA_Code retCode = arpRequestHelper.SendArpReq(hostDiscoveryInfo);

    ASSERT_TRUE(retCode == HRA_BAD_PARAM);
}


TEST_F(suit_ArpRequestHelper, test_ArpRequestHelper_send_to_gateway_bad_param3)
{
    CArpRequestHelper arpRequestHelper("10.21.139.134", "00:50:56:a0:1b:46", "");

    CHostDiscoveryInfo hostDiscoveryInfo;
    HRA_Code retCode = arpRequestHelper.SendArpReq(hostDiscoveryInfo);

    ASSERT_TRUE(retCode == HRA_BAD_PARAM);
}