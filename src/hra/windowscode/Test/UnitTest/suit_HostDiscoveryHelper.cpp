#include "suit_HostDiscoveryHelper.h"
#include "HostDiscovery/HostDiscoveryHelper.h"
#include "HostDiscovery/NICInfoHelper.h"
#include "utility/Logger.h"
#include "utility/HraCtrlCmd.h"

TEST_F(suit_HostDiscoveryHelper, test_merge_scan_range_with_scanner_success)
{
    CHostDiscoveryHelper hostDiscoveryHelper(123);

    std::string strSelfIP         = "10.21.142.50";
    std::string strSelfSubNetMask = "255.255.255.0";
    std::string strTargetIpRange  = "10.21.142.50/30";

    std::vector<std::string> vecToBeScanIpRange;

    // self addr range: [10.21.142.0, 10.21.142.255]
    // target addr ragne: [10.21.142.48, 10.21.142.51]
    // ==> merge: [10.21.142.48, 10.21.142.51] except 10.21.142.50
    HRA_Code retCode = hostDiscoveryHelper.MergeScanRangeWithScannerNetInfo(strSelfIP, strSelfSubNetMask,
                                                                            strTargetIpRange, vecToBeScanIpRange);

    ASSERT_TRUE(retCode == HRA_OK);

    ASSERT_TRUE(vecToBeScanIpRange.size() == 3);

    ASSERT_TRUE(vecToBeScanIpRange[0] != strSelfIP);
    ASSERT_TRUE(vecToBeScanIpRange[1] != strSelfIP);
    ASSERT_TRUE(vecToBeScanIpRange[2] != strSelfIP);
}

TEST_F(suit_HostDiscoveryHelper, test_merge_scan_range_success1)
{
    CHostDiscoveryHelper hostDiscoveryHelper(123);

    std::set<std::string> setIpRange;
    setIpRange.insert("10.21.142.51");
    setIpRange.insert("10.21.142.50/30");

    std::set<std::string> setToBeScanIpRange;

    HRA_Code retCode = hostDiscoveryHelper.MergeScanRange(setIpRange, setToBeScanIpRange);

    ASSERT_TRUE(retCode == HRA_OK);

    ASSERT_TRUE(setToBeScanIpRange.size() == 4);
}

TEST_F(suit_HostDiscoveryHelper, test_merge_scan_range_success2)
{
    CHostDiscoveryHelper hostDiscoveryHelper(123);

    std::set<std::string> setIpRange;
    setIpRange.insert("10.21.142.50-10.21.142.55");
    setIpRange.insert("10.21.142.50/30");

    std::set<std::string> setToBeScanIpRange;

    HRA_Code retCode = hostDiscoveryHelper.MergeScanRange(setIpRange, setToBeScanIpRange);

    ASSERT_TRUE(retCode == HRA_OK);

    for (auto& iter = setToBeScanIpRange.begin(); iter != setToBeScanIpRange.end(); ++iter)
    {
        LOG_DEBUG("%s\n", (*iter).c_str());
    }

    ASSERT_TRUE(setToBeScanIpRange.size() == 8);
}

TEST_F(suit_HostDiscoveryHelper, test_discovery__gatewaty_by_arp_success)
{
    CHostDiscoveryHelper hostDiscoveryHelper(123);

    HostDiscoveryResult mapScanResult;
    HostDiscoveryScanParam scanParameter;

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

    retCode = hostDiscoveryHelper.DiscoveryHost(nicNetInfo, strDestIp, HostDiscoveryMethod::Arp, mapScanResult,
                                                scanParameter);

    ASSERT_TRUE(retCode == HRA_OK);

    auto& setHostDiscoveryResult = mapScanResult;

    ASSERT_TRUE(setHostDiscoveryResult.size() == 1);
    ASSERT_TRUE(setHostDiscoveryResult.begin()->strIP == strDestIp);
}

TEST_F(suit_HostDiscoveryHelper, test_discovery__gatewaty_by_ping_success)
{
    CHostDiscoveryHelper hostDiscoveryHelper(123);

    HostDiscoveryResult mapScanResult;
    HostDiscoveryScanParam scanParameter;

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

    retCode = hostDiscoveryHelper.DiscoveryHost(nicNetInfo, strDestIp, HostDiscoveryMethod::Ping, mapScanResult,
                                                scanParameter);

    ASSERT_TRUE(retCode == HRA_OK);

    auto& setHostDiscoveryResult = mapScanResult;

    ASSERT_TRUE(setHostDiscoveryResult.size() == 1);

    ASSERT_TRUE(setHostDiscoveryResult.begin()->strScannerIp == strScannerIp);
    ASSERT_TRUE(setHostDiscoveryResult.begin()->strScannerMac == strScannerMac);
    ASSERT_TRUE(setHostDiscoveryResult.begin()->strIP == strDestIp);
}

TEST_F(suit_HostDiscoveryHelper, test_discovery__gatewaty_by_ping_cancel)
{
    CHostDiscoveryHelper hostDiscoveryHelper(123);

    HostDiscoveryResult mapScanResult;
    HostDiscoveryScanParam scanParameter;

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

    HraCtrlCmd::getInstance()->pushCmd(123, HraCtrlCmd::CmdDef::cmd_cancel);

    retCode = hostDiscoveryHelper.DiscoveryHost(nicNetInfo, strDestIp, HostDiscoveryMethod::Ping, mapScanResult,
                                                scanParameter);

    ASSERT_TRUE(retCode == HRA_USER_CANCEL);

    auto& setHostDiscoveryResult = mapScanResult;

    ASSERT_TRUE(setHostDiscoveryResult.size() == 0);

    HraCtrlCmd::getInstance()->popCmd(123);
}

TEST_F(suit_HostDiscoveryHelper, test_discovery__gatewaty_by_arp_cancel)
{
    CHostDiscoveryHelper hostDiscoveryHelper(123);

    HostDiscoveryResult mapScanResult;
    HostDiscoveryScanParam scanParameter;

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

    HraCtrlCmd::getInstance()->pushCmd(123, HraCtrlCmd::CmdDef::cmd_cancel);

    retCode = hostDiscoveryHelper.DiscoveryHost(nicNetInfo, strDestIp, HostDiscoveryMethod::Arp, mapScanResult,
                                                scanParameter);

    ASSERT_TRUE(retCode == HRA_USER_CANCEL);

    auto& setHostDiscoveryResult = mapScanResult;

    ASSERT_TRUE(setHostDiscoveryResult.size() == 0);

    HraCtrlCmd::getInstance()->popCmd(123);
}