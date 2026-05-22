#include "suite_IpRangeParser.h"

#include "../Features/HostDiscovery/IpRangeParser.h"
#include <utility/comm.h>

///////////////////////////////////////////////////
TEST_F(suite_IpRangeParser, test_single_ip_parse)
{
    std::string strIpRange = "10.21.142.50";
    CIpRangeParser ipRangeParser(strIpRange);

    bool bRet = ipRangeParser.Parse();

    ASSERT_TRUE(bRet);

    bRet = ipRangeParser.IsInRange("10.21.142.50");

    ASSERT_TRUE(bRet);

    bRet = ipRangeParser.IsInRange("10.21.142.51");

    ASSERT_FALSE(bRet);

    std::vector<std::string> vecIp;
    ipRangeParser.RangeToList(vecIp, false);

    ASSERT_TRUE(vecIp.size() == 1);

    for (int i = 0; i < 1; ++i)
    {
        char temp[MAX_PATH] = {0};

        sprintf_s(temp, "10.21.142.%d", 50);

        ASSERT_TRUE(vecIp[i] == temp);
    }
}

TEST_F(suite_IpRangeParser, test_parse_ip_range_dash_style_success)
{
    CIpRangeParser ipRangeParser("10.21.142.50-10.21.142.150");

    bool bRet = ipRangeParser.Parse();

    ASSERT_TRUE(bRet);

    bRet = ipRangeParser.IsInRange("10.21.142.50");

    ASSERT_TRUE(bRet);

    bRet = ipRangeParser.IsInRange("10.21.142.51");

    ASSERT_TRUE(bRet);

    bRet = ipRangeParser.IsInRange("10.21.142.49");

    ASSERT_FALSE(bRet);

    bRet = ipRangeParser.IsInRange("10.21.142.151");

    ASSERT_FALSE(bRet);

    std::vector<std::string> vecIp;
    ipRangeParser.RangeToList(vecIp, false);

    ASSERT_TRUE(vecIp.size() == 101);

    for (int i = 0; i < 101; ++i)
    {
        char temp[MAX_PATH] = {0};

        sprintf_s(temp, "10.21.142.%d", 50 + i);

        ASSERT_TRUE(vecIp[i] == temp);
    }
}

TEST_F(suite_IpRangeParser, test_parse_ip_range_CIDR_style_success)
{
    CIpRangeParser ipRangeParser("10.21.142.50/24");

    bool bRet = ipRangeParser.Parse();

    ASSERT_TRUE(bRet);

    bRet = ipRangeParser.IsInRange("10.21.142.1");

    ASSERT_TRUE(bRet);

    bRet = ipRangeParser.IsInRange("10.21.142.254");

    ASSERT_TRUE(bRet);

    bRet = ipRangeParser.IsInRange("10.21.142.0");

    ASSERT_TRUE(bRet);

    bRet = ipRangeParser.IsInRange("10.21.142.255");

    ASSERT_TRUE(bRet);

    bRet = ipRangeParser.IsInRange("10.21.141.151");

    ASSERT_FALSE(bRet);

    std::vector<std::string> vecIp;
    ipRangeParser.RangeToList(vecIp, false);
    int ipCount = 256;

    ASSERT_TRUE(vecIp.size() == ipCount);

    for (int i = 0; i < ipCount; ++i)
    {
        char temp[MAX_PATH] = {0};

        sprintf_s(temp, "10.21.142.%d", i);

        ASSERT_TRUE(vecIp[i] == temp);
    }
}
////////////////////////////////////////////////////////////////////////////
TEST_F(suite_IpRangeParser, test_single_ip_parse_failed_invalid_format1)
{
    CIpRangeParser ipRangeParser("10.21.142.501");

    bool bRet = ipRangeParser.Parse();

    ASSERT_FALSE(bRet);
}

TEST_F(suite_IpRangeParser, test_single_ip_parse_failed_invalid_format2)
{
    CIpRangeParser ipRangeParser("310.21.142.50");

    bool bRet = ipRangeParser.Parse();

    ASSERT_FALSE(bRet);
}

TEST_F(suite_IpRangeParser, test_single_ip_parse_failed_invalid_format3)
{
    CIpRangeParser ipRangeParser("a10.21.142.50");

    bool bRet = ipRangeParser.Parse();

    ASSERT_FALSE(bRet);
}
////////////////////////////////////////////////////////////////////////////
TEST_F(suite_IpRangeParser, test_dash_style_ip_parse_failed_invalid_format1)
{
    CIpRangeParser ipRangeParser("10.21.142.431");

    bool bRet = ipRangeParser.Parse();

    ASSERT_FALSE(bRet);
}
TEST_F(suite_IpRangeParser, test_dash_style_ip_parse_failed_invalid_format2)
{
    CIpRangeParser ipRangeParser("10.21.142.501-");

    bool bRet = ipRangeParser.Parse();

    ASSERT_FALSE(bRet);
}

TEST_F(suite_IpRangeParser, test_dash_style_ip_parse_failed_invalid_format3)
{
    CIpRangeParser ipRangeParser("10.21.142.01-10.21.142.501");

    bool bRet = ipRangeParser.Parse();

    ASSERT_FALSE(bRet);
}
TEST_F(suite_IpRangeParser, test_dash_style_ip_parse_failed_invalid_format4)
{
    CIpRangeParser ipRangeParser("-10.21.142.501");

    bool bRet = ipRangeParser.Parse();

    ASSERT_FALSE(bRet);
}
////////////////////////////////////////////////////////////////////////////
TEST_F(suite_IpRangeParser, test_CIDR_style_ip_parse_failed_invalid_format1)
{
    CIpRangeParser ipRangeParser("10.21.142.411");

    bool bRet = ipRangeParser.Parse();

    ASSERT_FALSE(bRet);
}

TEST_F(suite_IpRangeParser, test_CIDR_style_ip_parse_failed_invalid_format2)
{
    CIpRangeParser ipRangeParser("10.21.142.0/-1");

    bool bRet = ipRangeParser.Parse();

    ASSERT_FALSE(bRet);
}

TEST_F(suite_IpRangeParser, test_CIDR_style_ip_parse_failed_invalid_format3)
{
    CIpRangeParser ipRangeParser("10.21.142.0/33");

    bool bRet = ipRangeParser.Parse();

    ASSERT_FALSE(bRet);
}

TEST_F(suite_IpRangeParser, test_CIDR_style_ip_parse_failed_invalid_format4)
{
    CIpRangeParser ipRangeParser("10.21.142.0/A");

    bool bRet = ipRangeParser.Parse();

    ASSERT_FALSE(bRet);
}

TEST_F(suite_IpRangeParser, test_CIDR_style_ip_parse_failed_invalid_format5)
{
    CIpRangeParser ipRangeParser("10.21.142.260/2");

    bool bRet = ipRangeParser.Parse();

    ASSERT_FALSE(bRet);
}
////////////////////////////////////////////////////////////////////////////
TEST_F(suite_IpRangeParser, test_VerifySubNetMask)
{
    bool bRet = IpAddrHelper::VerifySubNetMask("0.128.192.224");

    ASSERT_TRUE(bRet);

    bRet = IpAddrHelper::VerifySubNetMask("240.248.252.254");

    ASSERT_TRUE(bRet);

    bRet = IpAddrHelper::VerifySubNetMask("255.255.255.255");

    ASSERT_TRUE(bRet);

    bRet = IpAddrHelper::VerifySubNetMask("");

    ASSERT_FALSE(bRet);

    bRet = IpAddrHelper::VerifySubNetMask("1.255.255.255");

    ASSERT_FALSE(bRet);
}
////////////////////////////////////////////////////////////////////////////
TEST_F(suite_IpRangeParser, test_SubNetwork_style_ip_parse_success)
{
    CIpRangeParser ipRangeParser("10.21.142.0", "255.255.255.0");

    bool bRet = ipRangeParser.Parse();

    ASSERT_TRUE(bRet);

    bRet = ipRangeParser.IsInRange("10.21.142.1");

    ASSERT_TRUE(bRet);

    bRet = ipRangeParser.IsInRange("10.21.142.254");

    ASSERT_TRUE(bRet);

    bRet = ipRangeParser.IsInRange("10.21.142.0");

    ASSERT_TRUE(bRet);

    bRet = ipRangeParser.IsInRange("10.21.142.255");

    ASSERT_TRUE(bRet);

    bRet = ipRangeParser.IsInRange("10.21.141.25");

    ASSERT_FALSE(bRet);

    std::vector<std::string> vecIp;
    ipRangeParser.RangeToList(vecIp, false);
    int ipCount = 256;

    ASSERT_TRUE(vecIp.size() == ipCount);

    for (int i = 0; i < ipCount; ++i)
    {
        char temp[MAX_PATH] = {0};

        sprintf_s(temp, "10.21.142.%d", i);

        ASSERT_TRUE(vecIp[i] == temp);
    }
}
////////////////////////////////////////////////////////////////////////////
TEST_F(suite_IpRangeParser, test_RangeToList_subnet_mask_style_success)
{
    CIpRangeParser ipRangeParser("10.21.142.0", "255.255.255.0");

    bool bRet = ipRangeParser.Parse();

    ASSERT_TRUE(bRet);

    std::vector<std::string> vecIp;
    ipRangeParser.RangeToList(vecIp, false);

    ASSERT_TRUE(vecIp.size() == 256);

    for (int i = 0; i < 256; ++i)
    {
        char temp[MAX_PATH] = {0};

        sprintf_s(temp, "10.21.142.%d", i);

        ASSERT_TRUE(vecIp[i] == temp);
    }

    ipRangeParser.RangeToList(vecIp);

    ASSERT_TRUE(vecIp.size() == 254);

    for (int i = 0; i < 254; ++i)
    {
        char temp[MAX_PATH] = {0};

        sprintf_s(temp, "10.21.142.%d", i + 1);

        ASSERT_TRUE(vecIp[i] == temp);
    }
}
////////////////////////////////////////////////////////////////////////////
TEST_F(suite_IpRangeParser, test_RangeToList_CIDR_style_success)
{
    CIpRangeParser ipRangeParser("10.21.142.0/24");

    bool bRet = ipRangeParser.Parse();

    ASSERT_TRUE(bRet);

    std::vector<std::string> vecIp;
    ipRangeParser.RangeToList(vecIp, false);

    ASSERT_TRUE(vecIp.size() == 256);

    for (int i = 0; i < 256; ++i)
    {
        char temp[MAX_PATH] = {0};

        sprintf_s(temp, "10.21.142.%d", i);

        ASSERT_TRUE(vecIp[i] == temp);
    }

    ipRangeParser.RangeToList(vecIp);

    ASSERT_TRUE(vecIp.size() == 254);

    for (int i = 0; i < 254; ++i)
    {
        char temp[MAX_PATH] = {0};

        sprintf_s(temp, "10.21.142.%d", i + 1);

        ASSERT_TRUE(vecIp[i] == temp);
    }
}

////////////////////////////////////////////////////////////////////////////
TEST_F(suite_IpRangeParser, test_RangeToList_Single_IP_style_success)
{
    CIpRangeParser ipRangeParser("10.21.142.1");

    bool bRet = ipRangeParser.Parse();

    ASSERT_TRUE(bRet);

    std::vector<std::string> vecIp;
    ipRangeParser.RangeToList(vecIp, false);

    ASSERT_TRUE(vecIp.size() == 1);

    for (int i = 0; i < 1; ++i)
    {
        char temp[MAX_PATH] = {0};

        sprintf_s(temp, "10.21.142.%d", i + 1);

        ASSERT_TRUE(vecIp[i] == temp);
    }

    ipRangeParser.RangeToList(vecIp);

    ASSERT_TRUE(vecIp.size() == 1);

    for (int i = 0; i < 1; ++i)
    {
        char temp[MAX_PATH] = {0};

        sprintf_s(temp, "10.21.142.%d", i + 1);

        ASSERT_TRUE(vecIp[i] == temp);
    }
}
////////////////////////////////////////////////////////////////////////////
TEST_F(suite_IpRangeParser, test_RangeToList_LINK_style_success)
{
    CIpRangeParser ipRangeParser("10.21.142.0-10.21.142.255");

    bool bRet = ipRangeParser.Parse();

    ASSERT_TRUE(bRet);

    std::vector<std::string> vecIp;
    ipRangeParser.RangeToList(vecIp, false);

    ASSERT_TRUE(vecIp.size() == 256);

    for (int i = 0; i < 256; ++i)
    {
        char temp[MAX_PATH] = {0};

        sprintf_s(temp, "10.21.142.%d", i);

        ASSERT_TRUE(vecIp[i] == temp);
    }

    ipRangeParser.RangeToList(vecIp);

    ASSERT_TRUE(vecIp.size() == 256);

    for (int i = 0; i < 256; ++i)
    {
        char temp[MAX_PATH] = {0};

        sprintf_s(temp, "10.21.142.%d", i);

        ASSERT_TRUE(vecIp[i] == temp);
    }
}

////////////////////////////////////////////////////////////////////////////
TEST_F(suite_IpRangeParser, test_IsLoopback)
{
    bool bRet = IpAddrHelper::IsLoopback("127.0.0.1");

    ASSERT_TRUE(bRet);

    bRet = IpAddrHelper::IsLoopback("127.0.0.0");

    ASSERT_FALSE(bRet);
}
////////////////////////////////////////////////////////////////////////////
TEST_F(suite_IpRangeParser, test_IsUnspecified)
{
    bool bRet = IpAddrHelper::IsUnspecified("0.0.0.0");

    ASSERT_TRUE(bRet);

    bRet = IpAddrHelper::IsUnspecified("127.0.0.1");

    ASSERT_FALSE(bRet);
}
////////////////////////////////////////////////////////////////////////////
TEST_F(suite_IpRangeParser, test_IsMulticastAddress)
{
    bool bRet = IpAddrHelper::IsMulticastAddress("224.0.0.0");

    ASSERT_TRUE(bRet);

    bRet = IpAddrHelper::IsMulticastAddress("239.255.255.255");

    ASSERT_TRUE(bRet);

    bRet = IpAddrHelper::IsMulticastAddress("224.0.0.1");

    ASSERT_TRUE(bRet);

    bRet = IpAddrHelper::IsUnspecified("127.0.0.1");

    ASSERT_FALSE(bRet);
}
////////////////////////////////////////////////////////////////////////////
TEST_F(suite_IpRangeParser, test_IsInAvailable_addr_SUCCESS)
{
    CIpRangeParser ipRangeParser("10.21.142.50/24");

    bool bRet = ipRangeParser.Parse();

    ASSERT_TRUE(bRet);

    bool bIsInAvailableRange = false;

    HRA_Code retCode;

    retCode = ipRangeParser.IsInAvailableRange("10.21.142.1", bIsInAvailableRange);

    ASSERT_TRUE(retCode == HRA_OK);
    ASSERT_TRUE(bIsInAvailableRange);

    retCode = ipRangeParser.IsInAvailableRange("10.21.142.254", bIsInAvailableRange);

    ASSERT_TRUE(retCode == HRA_OK);
    ASSERT_TRUE(bIsInAvailableRange);

    retCode = ipRangeParser.IsInAvailableRange("10.21.142.0", bIsInAvailableRange);

    ASSERT_TRUE(retCode == HRA_OK);
    ASSERT_FALSE(bIsInAvailableRange);

    retCode = ipRangeParser.IsInAvailableRange("10.21.142.255", bIsInAvailableRange);

    ASSERT_TRUE(retCode == HRA_OK);
    ASSERT_FALSE(bIsInAvailableRange);

    retCode = ipRangeParser.IsInAvailableRange("10.21.141.151", bIsInAvailableRange);

    ASSERT_TRUE(retCode == HRA_OK);
    ASSERT_FALSE(bIsInAvailableRange);
}
////////////////////////////////////////////////////////////////////////////
TEST_F(suite_IpRangeParser, test_IsInAvailable_addr_failed1)
{
    CIpRangeParser ipRangeParser("10.21.142.50/24");

    bool bRet = ipRangeParser.Parse();

    ASSERT_TRUE(bRet);

    bool bIsInAvailableRange = false;

    HRA_Code retCode;

    retCode = ipRangeParser.IsInAvailableRange("10.21.142.256", bIsInAvailableRange);
    ASSERT_TRUE(retCode == HRA_BAD_PARAM);
}

////////////////////////////////////////////////////////////////////////////
TEST_F(suite_IpRangeParser, test_IsInAvailable_addr_failed2)
{
    CIpRangeParser ipRangeParser("10.21.142.50");

    bool bRet = ipRangeParser.Parse();

    ASSERT_TRUE(bRet);

    bool bIsInAvailableRange = false;

    HRA_Code retCode;

    retCode = ipRangeParser.IsInAvailableRange("10.21.142.256", bIsInAvailableRange);
    ASSERT_TRUE(retCode == HRA_BAD_PARAM);
}
////////////////////////////////////////////////////////////////////////////
TEST_F(suite_IpRangeParser, test_Calc_CIDR_NUMBER_SUCCESS)
{
    CIpRangeParser ipRangeParser("10.21.142.50", "255.255.255.0");

    bool bRet = ipRangeParser.Parse();

    ASSERT_TRUE(bRet);

    bool bIsInAvailableRange = false;

    HRA_Code retCode;

    int iCidrNum = -1;
    bRet         = ipRangeParser.CalcCidrNumOfSubnetMask(iCidrNum);
    ASSERT_TRUE(bRet);

    ASSERT_TRUE(iCidrNum == 24);
}

////////////////////////////////////////////////////////////////////////////
TEST_F(suite_IpRangeParser, test_convert_to_CIDR_NUMBER_SUCCESS)
{
    CIpRangeParser ipRangeParser("10.21.142.50", "255.255.255.0");

    bool bRet = ipRangeParser.Parse();

    ASSERT_TRUE(bRet);

    bool bIsInAvailableRange = false;

    HRA_Code retCode;

    std::string strCidrStyle;
    bRet = ipRangeParser.ConvertSubnetStyleToCidrStyle(strCidrStyle);
    ASSERT_TRUE(bRet);

    ASSERT_TRUE(strCidrStyle == "10.21.142.50/24");
}