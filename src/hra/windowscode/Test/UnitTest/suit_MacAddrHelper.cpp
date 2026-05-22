#include "suit_MacAddrHelper.h"
#include "HostDiscovery/MacAddrHelper.h"

TEST_F(suit_MacAddrHelper, test_normalize_success)
{
    unsigned char temp[32] = {0x68, 0x4f, 0x64, 0xa6, 0x3f, 0xba, 0x00};
    std::string strMacAddr;

    MacAddrHelper::NormalizeMacAddr(temp, 6, strMacAddr);

    ASSERT_TRUE(strMacAddr == "68:4F:64:A6:3F:BA");
}

TEST_F(suit_MacAddrHelper, test_normalize_failed1)
{
    unsigned char temp[32] = {0x68, 0x4f, 0x64, 0xa6, 0x3f, 0xba, 0x00};
    std::string strMacAddr;

    MacAddrHelper::NormalizeMacAddr(NULL, 6, strMacAddr);

    ASSERT_TRUE(strMacAddr == "");
}

TEST_F(suit_MacAddrHelper, test_normalize_failed2)
{
    unsigned char temp[32] = {0x68, 0x4f, 0x64, 0xa6, 0x3f, 0xba, 0x00};
    std::string strMacAddr;

    MacAddrHelper::NormalizeMacAddr(temp, 8, strMacAddr);

    ASSERT_TRUE(strMacAddr == "");
}