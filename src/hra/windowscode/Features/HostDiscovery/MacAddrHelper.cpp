#include "MacAddrHelper.h"
#include <Windows.h>
#include <ifdef.h>

#include <utility/HraUtils.h>

#include <algorithm>
#include <cctype>
#include <vector>

#define MAC_ADDR_LENGTH 6

#define MAX_PATH 256

#define MAC_ADDR_DELIMITER ":"

void MacAddrHelper::NormalizeMacAddr(const unsigned char* pMacArrary, unsigned long physicalAddressLength,
                                     std::string& strMacAddr)
{
    if (pMacArrary == NULL || physicalAddressLength != MAC_ADDR_LENGTH)
    {
        return;
    }

    strMacAddr = "";

    for (unsigned int iMacAddrIndex = 0; iMacAddrIndex < physicalAddressLength; iMacAddrIndex++)
    {
        char szTemp[MAX_PATH] = {0};

        if (iMacAddrIndex == (physicalAddressLength - 1))
        {
            sprintf_s(szTemp, "%.2X", (int)pMacArrary[iMacAddrIndex]);
        }
        else
        {
            sprintf_s(szTemp, "%.2X%s", (int)pMacArrary[iMacAddrIndex], MAC_ADDR_DELIMITER);
        }

        strMacAddr.append(szTemp);
    }
}

void MacAddrHelper::NormalizeMacAddr(const std::string& strOrignMacAddr, std::string& strMacAddrNormalized)
{
    // to upper case
    std::string strOrignMacAddrUpper = strOrignMacAddr;
    std::transform(strOrignMacAddrUpper.cbegin(), strOrignMacAddrUpper.cend(), strOrignMacAddrUpper.begin(), ::toupper);

    // replace dash to colon
    strMacAddrNormalized = UtilsReplaceAll(strOrignMacAddrUpper, "-", MAC_ADDR_DELIMITER);
}

bool MacAddrHelper::ConvertToArray(const std::string& strMacAddr, unsigned char* pMacArrary, unsigned long cbMacArray)
{
    if (pMacArrary == NULL || cbMacArray < MAC_ADDR_LENGTH)
    {
        return false;
    }

    std::string strNormalized;
    MacAddrHelper::NormalizeMacAddr(strMacAddr, strNormalized);

    std::vector<std::string> vecSplit = UtilsStringSplit(strNormalized, MAC_ADDR_DELIMITER);

    if (vecSplit.size() != MAC_ADDR_LENGTH)
    {
        return false;
    }

    for (size_t i = 0; i < MAC_ADDR_LENGTH; i++)
    {
        char* end = NULL;

        std::string curStr = vecSplit[i];
        unsigned long ul   = strtoul(curStr.c_str(), &end, 16);

        pMacArrary[i] = (unsigned char)ul;
    }

    return true;
}

bool MacAddrHelper::IsUnspecified(const std::string& strMacAddr)
{
    std::string strNormalized;
    MacAddrHelper::NormalizeMacAddr(strMacAddr, strNormalized);

    std::vector<std::string> vecSplit = UtilsStringSplit(strNormalized, MAC_ADDR_DELIMITER);

    if (vecSplit.size() != MAC_ADDR_LENGTH)
    {
        return false;
    }

    for (size_t i = 0; i < MAC_ADDR_LENGTH; i++)
    {
        char* end = NULL;

        std::string curStr = vecSplit[i];
        unsigned long ul   = strtoul(curStr.c_str(), &end, 16);

        if (ul != 0x00)
        {
            return false;
        }
    }

    return true;
}
bool MacAddrHelper::IsBroadcast(const std::string& strMacAddr)
{
    std::string strNormalized;
    MacAddrHelper::NormalizeMacAddr(strMacAddr, strNormalized);

    std::vector<std::string> vecSplit = UtilsStringSplit(strNormalized, MAC_ADDR_DELIMITER);

    if (vecSplit.size() != MAC_ADDR_LENGTH)
    {
        return false;
    }

    for (size_t i = 0; i < MAC_ADDR_LENGTH; i++)
    {
        char* end = NULL;

        std::string curStr = vecSplit[i];
        unsigned long ul   = strtoul(curStr.c_str(), &end, 16);

        if (ul != 0xff)
        {
            return false;
        }
    }

    return true;
}
