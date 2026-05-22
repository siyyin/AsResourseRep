#pragma once
#include <string>

namespace MacAddrHelper
{
void NormalizeMacAddr(const unsigned char* pMacArrary, unsigned long cbMacArray, std::string& strMacAddr);
void NormalizeMacAddr(const std::string& strOrignMacAddr, std::string& strMacAddrNormalized);

bool ConvertToArray(const std::string& strMacAddr, unsigned char* pMacArrary, unsigned long cbMacArray);

bool IsUnspecified(const std::string& strMacAddr);
bool IsBroadcast(const std::string& strMacAddr);
};
