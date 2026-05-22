#pragma once
#include <utility/comm.h>

#include <string>

// forward declare
class CHostDiscoveryInfo;

class CArpRequestHelper
{
public:
    CArpRequestHelper(const std::string& strScannerIp, const std::string& strScannerMac, const std::string& strDestIp);
    virtual ~CArpRequestHelper();

private:
    CArpRequestHelper(const CArpRequestHelper&){};
    CArpRequestHelper& operator=(const CArpRequestHelper&){};

public:
    HRA_Code SendArpReq(CHostDiscoveryInfo& hostDiscoveryInfo);

private:
    std::string m_strScannerIp;
    std::string m_strScannerMac;
    std::string m_strDestIp;
};
