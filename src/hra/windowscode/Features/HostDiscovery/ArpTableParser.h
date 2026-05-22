#pragma once
#include <string>
#include <map>

class CArpTableParser
{
public:
    CArpTableParser();
    virtual ~CArpTableParser();

private:
    CArpTableParser(const CArpTableParser&);
    CArpTableParser& operator=(const CArpTableParser&){};

public:
    bool FindMacAddrByIpAddress(const std::string& strIpAddr, std::string& strMacAddr);

private:
    bool ParseArpTable(std::map<std::string, std::string>& mapIpMacResult);
};
