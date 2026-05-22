#pragma once
#include <utility/comm.h>

#include <string>

#include <Windows.h>

class CPingIcmpHelper
{
public:
    CPingIcmpHelper();
    virtual ~CPingIcmpHelper();

private:
    CPingIcmpHelper(const CPingIcmpHelper&){};
    CPingIcmpHelper& operator=(const CPingIcmpHelper&){};

public:
    bool Init();

    HRA_Code Ping(const std::string& strDestIp, bool& bHasEcho, int iTimeoutInMs = 1000);

private:
    HANDLE m_hIcmpFile;
};
