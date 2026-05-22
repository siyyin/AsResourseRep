#include "PingIcmpHelper.h"
#include "IpRangeParser.h"

#include <utility/Logger.h>

#include <iphlpapi.h>
#include <icmpapi.h>
#include <winsock2.h>

#include <new>
#include <memory>

#define ICMP_SEND_PACKAGE_NUM 1
#define ICMP_SEND_PACKAGE_SIZE 2

CPingIcmpHelper::CPingIcmpHelper()
    : m_hIcmpFile(NULL)
{
}

CPingIcmpHelper::~CPingIcmpHelper()
{
    if (m_hIcmpFile != NULL)
    {
        IcmpCloseHandle(m_hIcmpFile);
        m_hIcmpFile = NULL;
    }
}

bool CPingIcmpHelper::Init()
{
    HANDLE hIcmpFile = IcmpCreateFile();
    if (hIcmpFile == INVALID_HANDLE_VALUE)
    {
        LOG_ERROR("IcmpCreatefile returned error: %ld", GetLastError());
        return false;
    }

    m_hIcmpFile = hIcmpFile;

    return true;
}

HRA_Code CPingIcmpHelper::Ping(const std::string& strDestIp, bool& bHasEcho, int iTimeoutInMs)
{
    if (m_hIcmpFile == NULL)
    {
        LOG_ERROR("not init Icmp");
        return HRA_NOT_INIT;
    }

    if (strDestIp.empty())
    {
        LOG_ERROR("empty paramter");
        return HRA_BAD_PARAM;
    }

    unsigned long ipaddr                  = INADDR_NONE;
    DWORD dwReplyPackageNumber            = 0;
    char SendData[ICMP_SEND_PACKAGE_SIZE] = "E";
    DWORD ReplySize                       = 0;

    // convert ip string to unsigned long
    in_addr inAddr;
    if (!IpAddrHelper::ConvertStrToNetWorkOrderBin(strDestIp, inAddr))
    {
        LOG_ERROR("invalid ip: %s", strDestIp.c_str());
        return HRA_BAD_PARAM;
    }

    ipaddr = inAddr.S_un.S_addr;

    ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);

    std::shared_ptr<char> ptrReplyBuffer(new (std::nothrow) char[ReplySize], std::default_delete<char[]>());

    if (ptrReplyBuffer == NULL)
    {
        LOG_ERROR("Unable to allocate memory");
        return HRA_FAILED;
    }

    memset(ptrReplyBuffer.get(), 0, ReplySize * sizeof(char));

    // init return value to false
    bHasEcho = false;

    // send icmp echo
    dwReplyPackageNumber = IcmpSendEcho(m_hIcmpFile, ipaddr, SendData, sizeof(SendData), NULL, ptrReplyBuffer.get(),
                                        ReplySize, iTimeoutInMs);

    // number of reply package
    if (dwReplyPackageNumber != ICMP_SEND_PACKAGE_NUM)
    {
        LOG_DEBUG("the number of reply package not match, reply package number: %d, errCode: %d", dwReplyPackageNumber,
                 GetLastError());
        return HRA_FAILED;
    }

    // check reply content
    ICMP_ECHO_REPLY* pEchoReply = reinterpret_cast<ICMP_ECHO_REPLY*>(ptrReplyBuffer.get());

    if (pEchoReply->Status != 0)
    {
        LOG_DEBUG("reply status is not right, %d", pEchoReply->Status);
        return HRA_FAILED;
    }

    // Check we got the same amount of data back as we sent
    if (pEchoReply->DataSize != ICMP_SEND_PACKAGE_SIZE)
    {
        LOG_DEBUG("reply package size not match, %d", pEchoReply->DataSize);
        return HRA_FAILED;
    }

    // Check the data we got back is what was sent
    char* pReplyData = (char*)pEchoReply->Data;
    if (pReplyData == NULL)
    {
        LOG_DEBUG("reply package content is NULL");
        return HRA_FAILED;
    }

    for (int i = 0; i < ICMP_SEND_PACKAGE_SIZE; i++)
    {
        if ((pReplyData[i] != SendData[i]))
        {
            LOG_DEBUG("reply package content not match, %s", pReplyData[i]);
            return HRA_FAILED;
        }
    }

    // everything seems ok
    bHasEcho = true;

    return HRA_OK;
}
