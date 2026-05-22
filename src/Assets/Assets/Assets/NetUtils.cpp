#include "NetUtils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <WS2tcpip.h>
#include <WinSock2.h>
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h> 
#include <unistd.h>
#endif

#define IP_SIZE     16

namespace di_rest_client
{
int GetLocalIp(const char* pszDstIp, std::string& localIp, uint16_t dstPort)
{
#ifdef _WIN32
    SOCKET fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == INVALID_SOCKET) {
        return -1;
    }
#else
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        return -1;
    }
#endif

    int ret = 0;
    socklen_t len = sizeof(struct sockaddr);
    struct sockaddr_in saddr;
    struct sockaddr_in name;

    memset(&saddr, 0, sizeof(struct sockaddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(dstPort);

#ifdef _WIN32
    saddr.sin_addr.s_addr = inet_addr(pszDstIp);  // for xp/2003
#else
    char ip[IP_SIZE] = {0};
    int iRet = GetIPByDomian(pszDstIp, ip); 
    if (0 == iRet)
        saddr.sin_addr.s_addr = inet_addr(ip);
    else
        saddr.sin_addr.s_addr = inet_addr(pszDstIp);
#endif


    ret = connect(fd, (struct sockaddr*)&saddr, len);

    if (ret == -1) {
        goto out;
    }

    ret = getsockname(fd, (struct sockaddr*)&name, &len);

    if (ret == -1) {
        goto out;
    }

    localIp = inet_ntoa(name.sin_addr);

out:
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif

    return ret;
}

std::string IPLongToString(unsigned ip)
{
    char buf[16] = "\0";
#ifdef _WIN32
    _snprintf_s(buf, sizeof(buf)-1, "%d.%d.%d.%d", (int)(0X000000FF & (ip >> 24)), (int)(0X000000FF & (ip >> 16)),
              (int)(0X000000FF & (ip >> 8)), (int)(0X000000FF & ip));
#else
    snprintf(buf, sizeof(buf), "%d.%d.%d.%d", (int)(0X000000FF & (ip >> 24)), (int)(0X000000FF & (ip >> 16)),
             (int)(0X000000FF & (ip >> 8)), (int)(0X000000FF & ip));
#endif
    return buf;
}

unsigned long IPStringToLong(const char* addr)
{
    return ntohl(inet_addr(addr));
}

int GetIPByDomian(const char *domain, char *ip)
{
    char **pptr = NULL;
    struct hostent *hptr = NULL;
    hptr = gethostbyname(domain);
    if (NULL == hptr){
        return -1;
    }

    for (pptr = hptr->h_addr_list ; *pptr != NULL; pptr++)
    {
        if (NULL != inet_ntop(hptr->h_addrtype, *pptr, ip, IP_SIZE) ) 
            return 0;  // 只获取第一个ip
    }

    return -1;
}

#ifdef _WIN32
bool GetAdapterAddress(std::string &sAdapterAddress)
{
    PIP_ADAPTER_INFO pIPAdapterInfo = NULL;
    unsigned long ulSize = 0;
    int nRstCode = GetAdaptersInfo(pIPAdapterInfo, &ulSize);
    if (ERROR_BUFFER_OVERFLOW == nRstCode) {
        pIPAdapterInfo = (PIP_ADAPTER_INFO) new BYTE[(ulSize / 4096 + 1) * 4096];
        nRstCode = GetAdaptersInfo(pIPAdapterInfo, &ulSize);
    }

    char strMac[19];
    if (ERROR_SUCCESS == nRstCode) {
      _snprintf_s(strMac, sizeof(strMac)-1, "%02X-%02X-%02X-%02X-%02X-%02X",
        pIPAdapterInfo->Address[0],
        pIPAdapterInfo->Address[1],
        pIPAdapterInfo->Address[2],
        pIPAdapterInfo->Address[3],
        pIPAdapterInfo->Address[4],
        pIPAdapterInfo->Address[5]);

      sAdapterAddress = strMac;
    }

    if (pIPAdapterInfo){
      delete []pIPAdapterInfo;
    }

    return true;
}
#endif

}  // namespace di_rest_client
