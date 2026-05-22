#pragma once
#pragma warning(disable:4290)
#include <winsock2.h>
#include <atomic>
#include <vector>
#include "comm.h"

#define SOCKET_TCP_MAX_IP_SIZE 128
#define SOCKET_TCP_ERROR_MSG_SIZE 2048

class HRA_UTILITY_EXPORT SocketTcpClient
{
public:
    SocketTcpClient();
    virtual ~SocketTcpClient();

    int close();
    int receive(void* pBuf, int nCount, int iTimeOut = 0);
    int receiveOnce(void* pBuf, int nCount, int iTimeOut);
    int send(const void* pBuf, int nCount, int iTimeOut = 0);
    int connect(const char* ip, int port, int iTimeOut = 0);
    int connectTestPorts(const char* ip, std::vector<int>& ports, int iTimeOut);
    
    bool isConnect();
    SOCKET getHandle();
    const char* getIP();
    int getPort();
    const char* getStatStr();
    const char* getErrorMsg();

private:
    std::atomic<bool> m_bConnectStatus;
    SOCKET m_fdSocket;
    char m_szIP[SOCKET_TCP_MAX_IP_SIZE];
    int m_iPort;
    char m_szErrorMsg[SOCKET_TCP_ERROR_MSG_SIZE];
    char m_szStatStr[SOCKET_TCP_ERROR_MSG_SIZE];
};

