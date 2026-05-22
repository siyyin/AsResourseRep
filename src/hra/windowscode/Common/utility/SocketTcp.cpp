#include <ws2tcpip.h>
#include <regex>
#include "SocketTcp.h"
#include <utility/Logger.h>

#pragma comment(lib, "ws2_32.lib")

SocketTcpClient::SocketTcpClient()
{
    //初始化
    WSAData wsa;
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        int iErrorCode = ::WSAGetLastError();
    }

    m_bConnectStatus = false;
    m_iPort = 0;
    memset(m_szIP, 0, sizeof(m_szIP));
    m_fdSocket = 0;
    memset(m_szErrorMsg, 0, sizeof(m_szErrorMsg));
    memset(m_szStatStr, 0, sizeof(m_szStatStr));
}

SocketTcpClient::~SocketTcpClient()
{
    ::WSACleanup();
}

const char* SocketTcpClient::getStatStr()
{
    //char szTmp[1024];
    //memset(szTmp, 0 , sizeof(szTmp));
    _snprintf_s(m_szStatStr, sizeof(m_szStatStr), "{IP:%s,Port:%d,Connect:%s}", m_szIP, m_iPort,
                isConnect() ? "true" : "false");
    return m_szStatStr;
}

bool SocketTcpClient::isConnect()
{
    if (m_fdSocket <= 0)
    {
        m_bConnectStatus = false;
    }
    return m_bConnectStatus;
}

SOCKET SocketTcpClient::getHandle()
{
    return m_fdSocket;
}

const char* SocketTcpClient::getIP()
{
    return m_szIP;
}

const char* SocketTcpClient::getErrorMsg()
{
    return m_szErrorMsg;
}


int SocketTcpClient::getPort()
{
    return m_iPort;
}

int SocketTcpClient::close()
{
    //::shutdown(m_fdSocket, 2);
    ::closesocket(m_fdSocket);
    m_bConnectStatus = false;
    //m_iPort = 0;
    //memset(m_szIP, 0, sizeof(m_szIP));
    m_fdSocket = 0;
    return 0;
}

int SocketTcpClient::connect(const char* ip, int port, int iTimeOut)
{
    char szPort[SOCKET_TCP_MAX_IP_SIZE];
    memset(szPort, 0, sizeof(szPort));
    _snprintf_s(szPort, sizeof(szPort), "%d", port);

    //先调用一次关闭
    this->close();

    //解析地址
    struct addrinfo hints;
    struct addrinfo* res = NULL;
    struct addrinfo* ressave = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    int err;
    if (0 != (err = ::getaddrinfo(ip, szPort, &hints, &res)))
    {
        int iErrorCode = ::WSAGetLastError();
        this->close();
        _snprintf_s(m_szErrorMsg, sizeof(m_szErrorMsg), "getaddrinfo error, code:%d, %d:%s", iErrorCode, err,
                    ::gai_strerrorA(err));
        return -1;
    }

    ressave = res;
    while (NULL != res)
    {
        if (SOCKET_ERROR == (m_fdSocket = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol)))
        {
            this->close();
            res = res->ai_next;
            continue;
        }

        //设置超时时间
        if (m_fdSocket > 0 && iTimeOut > 0)
        {
            //struct timeval timeo = { 0, 0 };
            //timeo.tv_sec = iTimeOut;
            //timeo.tv_usec = 0;
            int timeo = iTimeOut * 1000;//windos是毫秒，Linux是秒
            if (::setsockopt(m_fdSocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeo, sizeof(timeo)) == -1)
            {
                this->close();
                res = res->ai_next;
                continue;
            }
        }

        if (SOCKET_ERROR == ::connect(m_fdSocket, res->ai_addr, (int)res->ai_addrlen))
        {
            this->close();
            res = res->ai_next;
            continue;
        }

        break;
    }

    ::freeaddrinfo(ressave);
    if (NULL == res)
    {
        this->close();
        _snprintf_s(m_szErrorMsg, sizeof(m_szErrorMsg), "res NULL! ip:%s, port:%d", ip, port);
        return -1;
    }

    m_bConnectStatus = true;
    _snprintf_s(m_szIP, sizeof(m_szIP), "%s", ip);
    m_iPort = port;

    return 0;
}

int SocketTcpClient::connectTestPorts(const char* ip, std::vector<int>& ports, int iTimeOutSec)
{
    fd_set fdSocketSet;
    FD_ZERO(&fdSocketSet);
    
    SOCKET fdSocketList[1000];
    int nFdSocketList = 0;

    for (auto& iterCurPort = ports.begin(); iterCurPort != ports.end(); ++iterCurPort)
    {
        int iCurPort      = *iterCurPort;

        SOCKET fdSocket = INVALID_SOCKET;

        sockaddr_in res;
        res.sin_family      = AF_INET;
        res.sin_addr.s_addr = inet_addr(ip);
        res.sin_port        = htons(iCurPort);

        if (INVALID_SOCKET == (fdSocket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)))
        {
            break;
        }

        unsigned long lMode = 1;
        if (::ioctlsocket(fdSocket, FIONBIO, &lMode) < 0)
        {
            ::closesocket(fdSocket);
            fdSocket = 0;
            break;
        }

        if (SOCKET_ERROR == ::connect(fdSocket, (struct sockaddr*)&res, sizeof(res)))
        {
            int iErrorCode = ::WSAGetLastError();
            if (WSAEWOULDBLOCK != iErrorCode)
            {
                ::closesocket(fdSocket);
                fdSocket = 0;
                break;
            }
        }
        
        fdSocketList[nFdSocketList++] = fdSocket;
        FD_SET(fdSocket, &fdSocketSet);
    }
    
    struct timeval timeo = {0, 0};
    timeo.tv_sec         = iTimeOutSec;
    timeo.tv_usec        = 0;

    int nReady = ::select(0, NULL, &fdSocketSet, NULL, &timeo);
    // clean up
    for (int i = 0; i < nFdSocketList; i++)
    {
        ::closesocket(fdSocketList[i]);
        fdSocketList[i] = 0;
    }
    return nReady > 0 ? nReady : 0;
}

int SocketTcpClient::receive(void* pBuf, int nCount, int iTimeOut)
{
    //设置超时时间
    if (iTimeOut < 0)
    {
        iTimeOut = 0;
    }
    //struct timeval timeo = { 0, 0 };
    //timeo.tv_sec = iTimeOut;
    //timeo.tv_usec = 0;
    int timeo = iTimeOut * 1000;//Windows版本是毫秒，Linux是秒
    if (::setsockopt(m_fdSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeo, sizeof(timeo)) == -1)
    {
        int iErrorCode = ::WSAGetLastError();
        this->close();
        _snprintf_s(m_szErrorMsg, sizeof(m_szErrorMsg), "setsockopt error! code:%d, IP:%s, port:%d", iErrorCode, m_szIP,
                    m_iPort);
        return -1;
    }

    //接收
    int nLeft = nCount;
    char* ptr = (char*)pBuf;
    int iReadCount = 0;

    while (nLeft > 0)
    {
        int iRcv = 0;
        if ((iRcv = ::recv(m_fdSocket, ptr, nLeft, 0)) < 0)
        {
            int iErrorCode = ::WSAGetLastError();
            this->close();
            _snprintf_s(m_szErrorMsg, sizeof(m_szErrorMsg), "receive error! code:%d, IP:%s, port:%d", iErrorCode, m_szIP,
                        m_iPort);
            return -1;
        }
        else if (iRcv == 0)
        {
            return iReadCount;
        }

        nLeft -= iRcv;
        ptr += iRcv;

        iReadCount += iRcv;
    }

    return iReadCount;
}

int SocketTcpClient::receiveOnce(void* pBuf, int nCount, int iTimeOutSec)
{
    if (iTimeOutSec <= 0)
    {
        return -1;
    }
    int nReadCount = 0;
    fd_set fdSocket;
    FD_ZERO(&fdSocket);
    FD_SET(m_fdSocket, &fdSocket);

    struct timeval timeo = { 0, 0 };
    timeo.tv_sec         = iTimeOutSec;
    timeo.tv_usec = 0;
    
    fd_set fdRead = fdSocket;

    int nReady = ::select(0, &fdRead, NULL, NULL, &timeo);
    if (nReady > 0)
    {
        for (int i = 0; i < (int)fdSocket.fd_count; i++)
        {
            if (FD_ISSET(fdSocket.fd_array[i], &fdRead) == true)
            {
                int index = ::recv(fdSocket.fd_array[i], (char *)pBuf, nCount, 0);
                if (index > 0)
                {
                    ((char*)pBuf)[index] = '\0';
                    nReadCount += index;
                }
            }
        }
    }
    // no need to handling for conn reset by peer or sock error

    FD_CLR(m_fdSocket, &fdSocket);

    return nReadCount;
}

int SocketTcpClient::send(const void* pBuf, int nCount, int iTimeOut)
{
    //设置超时时间
    if (iTimeOut < 0)
    {
        iTimeOut = 0;
    }

    //struct timeval timeo = { 0, 0 };
    //timeo.tv_sec = iTimeOut;
    //timeo.tv_usec = 0;
    int timeo = iTimeOut * 1000;//windos是毫秒，Linux是秒
    if (::setsockopt(m_fdSocket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeo, sizeof(timeo)) == -1)
    {
        int iErrorCode = ::WSAGetLastError();
        this->close();
        _snprintf_s(m_szErrorMsg, sizeof(m_szErrorMsg), "setsockopt error! code:%d, IP:%s, port:%d", iErrorCode, m_szIP,
                    m_iPort);
        return -1;
    }

    //发送
    int nLeft = nCount;
    const char* ptr = (const char*)pBuf;
    int iWrittenCount = 0;

    while (nLeft > 0)
    {
        int nWritten = 0;
        if ((nWritten = ::send(m_fdSocket, ptr, nLeft, 0)) <= 0)
        {
            int iErrorCode = ::WSAGetLastError();
            this->close();
            _snprintf_s(m_szErrorMsg, sizeof(m_szErrorMsg), "send error! code:%d, IP:%s, port:%d", iErrorCode, m_szIP,
                        m_iPort);
            return -1;
        }

        nLeft -= nWritten;
        ptr += nWritten;
        iWrittenCount = nWritten;
    }
    return iWrittenCount;
}
