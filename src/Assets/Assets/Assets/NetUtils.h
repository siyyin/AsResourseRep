#ifndef DIAGENT_NETUTILS_H
#define DIAGENT_NETUTILS_H

#include <string>
#ifdef _WIN32
#include <cstdint>
#endif
namespace di_rest_client
{
int GetLocalIp(const char* pszDstIp, std::string& localIp, uint16_t dstPort = 6666);
int GetIPByDomian(const char *domain, char *ip);
std::string IPLongToString(unsigned int ip);
unsigned long IPStringToLong(const char* addr);
#ifdef _WIN32
bool GetAdapterAddress(std::string &sAdapterAddress);
#endif

}  // namespace di_rest_client
#endif  //DIAGENT_NETUTILS_H
