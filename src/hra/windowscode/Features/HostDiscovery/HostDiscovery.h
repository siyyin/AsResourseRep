#ifndef _HOST_DISCOVERY_H_
#define _HOST_DISCOVERY_H_

#include "json/json.h"
#include "utility/comm.h"
#include "utility/HraReport.h"
#include "utility/HraTaskType.h"
#include "HRATaskScheduler\HRATaskScheduler.h"

#ifdef HRA_HOST_DISCOVERY_API_COMPILED
#ifdef WIN32
#define HRA_HOST_DISCOVERY_EXPORT __declspec(dllexport)
#else
#define HRA_HOST_DISCOVERY_EXPORT
#endif
#else
#ifdef WIN32
#define HRA_HOST_DISCOVERY_EXPORT __declspec(dllimport)
#else
#define HRA_HOST_DISCOVERY_EXPORT extern
#endif
#endif

int HRA_HOST_DISCOVERY_EXPORT HostDiscoveryInit(void);
int HRA_HOST_DISCOVERY_EXPORT HostDiscoveryDestroy(void);
int HRA_HOST_DISCOVERY_EXPORT HostDiscoveryCfgHandle(const Json::Value& jsContent);

int HRA_HOST_DISCOVERY_EXPORT HostDiscoveryCancelInit(void);
int HRA_HOST_DISCOVERY_EXPORT HostDiscoveryCancelDestroy(void);
int HRA_HOST_DISCOVERY_EXPORT HostDiscoveryCancelHandle(const Json::Value& jsContent);
#endif /* _HOST_DISCOVERY_H_ */