#pragma once

// 资产DB表
#ifndef GLOBAL_ASSET_TABLE
#define GLOBAL_ASSET_TABLE "GlobalAssetTable"
#endif // !GLOBAL_ASSET_TABLE
// 上报key值宏定义
#ifndef ASSET_SEQ_KEY
#define ASSET_SEQ_KEY "SequenceNumber"
#endif // !ASSET_SEQ_KEY
#ifndef ASSET_HOST_KEY
#define ASSET_HOST_KEY "HOSTINFO"
#endif // !ASSET_HOST_KEY
#ifndef ASSET_USER_KEY
#define ASSET_USER_KEY "USER"
#endif // !ASSET_USER_KEY
#ifndef ASSET_APP_KEY
#define ASSET_APP_KEY "APP"
#endif // !ASSET_APP_KEY
#ifndef ASSET_SOFTWARE_KEY
#define ASSET_SOFTWARE_KEY "SOFTWARE"
#endif // !ASSET_SOFTWARE_KEY
#ifndef ASSET_PORT_KEY
#define ASSET_PORT_KEY "portinfo"
#endif // !ASSET_PORT_KEY
#ifndef ASSET_WEBSERVICE_KEY
#define ASSET_WEBSERVICE_KEY "webserviceinfo"
#endif // !ASSET_WEBSERVICE_KEY
#ifndef ASSET_DB_KEY
#define ASSET_DB_KEY "dbinfo"
#endif // !ASSET_DB_KEY
#ifndef ASSET_AUTORUN_KEY
#define ASSET_AUTORUN_KEY "autoruninfo"
#endif // !ASSET_AUTORUN
#ifndef ASSET_CRON_KEY
#define ASSET_CRON_KEY "croninfo"
#endif // !ASSET_CRON_KEY
#ifndef ASSET_WEBSITE_KEY
#define ASSET_WEBSITE_KEY "website_info"
#endif // !ASSET_WEBSITE_KEY
#ifndef ASSET_WEBAPP_KEY
#define ASSET_WEBAPP_KEY "web_application_info"
#endif // !ASSET_WEBAPP_KEY
#ifndef ASSET_FRAMEWORK_KEY
#define ASSET_FRAMEWORK_KEY "web_framework_info"
#endif // !ASSET_FRAMEWORK_KEY
#ifndef ASSET_JAR_KEY
#define ASSET_JAR_KEY "jar_info"
#endif // !ASSET_JAR_KEY
#ifndef ASSET_THIRDPARTY_KEY
#define ASSET_THIRDPARTY_KEY "third_party_library_info"
#endif // !ASSET_THIRDPARTY
#ifndef ASSET_PROCESSLIST_KEY
#define ASSET_PROCESSLIST_KEY "process_info"
#endif // !ASSET_PROCESSLIST_KEY
#ifndef ASSET_WINDOWS_SERVICE_KEY
#define ASSET_WINDOWS_SERVICE_KEY "system_service_info"
#endif // !ASSET_WINDOWS_SERVICE


//定义资产类别位标识
#define ASSET_HOST (1 << 0)
#define ASSET_USER (1 << 1)
#define ASSET_APP (1 << 2)
#define ASSET_SOFTWARE (1 << 3)
#define ASSET_PACKAGE (1 << 4)
#define ASSET_PORT (1 << 5)
#define ASSET_WEBSERVICE (1 << 6)
#define ASSET_DB (1 << 7)
#define ASSET_AUTORUN (1 << 8)
#define ASSET_CRON (1 << 9)
#define ASSET_WEBSITE (1 << 11)
#define ASSET_WEBAPP (1 << 12)
#define ASSET_WEBFRAMEWORK (1 << 13)
#define ASSET_JAR (1 << 14)
#define ASSET_THIRDPARTY (1 << 15)
#define ASSET_PROCESSLIST (1 << 16)
#define ASSET_WINDOWS_SERVICE (1 << 17)
