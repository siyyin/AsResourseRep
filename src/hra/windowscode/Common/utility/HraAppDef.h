#ifndef _HRA_APP_DEF_
#define _HRA_APP_DEF_

//命令起始符，不用-是为了防止有些路径中带-号
#define HRA_PARAM_START "--"
// hra服务传参
#define HRA_PARAM_UUID "uuid"                 // uuid
#define HRA_PARAM_PRO_IPC_NAME "pro_ipc_name" // pro_ipc_name
#define HRA_PARAM_HRA_IPC_NAME "hra_ipc_name" // hra_ipc_name

//其他参数
#define HRA_PARAM_AIS_DIR_NAME "AsiaInfo Security" // AsiaInfo，没有程序传这个，保存配置时使用
#define HRAW_PARAM_AIS_DIR_NAME L"AsiaInfo Security" // AsiaInfo，没有程序传这个，保存配置时使用
#define HRA_PARAM_DATA_DIR "data_dir"   // data_dir，没有程序传这个，保存配置时使用
#define HRA_PARAM_WORK_DIR "work_dir"   // work_dir，没有程序传这个，保存配置时使用
#define HRA_PARAM_VERSION "hra_version"       // HRA的当前版本
#define REG_HRA_DATA_DIR L"data_dir"	// 写入注册表的指定数据名称
#define REG_HRA_SERVICE_REGISTRY_KEY L"SYSTEM\\CurrentControlSet\\Services"
#define LOG_FILE_PATH "log"				// 日志目录名称
#define LOGW_FILE_PATH L"log"           // 日志目录名称
#define HRA_PARAM_LOG_LEVEL "log_level" // 日志等级
#define HRA_PARAM_LOG_AGE "log_age"     // 日志等级生效期限：0单次生效，1永久生效，默认0
#define HRA_LOG_AGE_ONCE 0              // 日志等级生效期限，单次
#define HRA_LOG_AGE_LONG 1              // 日志等级生效期限，永久

#define DEFAULT_PRO_IPC_NAME "AsiDSIpcDSAPlugin" //默认产品端监听管道名
#define DEFAULT_HRA_IPC_NAME "AsiDSIpcHRA"       //默认hra端监听管道名
#define DEFAULT_UUID "09C6D6BF02D64A1CB3C8"      //默认UUID

//#define SZSERVICENAME						L"hragent"                            //服务程序名
//#define SZDISPLAYNAME						L"hragent"                            //标识服务的内部名
#define REQUEST_STOP_HRAGENT_EVENT			L"Global\\request_stop"  //请求停止hragent服务
//#define NOTIFY_STOP_EVENT					L"Global\\notify_stop_hragent"    //通知hragent服务已经停止



#endif
