#ifndef HRATaskSchedulerDefine_h__
#define HRATaskSchedulerDefine_h__

#ifdef HRATASKSCHEDULER_API_COMPILED
#ifdef WIN32
#define HRA_TASKSCHEDULER_EXPORT __declspec(dllexport)
#else
#define HRA_TASKSCHEDULER_EXPORT
#endif
#else
#ifdef WIN32
#define HRA_TASKSCHEDULER_EXPORT __declspec(dllimport)
#else
#define HRA_TASKSCHEDULER_EXPORT extern
#endif
#endif

#endif // HRATaskSchedulerDefine_h__
