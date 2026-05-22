#ifndef DIAGENT_DIMUTEX_H
#define DIAGENT_DIMUTEX_H

#include <windows.h>
#include "comm.h"

class HRA_UTILITY_EXPORT CDIMutex
{
public:
	CDIMutex(void);
	~CDIMutex(void);

	void Lock(void);
	void UnLock(void);

private:
	CRITICAL_SECTION m_mutex;
};

class HRA_UTILITY_EXPORT CDIMutexGuard
{
public:
	CDIMutexGuard(CDIMutex& mutex);
	~CDIMutexGuard(void);

private:
	CDIMutex m_mutex;
};

#endif  // DIAGENT_MUTEX_H
