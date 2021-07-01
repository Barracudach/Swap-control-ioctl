#pragma once

//#define _DBG_

template <typename... Args>
void DBG(const char* format, Args... args)
{
#ifdef _DBG_
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, args...);
#endif 
}
