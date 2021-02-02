#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#define WINVER 0x0601
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include "Utils/MemoryMgr.h"
#include "Utils/Trampoline.h"
#include "Utils/Patterns.h"


//
// Usage: SetThreadName ((DWORD)-1, "MainThread");
//
#include <windows.h>
const DWORD MS_VC_EXCEPTION = 0x406D1388;
#pragma pack(push,8)
typedef struct tagTHREADNAME_INFO
{
    DWORD dwType; // Must be 0x1000.
    LPCSTR szName; // Pointer to name (in user addr space).
    DWORD dwThreadID; // Thread ID (-1=caller thread).
    DWORD dwFlags; // Reserved for future use, must be zero.
} THREADNAME_INFO;
#pragma pack(pop)
void SetThreadName(DWORD dwThreadID, const char* threadName) {
    THREADNAME_INFO info;
    info.dwType = 0x1000;
    info.szName = threadName;
    info.dwThreadID = dwThreadID;
    info.dwFlags = 0;
#pragma warning(push)
#pragma warning(disable: 6320 6322)
    __try{
        RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
    }
    __except (EXCEPTION_EXECUTE_HANDLER){
    }
#pragma warning(pop)
}

static HANDLE WINAPI CreateThread_SetDesc(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
								DWORD dwCreationFlags, LPDWORD lpThreadId)
{
	DWORD threadId;
	HANDLE result = CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, &threadId);
	if ( result != nullptr )
	{
		const uintptr_t threadNameAddr = reinterpret_cast<uintptr_t>(lpParameter) + 4;
		const char* threadName = reinterpret_cast<const char*>(threadNameAddr);

		SetThreadName(threadId, threadName);
	}
	if ( lpThreadId != nullptr ) *lpThreadId = threadId;

	return result;
}



void OnInitializeHook()
{
	std::unique_ptr<ScopedUnprotect::Unprotect> Protect = ScopedUnprotect::UnprotectSectionOrFullModule( GetModuleHandle( nullptr ), ".text" );

	using namespace Memory;
	using namespace hook;
	
	// Restore thread names	
	if ( auto createThreadPattern = pattern( "48 89 43 20 48 85 C0 74 5D" ).count(1); createThreadPattern.size() == 1 )
	{
		auto addr = createThreadPattern.get_first( -6 + 2 );

		Trampoline* hop = Trampoline::MakeTrampoline( addr );

		void** funcPtr = hop->Pointer<void*>();
		*funcPtr = &CreateThread_SetDesc;
		WriteOffsetValue( addr, funcPtr );
	}

}
