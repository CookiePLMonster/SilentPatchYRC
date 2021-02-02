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

namespace MessagePumpFixes
{
	BOOL WINAPI PeekMessageA_WaitForMessages( LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg )
	{
		// This function is only ever called from a single thread, so a static variable is acceptable
		static bool shouldWaitForMessages = false;

		if ( std::exchange(shouldWaitForMessages, false) )
		{
			GetMessageA( lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax );
			return TRUE; // GetMessage definitely processed a message
		}

		const BOOL result = PeekMessageA( lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg );
		shouldWaitForMessages = result == FALSE;
		return result;
	}
};


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


	// Message pump thread using less CPU time
	if ( auto peekMessage = pattern( "FF 15 ? ? ? ? 85 C0 74 16" ).count(1); peekMessage.size() == 1 )
	{
		using namespace MessagePumpFixes;

		auto match = peekMessage.get_one();
		Trampoline* trampoline = Trampoline::MakeTrampoline( match.get<void*>() );

		void** funcPtr = trampoline->Pointer<void*>();
		*funcPtr = &PeekMessageA_WaitForMessages;
		WriteOffsetValue( match.get<void*>( 2 ), funcPtr );

		const uint8_t elseStatementPayload[] = {
			0xFF, 0x15, 0x0, 0x0, 0x0, 0x0, // call ds:[DispatchMessageA]
			0xE9, 0x0, 0x0, 0x0, 0x0 // jmp loc_1404CF4A0
		};

		auto space = reinterpret_cast<uint8_t*>(trampoline->Pointer<decltype(elseStatementPayload)>());
		memcpy( space, elseStatementPayload, sizeof(elseStatementPayload) );

		// Fill pointers accordingly and redirect to payload
		void* orgDispatchMessage;
		ReadOffsetValue( match.get<void*>( 0x1A + 2 ), orgDispatchMessage );
		WriteOffsetValue( space + 2, orgDispatchMessage );
		WriteOffsetValue( space + 6 + 1, match.get<void*>( -0x28 ) );

		InjectHook( match.get<void*>( 0x1A ), space, PATCH_JUMP );
	}

}
