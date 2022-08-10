#pragma once

EXTERN_C
{
	typedef struct _GLOBAL_PARAM
	{
		//���е�OEP
		DWORD dwStart;
		//ӳ���ַ
		ULONGLONG ullImageBase;
		//����OEP
		DWORD dwOEP;
		//�������������ʼ��ַ
		PBYTE lpStartVA;
		//������������ֽ���
		DWORD dwCodeSize;
		//���ʹ�õĵļ���Key
		BYTE byXorCode;
	}GLOBAL_PARAM,*PGLOBAL_PARAM;

}

EXTERN_C typedef FARPROC(WINAPI * fnGetProcAddress)(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);
EXTERN_C typedef HMODULE(WINAPI * fnLoadLibraryA)(_In_ LPCSTR lpLibFileName);
EXTERN_C typedef HMODULE(WINAPI * fnGetModuleHandleA)(_In_opt_ LPCSTR lpModuleName);
EXTERN_C typedef BOOL(WINAPI *fnVirtualProtect)(_In_  LPVOID lpAddress, _In_  SIZE_T dwSize, _In_  DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
EXTERN_C typedef int (WINAPI * fnMessageBoxA)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);
EXTERN_C typedef VOID(WINAPI * fnExitProcess)(_In_ UINT uExitCode);
EXTERN_C typedef BOOL(WINAPI* fnWriteProcessMemory)(_In_ HANDLE hProcess,_In_ LPVOID lpBaseAddress,_In_reads_bytes_(nSize) LPCVOID lpBuffer,_In_ SIZE_T nSize,_Out_opt_ SIZE_T* lpNumberOfBytesWritten);
EXTERN_C typedef BOOL(WINAPI* fnReadProcessMemory)(_In_ HANDLE hProcess,_In_ LPCVOID lpBaseAddress,_Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,_In_ SIZE_T nSize,_Out_opt_ SIZE_T* lpNumberOfBytesRead);

fnGetProcAddress pfnGetProcAddress;
fnLoadLibraryA pfnLoadLibraryA;
fnGetModuleHandleA pfnGetModuleHandleA;
fnWriteProcessMemory pfnWriteProcessMemory;
fnReadProcessMemory pfnReadProcessMemory;

EXTERN_C void Start();


