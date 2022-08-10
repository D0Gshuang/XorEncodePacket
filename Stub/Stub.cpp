#include "pch.h"
#include "Stub.h"

//merge 
#pragma comment(linker,"/merge:.data=.text")
#pragma comment(linker,"/merge:.rdata=.text")
#pragma comment(linker,"/section:.text,RWE")

EXTERN_C _declspec(dllexport) GLOBAL_PARAM g_stcParam = { (DWORD)Start }; //第一个成员
typedef void(*JUMPOEP)();
JUMPOEP g_Oep;
//HOOK
BYTE Ori_Code[12] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
BYTE HookCode[12] = { 0x48, 0xB8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xFF, 0xE0 };

ULONGLONG GetKernel32Address()
{
	ULONGLONG ullKernel32 = 0;
	_TEB * pTeb = NtCurrentTeb();
	PULONGLONG pPeb = (PULONGLONG)*(PULONGLONG)((ULONGLONG)pTeb + 0x60);
	PULONGLONG pLdr = (PULONGLONG)*(PULONGLONG)((ULONGLONG)pPeb + 0x18);
	PULONGLONG pInLoadOrderModuleList = (PULONGLONG)((ULONGLONG)pLdr + 0x10);
	PULONGLONG pModuleExe = (PULONGLONG)*pInLoadOrderModuleList;
	PULONGLONG pModuleNtdll = (PULONGLONG)*pModuleExe;
	PULONGLONG pModuleKernel32 = (PULONGLONG)*pModuleNtdll;
	ullKernel32 = pModuleKernel32[6];
	return ullKernel32;
}


ULONGLONG GrkGetProcAddress()
{
	ULONGLONG ullBase = GetKernel32Address();
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ullBase;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)(pDos->e_lfanew + ullBase);
	PIMAGE_DATA_DIRECTORY pExportDir = pNt->OptionalHeader.DataDirectory;
	pExportDir = &(pExportDir[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	DWORD dwOffset = pExportDir->VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(ullBase + dwOffset);
	DWORD dwFunCount = pExport->NumberOfFunctions;
	DWORD dwFunNameCount = pExport->NumberOfNames;
	DWORD dwModOffset = pExport->Name;

	PDWORD pEAT = (PDWORD)(ullBase + pExport->AddressOfFunctions);
	PDWORD pENT = (PDWORD)(ullBase + pExport->AddressOfNames);
	PWORD pEIT = (PWORD)(ullBase + pExport->AddressOfNameOrdinals);

	for (size_t i = 0; i < dwFunCount; i++)
	{
		if (!pEAT[i])
		{
			continue;
		}
		DWORD dwOrdinal = pExport->Base + i;
		ULONGLONG ullFunAddrOffset = pEAT[i];
		for (size_t index = 0; index < dwFunNameCount; index++)
		{
			if (pEIT[index] == i)
			{
				ULONGLONG ullNameOffset = pENT[index];
				char * pFunname = (char *)(((ULONGLONG)ullBase) + ullNameOffset);
				if (!strcmp(pFunname,"GetProcAddress"))
				{
					return ullBase + ullFunAddrOffset;
				}
			}
		}
	}
	return 0;
}

void XorCode()
{
	PBYTE pBase = (PBYTE)((ULONGLONG)g_stcParam.ullImageBase + g_stcParam.lpStartVA);
	for (size_t i = 0; i < g_stcParam.dwCodeSize; i++)
	{
		pBase[i] ^= g_stcParam.byXorCode;
	}
}

EXTERN_C void Start()
{
	pfnGetProcAddress = (fnGetProcAddress)GrkGetProcAddress();
	ULONGLONG ullKernelBase = GetKernel32Address();
	pfnLoadLibraryA = (fnLoadLibraryA)pfnGetProcAddress((HMODULE)ullKernelBase, "LoadLibraryA");
	fnVirtualProtect pfnVirtualProtect = (fnVirtualProtect)pfnGetProcAddress((HMODULE)ullKernelBase, "VirtualProtect");
	pfnGetModuleHandleA = (fnGetModuleHandleA)pfnGetProcAddress((HMODULE)ullKernelBase, "GetModuleHandleA");
	pfnLoadLibraryA("user32.dll");
	HMODULE hUser32 = pfnGetModuleHandleA("user32.dll");
	HMODULE hKernel32 = pfnGetModuleHandleA("kernel32.dll");
	fnMessageBoxA pfnMessageBoxA = (fnMessageBoxA)pfnGetProcAddress(hUser32, "MessageBoxA");
	fnExitProcess pfnExitProcess = (fnExitProcess)pfnGetProcAddress(hKernel32, "ExitProcess");
	int nRetCode = pfnMessageBoxA(NULL, "是否要运行", "message", MB_YESNO);
	if (nRetCode == IDYES)
	{
		ULONGLONG ullCodeBase = g_stcParam.ullImageBase + (ULONGLONG)g_stcParam.lpStartVA;
		DWORD dwOldProtect = 0;
		pfnVirtualProtect((LPBYTE)ullCodeBase, g_stcParam.dwCodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		XorCode();
		pfnVirtualProtect((LPBYTE)ullCodeBase, g_stcParam.dwCodeSize, dwOldProtect, &dwOldProtect);
		g_Oep = (JUMPOEP)(g_stcParam.ullImageBase + g_stcParam.dwOEP);
		g_Oep();
	}
	pfnExitProcess(0);
}
