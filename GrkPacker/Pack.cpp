#include "pch.h"
#include "Pack.h"
#include <Psapi.h>
#pragma comment(lib,"psapi.lib")
#include "../Stub/Stub.h"
#pragma comment(lib,"../x64/release/Stub.lib")

CFile FileObject;
PBYTE pFileBase = NULL;
DWORD dwFileSize = 0;
PIMAGE_NT_HEADERS64 pNt = NULL;
DWORD  dwFileAlign;
DWORD dwMemAlign;
ULONGLONG ullImageBase;
DWORD dwOEP;
DWORD dwCodeBase;
DWORD dwCodeSize;
PIMAGE_SECTION_HEADER pLastSection;
DWORD dwNewSectionRVA;
DWORD g_dwNewOEP;

BOOL Pack(CString szFilePath, BYTE byXorCode)
{
	BOOL bRet = FALSE;
	bRet = InitPE(szFilePath);   //得到了要加壳文件的PE信息和我们新区段的起始RVA
	DWORD dwVirtualAddress = XorCode(byXorCode);   //加密要加壳文件的代码段,返回加密文件代码段的RVA
	HMODULE hModule = LoadLibrary(L"Stub.dll");
	PGLOBAL_PARAM pstcParam = (PGLOBAL_PARAM)GetProcAddress(hModule, "g_stcParam");  //获取stub导出的结构，把刚才获取到的源文件的PE信息全部填进去
	pstcParam->ullImageBase = ullImageBase;
	pstcParam->dwCodeSize = dwCodeSize;
	pstcParam->dwOEP = dwOEP;
	pstcParam->byXorCode = byXorCode;
	pstcParam->lpStartVA = (PBYTE)dwVirtualAddress;

	MODULEINFO modInfo = { 0 };
	GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));  
	PBYTE lpModule = new BYTE[modInfo.SizeOfImage];
	memcpy_s(lpModule, modInfo.SizeOfImage, hModule, modInfo.SizeOfImage);  //将stub的信息拷贝到内存里
	PBYTE pCodeSection = NULL;
	DWORD dwCodeBaseRva = 0;
	DWORD dwSize = GetSectionData(lpModule, 0, pCodeSection, dwCodeBaseRva);  //dwSize = stub的size pCodeSection = stub代码段VA dwCodeBaseRva = stub代码段RVA
	FixReloc(lpModule, pCodeSection, dwNewSectionRVA);  //将stub的代码段的VA进行重定位

	DWORD dwStubOEPRva = pstcParam->dwStart - (DWORD)hModule;
	DWORD dwNewOEP = dwStubOEPRva - dwCodeBaseRva;   //计算出start函数在段中的绝对RVA
	g_dwNewOEP = dwNewOEP;
	pNt->OptionalHeader.DllCharacteristics = 0;  //关闭随机基址 
	ClearBundleImport();  //清楚绑定导入表

	if (AddSection(pCodeSection,dwSize,"GrkPack"))
	{
		bRet = TRUE;
	}
	delete lpModule;
	lpModule = NULL;
	return TRUE;
}

BOOL InitPE(CString szFilePath)
{
	if (FileObject.m_hFile == INVALID_HANDLE_VALUE && pFileBase)
	{
		//Close()
		FileObject.Close();
		delete pFileBase;
		pFileBase = NULL;
	}
	FileObject.Open(szFilePath, CFile::modeRead);
	dwFileSize = FileObject.GetLength();
	pFileBase = new BYTE[dwFileSize];
	if (FileObject.Read(pFileBase, (DWORD)dwFileSize))
	{
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBase;
		pNt = (PIMAGE_NT_HEADERS64)((ULONGLONG)pFileBase + pDos->e_lfanew);
		dwFileAlign = pNt->OptionalHeader.FileAlignment;  //文件对齐
		dwMemAlign = pNt->OptionalHeader.SectionAlignment; //内存对齐
		ullImageBase = pNt->OptionalHeader.ImageBase;  //模块基地址
		dwOEP = pNt->OptionalHeader.AddressOfEntryPoint; //入口点RVA
		dwCodeBase = pNt->OptionalHeader.BaseOfCode;  // 代码段RVA
		dwCodeSize = pNt->OptionalHeader.SizeOfCode;  // 代码段大小

		PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);  
		pLastSection = &pSection[pNt->FileHeader.NumberOfSections];  //最后一个区段的

		DWORD dwVirtualSize = pLastSection[-1].Misc.VirtualSize; //计算前一个区段的对齐，我们要在其之后插入新区段
		if (dwVirtualSize % dwMemAlign)
		{
			dwVirtualSize = (dwVirtualSize / dwMemAlign + 1) * dwMemAlign;
		}
		else
		{
			dwVirtualSize = (dwVirtualSize / dwMemAlign) * dwMemAlign;
		}
		dwNewSectionRVA = pLastSection[-1].VirtualAddress + dwVirtualSize;  //新区段的起始RVA = 最后一个区段RVA + 对齐后的最后一个区段的大小
		return TRUE;
	}
	return FALSE;


}

DWORD XorCode(BYTE byXorCode)
{
	DWORD dwVirtualAddress = dwCodeBase;   //file
	DWORD dwOffset = RvaToOffset(dwCodeBase, pNt);
	if (!dwOffset)
	{
		PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
		dwOffset = RvaToOffset(pSection[1].VirtualAddress, pNt);
		dwVirtualAddress = pSection[1].VirtualAddress;
	}
	PBYTE pBase = (PBYTE)((ULONGLONG)pFileBase + dwOffset);  //获取text段的内存RVA，然后进行异或加密
	for (size_t i = 0; i < dwCodeSize; i++)
	{
		pBase[i] ^= byXorCode;
	}
	return dwVirtualAddress;

}

DWORD RvaToOffset(DWORD dwRva, PIMAGE_NT_HEADERS64 pNT)
{
	DWORD dwOffset = 0;
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	DWORD dwSectionCount = pNt->FileHeader.NumberOfSections;
	for (size_t i = 0; i < dwSectionCount; i++)
	{
		if (dwRva >= pSection[i].VirtualAddress && dwRva < (pSection[i].VirtualAddress + pSection[i].Misc.VirtualSize))
		{
			dwOffset = dwRva - pSection[i].VirtualAddress + pSection[i].PointerToRawData;
			return dwOffset;
		}
	}
	return dwOffset;
}

DWORD GetSectionData(PBYTE lpImage, DWORD dwSectionIndex, PBYTE & lpBuffer, DWORD & dwCodeBaseRVA)
{   //获取stub的代码段信息

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpImage;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)((ULONGLONG)lpImage + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	DWORD dwSize = pSection[0].SizeOfRawData; //stub代码段大小
	dwCodeBaseRVA = pSection[0].VirtualAddress; //stub代码段RVA
	lpBuffer = (PBYTE)(lpImage + dwCodeBaseRVA); //stub代码段VA
	return dwSize;
}

VOID FixReloc(PBYTE lpImage, PBYTE lpCode, DWORD dwCodeRVA)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpImage;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)((ULONGLONG)lpImage + pDos->e_lfanew);
	PIMAGE_DATA_DIRECTORY pRelocDir = pNt->OptionalHeader.DataDirectory;
	pRelocDir = &(pRelocDir[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((ULONGLONG)lpImage + pRelocDir->VirtualAddress);
	typedef struct {
		WORD Offset : 12;
		WORD Type : 4;
	}TypeOffset,*PTypeOffset;
	while (pReloc->VirtualAddress)
	{
		PTypeOffset pTypeOffset = (PTypeOffset)(pReloc + 1);
		ULONGLONG ullSize = sizeof(IMAGE_BASE_RELOCATION);
		ULONGLONG ullCount = (pReloc->SizeOfBlock - ullSize) / 2;
		for (size_t i = 0; i < ullCount; i++)
		{
			if (*(PULONGLONG)(&pTypeOffset[i]) == NULL)
			{
				break;
			}
			ULONGLONG ullRva = pReloc->VirtualAddress + pTypeOffset[i].Offset;
			PULONGLONG ullRelocAddr = (PULONGLONG)((ULONGLONG)lpImage + ullRva);
			ULONGLONG ullRelocCode = *ullRelocAddr - pNt->OptionalHeader.ImageBase - pNt->OptionalHeader.BaseOfCode + dwCodeRVA + ullImageBase;
			*ullRelocAddr = ullRelocCode;
		}
		pReloc = (PIMAGE_BASE_RELOCATION)((ULONGLONG)pReloc + pReloc->SizeOfBlock);

		if (pReloc->VirtualAddress == 0xfdfdfdfd)
		{
			break;
		}
	}
}

VOID ClearBundleImport()
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBase;
	PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)((ULONGLONG)pFileBase + pDos->e_lfanew);
	PIMAGE_DATA_DIRECTORY pDir = pNt->OptionalHeader.DataDirectory;
	ZeroMemory(&(pDir[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]), sizeof(IMAGE_DATA_DIRECTORY));
}

ULONGLONG AddSection(LPBYTE pBuffer, DWORD dwSize, PCHAR szSectionName)
{
	pNt->FileHeader.NumberOfSections++;
	memset(pLastSection, 0, sizeof(IMAGE_SECTION_HEADER));
	strcpy_s((char *)pLastSection->Name, IMAGE_SIZEOF_SHORT_NAME, szSectionName);
	DWORD dwVartualSize = 0;
	DWORD dwSizeOfRawData = 0;
	DWORD dwSizeOfImage = pNt->OptionalHeader.SizeOfImage;
	{
		if (dwSizeOfImage % dwMemAlign)
		{
			dwSizeOfImage = (dwSizeOfImage / dwMemAlign + 1) * dwMemAlign;
		}
		else
		{
			dwSizeOfImage = (dwSizeOfImage / dwMemAlign) * dwMemAlign;
		}

		if (dwSize % dwMemAlign)
		{
			dwVartualSize = (dwSize / dwMemAlign + 1) * dwMemAlign;
		}
		else
		{
			dwVartualSize = (dwSize / dwMemAlign) * dwMemAlign;
		}

		if (dwSize % dwFileAlign)
		{
			dwSizeOfRawData = (dwSize / dwFileAlign + 1) * dwFileAlign;
		}
		else
		{
			dwSizeOfRawData = (dwSize / dwFileAlign) * dwFileAlign;
		}
	}

	pLastSection->VirtualAddress = dwSizeOfImage;
	pLastSection->PointerToRawData = dwFileSize;
	pLastSection->SizeOfRawData = dwSizeOfRawData;
	pLastSection->Misc.VirtualSize = dwVartualSize;
	pLastSection->Characteristics = 0xE0000040;

	pNt->OptionalHeader.SizeOfImage = dwSizeOfImage + dwVartualSize;  //新的大小 = 原来的大小 + 新区段的大小
	pNt->OptionalHeader.AddressOfEntryPoint = g_dwNewOEP + pLastSection->VirtualAddress;  //新的OEP RVA = 最后一个区段的起始RVA + 新增区段的RVA

	CString csWriteFilePath = FileObject.GetFilePath();
	CString WriteFilePath = csWriteFilePath.Left(csWriteFilePath.ReverseFind('.')) + "_GrkPack.exe";

	CFile hFile(WriteFilePath.GetBuffer(0), CFile::modeCreate | CFile::modeReadWrite);
	hFile.Write(pFileBase, dwFileSize);
	hFile.SeekToEnd();
	hFile.Write(pBuffer, dwSize);

	return pLastSection->VirtualAddress;
	
}



