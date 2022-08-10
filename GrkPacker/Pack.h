#pragma once


EXTERN_C BOOL Pack(CString szFilePath, BYTE byXorCode);
EXTERN_C BOOL InitPE(CString szFilePath);
EXTERN_C DWORD XorCode(BYTE byXorCode);
EXTERN_C DWORD RvaToOffset(DWORD dwRva, PIMAGE_NT_HEADERS64 pNT);
EXTERN_C DWORD GetSectionData(PBYTE lpImage, DWORD dwSectionIndex, PBYTE & lpBuffer, DWORD & dwCodeBaseRVA);
EXTERN_C VOID FixReloc(PBYTE lpImage, PBYTE lpCode, DWORD dwCodeRVA);
EXTERN_C VOID ClearBundleImport();
EXTERN_C ULONGLONG AddSection(LPBYTE pBuffer, DWORD dwSize, PCHAR szSectionName);