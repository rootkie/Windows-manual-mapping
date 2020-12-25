#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

#define GET_NT_HEADER(pBase) reinterpret_cast<PIMAGE_NT_HEADERS>(pBase + reinterpret_cast<PIMAGE_DOS_HEADER>(pBase)->e_lfanew)
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);


// parameter points to a memory region where the binary blob of DLL file is stored
// validation of DLL file is done in this function. So you don't need to check if 
// your dll file is valid beforehand.
bool ManualMap(BYTE* DllFile, UINT size);