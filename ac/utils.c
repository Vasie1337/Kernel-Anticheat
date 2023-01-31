#include "defs.h"

INT64 SecInNs(INT64 ms)
{
	return (ms * 10000);
}

VOID DelayExecutionThread(INT64 ms)
{
	LARGE_INTEGER nDelay;
	memset(&nDelay, 0, sizeof(nDelay));

	nDelay.QuadPart -= SecInNs(ms);

	KeDelayExecutionThread(KernelMode, FALSE, &nDelay);
}

VOID WaitThreadTerminate(HANDLE ThreadHandle)
{
	if (ThreadHandle != NULL)
	{
		PETHREAD ThreadObject = NULL;

		if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID*)(&ThreadObject), NULL)))
		{
			KeWaitForSingleObject((PVOID)(ThreadObject), Executive, KernelMode, FALSE, NULL);
			ObDereferenceObject((PVOID)(ThreadObject));
		}
	}
}

BOOL IsAdressOutsideModulelist(uintptr_t address)
{
	BOOLEAN OutsideModulelist = TRUE;
	PSYSTEM_MODULE_INFORMATION pSystemInfoBuffer;
	ULONG SystemInfoBufferSize = 0;

	ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &SystemInfoBufferSize);

	pSystemInfoBuffer = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, (SIZE_T)SystemInfoBufferSize * 2, AC_POOL_TAG);
	
	memset(pSystemInfoBuffer, 0, (SIZE_T)SystemInfoBufferSize * 2);
	ZwQuerySystemInformation(SystemModuleInformation, pSystemInfoBuffer, (SIZE_T)SystemInfoBufferSize * 2, &SystemInfoBufferSize);

	for (ULONG l = 0; l < pSystemInfoBuffer->Count; l++)
	{
		if (address >= (ULONG64)pSystemInfoBuffer->Module[l].ImageBase &&
			address <= (ULONG64)pSystemInfoBuffer->Module[l].ImageBase + pSystemInfoBuffer->Module[l].ImageSize)
		{
			OutsideModulelist = FALSE;
			break;
		}
	}

	return OutsideModulelist;
}

BOOL DataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask) if (*szMask == 'x' && *pData != *bMask) return 0;
    return (*szMask) == 0;
}

UINT64 FindPattern(UINT64 dwAddress, UINT64 dwLen, BYTE* bMask, char* szMask)
{
    for (UINT64 i = 0; i < dwLen; i++) if (DataCompare((BYTE*)(dwAddress + i), bMask, szMask)) return (UINT64)(dwAddress + i);
    return 0;
}

PVOID ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize)
{
    ULONG_PTR Instr = (ULONG_PTR)Instruction;
    LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
    PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

    return ResolvedAddr;
}

PVOID GetKernelBase(OUT PULONG pSize)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes = 0;
    PRTL_PROCESS_MODULES pMods = NULL;
    PVOID checkPtr = NULL;
    UNICODE_STRING routineName;
	PVOID g_KernelBase = NULL;
	ULONG g_KernelSize = 0;

    if (g_KernelBase != NULL)
    {
        if (pSize)
            *pSize = g_KernelSize;
        return g_KernelBase;
    }

    RtlUnicodeStringInit(&routineName, L"NtOpenFile");

    checkPtr = MmGetSystemRoutineAddress(&routineName);
    if (checkPtr == NULL)
        return NULL;

    status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
    if (bytes == 0)
    {
        return NULL;
    }

    pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, AC_POOL_TAG);

    status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

    if (NT_SUCCESS(status))
    {
        PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

        for (ULONG i = 0; i < pMods->NumberOfModules; i++)
        {
            if (checkPtr >= pMod[i].ImageBase &&
                checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
            {
                g_KernelBase = pMod[i].ImageBase;
                g_KernelSize = pMod[i].ImageSize;
                if (pSize)
                    *pSize = g_KernelSize;
                break;
            }
        }
    }

    if (pMods)
        ExFreePoolWithTag(pMods, AC_POOL_TAG);

    return g_KernelBase;
}

VOID GetThreadStartAddress(PETHREAD ThreadObj, uintptr_t* pStartAddr)
{
	HANDLE hThread;
	uintptr_t start_addr;
	ULONG returned_bytes;

	if (!NT_SUCCESS(ObOpenObjectByPointer(ThreadObj, OBJ_KERNEL_HANDLE, NULL, GENERIC_READ, *PsThreadType, KernelMode, &hThread)))
		return;

	if (!NT_SUCCESS(NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &start_addr, sizeof(start_addr), &returned_bytes)))
	{
		NtClose(hThread);
		return;
	}

	if (!MmIsAddressValid((void*)start_addr))
		return;

	*pStartAddr = start_addr;

	NtClose(hThread);
}

PSYSTEM_HANDLE_INFORMATION GetHandleList()
{
	ULONG neededSize = 8 * 1024 * 1024;

	PSYSTEM_HANDLE_INFORMATION pHandleList;

	pHandleList = (PSYSTEM_HANDLE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, neededSize, AC_POOL_TAG);
	ZwQuerySystemInformation(SystemHandleInformation, pHandleList, neededSize, 0);
	return pHandleList;
}