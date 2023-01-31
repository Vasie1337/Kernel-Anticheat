#include "defs.h"

VOID ScanBigPool()
{
	DbgPrintEx(0, 0, "Scanning Big Pool :");

	ULONG len = 4 * 1024 * 1024;
	PVOID mem = ExAllocatePoolWithTag(NonPagedPool, len, AC_POOL_TAG);

	if (!NT_SUCCESS(ZwQuerySystemInformation(0x42, mem, len, &len)))
		return;

	PSYSTEM_BIGPOOL_INFORMATION pBuf = (PSYSTEM_BIGPOOL_INFORMATION)mem;
	for (ULONG i = 0; i < pBuf->Count; i++) {
		__try {

			if (pBuf->AllocatedInfo[i].TagULong != 'SldT')
				return;

			DbgPrint("[FLAG] TdlS pooltag detected\n");

			PVOID page = MmMapIoSpaceEx(MmGetPhysicalAddress((void*)pBuf->AllocatedInfo[i].VirtualAddress), PAGE_SIZE, PAGE_READWRITE);

			if ((uintptr_t)page + 0x184 == 0x0B024BC8B48)
				DbgPrint("[DETECTION] 0x0B024BC8B48 found at pool + 0x184\n");

			MmUnmapIoSpace(page, PAGE_SIZE);

		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
		}
	}

	ExFreePoolWithTag(mem, AC_POOL_TAG);

	DbgPrintEx(0, 0, "Finished Scanning Big Pool :");
}