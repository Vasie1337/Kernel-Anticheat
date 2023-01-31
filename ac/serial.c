#include "defs.h"

VOID PrintBootUUID()
{	
	ULONG neededSize = 8 * 1024 * 1024;

	PSYSTEM_BOOT_ENVIRONMENT_INFORMATION pBootInfo = ExAllocatePoolWithTag(NonPagedPool, neededSize, AC_POOL_TAG);
	if (!pBootInfo)
		return;

	if (ZwQuerySystemInformation(0x5a, pBootInfo, neededSize, 0) != STATUS_SUCCESS)
		return;

	DbgPrint("UUID : %08X-%04X-%04X-%02X%02X%02X%02X%02X%02X%02X%02X\n", pBootInfo->BootIdentifier.Data1, pBootInfo->BootIdentifier.Data2, pBootInfo->BootIdentifier.Data3, pBootInfo->BootIdentifier.Data4[0], pBootInfo->BootIdentifier.Data4[1], pBootInfo->BootIdentifier.Data4[2], pBootInfo->BootIdentifier.Data4[3], pBootInfo->BootIdentifier.Data4[4], pBootInfo->BootIdentifier.Data4[5], pBootInfo->BootIdentifier.Data4[6], pBootInfo->BootIdentifier.Data4[7]);
	ExFreePoolWithTag(pBootInfo, AC_POOL_TAG);
	
}