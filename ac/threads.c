#include "defs.h"

VOID ScanSystemThreads()
{
	DbgPrintEx(0, 0, "Scanning SystemThreads : (Could produce false positives)");

	for (ULONG thrd_id = 4; thrd_id < 0x30000; thrd_id += 4)
	{
		PETHREAD ThreadObj;

		if (!NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)thrd_id, &ThreadObj)))
			continue;

		if (!PsIsSystemThread(ThreadObj) || ThreadObj == KeGetCurrentThread())
			continue;

		uintptr_t start_addr;
		GetThreadStartAddress(ThreadObj, &start_addr);

		if (IsAdressOutsideModulelist(start_addr))
			DbgPrint("Startaddress not valid : %llx", start_addr);

		if (start_addr && (memcmp((void*)start_addr, "\xFF\xE1", 2) == 0)) 
			DbgPrint("Startaddress jmp rcx : %llx", start_addr);
	}

	DbgPrintEx(0, 0, "Stopped Scanning SystemThreads");
}