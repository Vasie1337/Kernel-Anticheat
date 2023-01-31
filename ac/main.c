#include "defs.h"

VOID DriverUnload(PDRIVER_OBJECT drvObj)
{
	UNREFERENCED_PARAMETER(drvObj);
	
	StopNMI();

	DbgPrintEx(0, 0, "========   Vasie Meme Anticheat Unloaded   ========\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drvObj, PUNICODE_STRING regPath)
{
	UNREFERENCED_PARAMETER(regPath);

	drvObj->DriverUnload = DriverUnload;

    DbgPrintEx(0, 0, "========   Vasie Meme Anticheat Entry   ========\n");

	PrintBootUUID();
	
	ScanSystemThreads();
	ScanBigPool();

	CheckPhysicalMemHandles();
    CheckPIDDBCacheTable();
	
	HypervisorDetection();

	StartNMI();

	return STATUS_SUCCESS;
}