#include "defs.h"

VOID CheckPIDDBCacheTable()
{
    DbgPrintEx(0, 0, "Scanning PIDDBCacheTable : ");
    
    PVOID base = GetKernelBase(NULL);
    if (!base)
        return;

    UINT64 PiDDBLockPtr = FindPattern((UINT64)base, (UINT64)0xFFFFFFFFFF, (BYTE*)"\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C", "xxx????x????xxx");
    if (!PiDDBLockPtr)
        return;

    UINT64 PiDDBCacheTablePtr = FindPattern((UINT64)base, (UINT64)0xFFFFFFFFFF, (BYTE*)"\x66\x03\xD2\x48\x8D\x0D", "xxxxxx");
    if (!PiDDBCacheTablePtr)
        return;

    PERESOURCE PiDDBLock; PRTL_AVL_TABLE table;

    PiDDBCacheTablePtr = ((uintptr_t)PiDDBCacheTablePtr + 3);

    PiDDBLock = (PERESOURCE)(ResolveRelativeAddress((PVOID)PiDDBLockPtr, 3, 7));
    table = (PRTL_AVL_TABLE)(ResolveRelativeAddress((PVOID)PiDDBCacheTablePtr, 3, 7));

    ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);

    for (PiDDBCacheEntry* p = (PiDDBCacheEntry*)RtlEnumerateGenericTableAvl(table, TRUE);
        p != NULL;
        p = (PiDDBCacheEntry*)RtlEnumerateGenericTableAvl(table, FALSE)) {
        if (p->TimeDateStamp == 0x5284eac3)
            DbgPrint("kdmapper detected, driver: %wZ\n", p->DriverName);
        if (p->TimeDateStamp == 0x57CD1415)
            DbgPrint("drvmap detected, driver: %wZ\n", p->DriverName);
    }

    ExReleaseResourceLite(PiDDBLock);
    
    DbgPrintEx(0, 0, "Finished Scanning PIDDBCacheTable");
}
