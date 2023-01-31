#include "defs.h"

VOID CheckPhysicalMemHandles()
{
	DbgPrintEx(0, 0, "Checking PhysicalMemHandles");
	
	PVOID					   Object;
	HANDLE                     hPhysMem;
	UNICODE_STRING             phys_mem_str;
	OBJECT_ATTRIBUTES		   oaAttributes;
	PSYSTEM_HANDLE_INFORMATION handles = GetHandleList();

	RtlInitUnicodeString(&phys_mem_str, L"\\Device\\PhysicalMemory");
	InitializeObjectAttributes(&oaAttributes, &phys_mem_str, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, (HANDLE)NULL, (PSECURITY_DESCRIPTOR)NULL);
	ZwOpenSection(&hPhysMem, SECTION_ALL_ACCESS, &oaAttributes);
	ObReferenceObjectByHandle(hPhysMem, 1, NULL, KernelMode, &Object, NULL);
	ZwClose(hPhysMem);

	__try {
		for (ULONG i = 0; i < handles->uCount; i++) 
		{	
			if (handles->Handles[i].uIdProcess == 4)
				continue; 

			if (handles->Handles[i].pObject == Object) 
			{ 
				if (!ObIsKernelHandle((HANDLE)handles->Handles[i].Handle))
					DbgPrint("Usermode PhysicalMemory handle detected, pid = %d, access = 0x%x.\n", handles->Handles[i].uIdProcess, handles->Handles[i].GrantedAccess);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { }

	ObDereferenceObject(Object);

	ExFreePoolWithTag(handles, AC_POOL_TAG);

	DbgPrintEx(0, 0, "Finished Checking PhysicalMemHandles");
}