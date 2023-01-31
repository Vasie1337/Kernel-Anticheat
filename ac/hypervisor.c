#include "defs.h"

VOID HypervisorDetection()
{
	DbgPrintEx(0, 0, "HyperVisor Detection Started : ");

	__try {
		__vmx_vmread(0, 0);
		DbgPrint("Detected Hypervisor\n");
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {}

	DbgPrintEx(0, 0, "HyperVisor Detection Finished");
}