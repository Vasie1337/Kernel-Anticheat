#include "defs.h"

PVOID               g_NmiCallbackHandle;
PKAFFINITY_EX       g_NmiAffinity;
PNMI_CONTEXT        g_NmiContext;
PVOID               g_PageOfpStackWalkResult;
BOOLEAN             NMIStop;
HANDLE              SendNMIThreadHandle;

BOOLEAN FireNMI(INT core, PKAFFINITY_EX affinity)
{
	KeInitializeAffinityEx(affinity);
	KeAddProcessorAffinityEx(affinity, core);

	HalSendNMI(affinity);

	return TRUE;
}

VOID DetectionThread(PVOID StartContext)
{
	UNREFERENCED_PARAMETER(StartContext);

	while (!NMIStop)
	{
		// Fire an NMI for eac core on the system with 100 ms delay
		for (ULONG i = 0; i < KeQueryActiveProcessorCountEx(0); i++)
		{
			FireNMI(i, g_NmiAffinity);
			DelayExecutionThread(100);
		}

		// Loop through the g_PageOfpStackWalkResult list
		for (INT i = 0; i < 0x1000 / 0x10; i += 2)
		{
			// Check if current item of g_PageOfpStackWalkResult is there
			if (((DWORD64*)g_PageOfpStackWalkResult)[i] == 0)
				continue;

			// Check if the stackTrace is valid and there are captured frames to loop through
			if (MmIsAddressValid(((PVOID*)g_PageOfpStackWalkResult)[i]) && ((DWORD64*)g_PageOfpStackWalkResult)[i + 1])
			{
				// Loop through the captured frames
				for (SIZE_T j = 0; i < ((DWORD64*)g_PageOfpStackWalkResult)[i + 1]; j++)
				{
					ULONG64 CurrentFrameValue = (((DWORD64**)g_PageOfpStackWalkResult)[i])[j];

					// Check if the CurrentFrameValue is an address in kernel 
					if (CurrentFrameValue < 0xFFFF000000000000)
						break;

					// Check if CurrentFrameValue is in a kernel module.
					// If not, we have found something.
					if (IsAdressOutsideModulelist(CurrentFrameValue))
						DbgPrintEx(0, 0, "Unsigned code : %llx", CurrentFrameValue);
				}
			}

			// Remove the stackTrace and the capturedFrames out of the list,
			// So the NMI callback can store new ones.
			ExFreePoolWithTag(((PVOID*)g_PageOfpStackWalkResult)[i], AC_POOL_TAG);
			((DWORD64*)g_PageOfpStackWalkResult)[i] = 0;
			((DWORD64*)g_PageOfpStackWalkResult)[i + 1] = 0;
		}
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}


BOOLEAN NmiCallback(PVOID context, BOOLEAN handled)
{
	UNREFERENCED_PARAMETER(context);
	UNREFERENCED_PARAMETER(handled);

	PVOID* stackTrace = ExAllocatePoolWithTag(NonPagedPool, 0x1000, AC_POOL_TAG);

	if (!stackTrace)
		return TRUE;

	// Captures a stack back trace by walking up the stack and recording the information for each frame 
	USHORT capturedFrames = RtlCaptureStackBackTrace(0, 0x1000 / 8, stackTrace, NULL);

	// Loop through g_PageOfpStackWalkResult list, 
	// if empty it has been checked by the DetectionThread,
	// and we can store the stackTrace and the capturedFrames in the list.
	for (int i = 0; i < 0x1000 / 0x10; i += 2)
	{
		if (((DWORD64*)g_PageOfpStackWalkResult)[i] == 0)
		{
			((DWORD64*)g_PageOfpStackWalkResult)[i] = (ULONG64)stackTrace;
			((DWORD64*)g_PageOfpStackWalkResult)[i + 1] = capturedFrames;
			break;
		}
	}

	return TRUE;
}

VOID StartNMI()
{
	DbgPrintEx(0, 0, "Started NMI callback : (Could produce false positives)");

	ULONG numCores = KeQueryActiveProcessorCountEx(0);
	ULONG nmiContextLength = numCores * sizeof(NMI_CONTEXT);

	g_NmiContext = (PNMI_CONTEXT)ExAllocatePoolWithTag(NonPagedPool, nmiContextLength, AC_POOL_TAG);
	g_NmiAffinity = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAFFINITY_EX), AC_POOL_TAG);
	g_PageOfpStackWalkResult = ExAllocatePoolWithTag(NonPagedPool, 0x1000, AC_POOL_TAG);

	g_NmiCallbackHandle = KeRegisterNmiCallback(NmiCallback, g_NmiContext);

	if (!g_NmiAffinity || !g_NmiContext || !g_NmiCallbackHandle || !g_PageOfpStackWalkResult)
		return;

	memset(g_NmiContext, 0, nmiContextLength);
	memset(g_PageOfpStackWalkResult, 0, 0x1000);

	PsCreateSystemThread(&SendNMIThreadHandle, 0, NULL, NULL, NULL, &DetectionThread, NULL);
}

VOID StopNMI()
{

	NMIStop = TRUE;
	WaitThreadTerminate(SendNMIThreadHandle);

	if (g_NmiCallbackHandle) KeDeregisterNmiCallback(g_NmiCallbackHandle);
	if (g_NmiAffinity) ExFreePoolWithTag(g_NmiAffinity, AC_POOL_TAG);
	if (g_NmiContext) ExFreePoolWithTag(g_NmiContext, AC_POOL_TAG);
	if (g_PageOfpStackWalkResult) ExFreePoolWithTag(g_PageOfpStackWalkResult, AC_POOL_TAG);

	DbgPrintEx(0, 0, "Stopped NMI callback");

}
