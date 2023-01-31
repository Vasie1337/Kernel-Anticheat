# Kernel-Anticheat - Check your detection vectors

Why?
I saw the thread of apexlegends and i thought it was pretty cool so i tried to improve his code a bit and add some more features. All the credits go to him because this was his idea. Ill add try to add more features later on.

Features :
-NMI StackWalking
-Hypervisor Detection
-Big Pool scanning
-UUID
-Scanning system threads
-Checking PIDDBCacheTable for KDmapper & Drvmap

The NMI Stackwalking :
First we register an NMI callback that will be called when a hardware interupt occurs. inside the NMI callback you can see we capture the stack using RtlCaptureStackBackTrace and store the results in a list. 

BOOLEAN NmiCallback(PVOID context, BOOLEAN handled)
{
	UNREFERENCED_PARAMETER(context);
	UNREFERENCED_PARAMETER(handled);

	PVOID* stackTrace = ExAllocatePoolWithTag(NonPagedPool, 0x1000, AC_POOL_TAG);

	if (!stackTrace)
		return TRUE;

	//Walk the stack and record information for each frame
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

Then when we get the results inside our list we can iterate through it and check one of the frame values is not in a valid module.

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
    
At last we can fire an NMI using HalSendNMI whenever we want to.

BOOLEAN FireNMI(INT core, PKAFFINITY_EX affinity)
{
	KeInitializeAffinityEx(affinity);
	KeAddProcessorAffinityEx(affinity, core);

	HalSendNMI(affinity);

	return TRUE;
}

// Fire an NMI for eac core on the system with 100 ms delay
for (ULONG i = 0; i < KeQueryActiveProcessorCountEx(0); i++)
{
	FireNMI(i, g_NmiAffinity);
	DelayExecutionThread(100);
}

Credits :
The idea and most of the code are from apexlegends 

Todo :
- Improve the NMI callback
- Improve the SystemThread scanning 
- Maybe add more features
