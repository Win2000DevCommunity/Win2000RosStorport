#ifndef FKRN_LIMP_H
#define FKRN_LIMP_H

#include <ntddk.h>  
#include <wdm.h>    

#include <stdarg.h>  // For va_list
// Declare the functions
KIRQL NTAPI
PoAcquireInterruptSpinLock(IN PKINTERRUPT Interrupt);
VOID NTAPI
PoReleaseInterruptSpinLock(IN PKINTERRUPT Interrupt, IN KIRQL OldIrql);
ULONG NTAPI
PovDbgPrintExWithPrefix(IN LPCSTR Prefix, IN ULONG ComponentId, IN ULONG Level, IN LPCSTR Format, IN va_list ap);






typedef struct _KINTERRUPT
{
    CSHORT Type;
    CSHORT Size;
    LIST_ENTRY InterruptListEntry;
    PKSERVICE_ROUTINE ServiceRoutine;
    PVOID ServiceContext;
    KSPIN_LOCK SpinLock;
    ULONG TickCount;
    PKSPIN_LOCK ActualLock;
    PKINTERRUPT_ROUTINE DispatchAddress;
    ULONG Vector;
    KIRQL Irql;
    KIRQL SynchronizeIrql;
    BOOLEAN FloatingSave;
    BOOLEAN Connected;
    CCHAR Number;
    BOOLEAN ShareVector;
    KINTERRUPT_MODE Mode;
    ULONG ServiceCount;
    ULONG DispatchCount;
} KINTERRUPT, *PKINTERRUPT;


#endif // FKRN_LIMP_H
