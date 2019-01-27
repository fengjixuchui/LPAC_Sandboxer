#include <windows.h>
#include <strsafe.h>
#include <Sddl.h>
#include <Userenv.h>

#pragma comment(lib, "Userenv.lib")

WCHAR container_name[] = L"Sandbox";
WCHAR container_desc[] = L"Windows LPAC sandbox";

BOOL SetSecCapabilities(PSID sid, SECURITY_CAPABILITIES *capabiliti);

BOOL Sandboxed(CHAR *path)
{
  PSID pSid = NULL;
	SIZE_T sz_attr = 0;
	CHAR *str_sid = nullptr;
  SECURITY_CAPABILITIES secap = {0};
  STARTUPINFOEXA startup = {0};
  PROCESS_INFORMATION process = {0};


  switch(HRESULT_CODE(CreateAppContainerProfile(container_name, container_name, container_desc, NULL, 0, &pSid)))
  {
		case ERROR_ALREADY_EXISTS:
        if(HRESULT_CODE(DeriveAppContainerSidFromAppContainerName(container_name, &pSid)) == E_INVALIDARG)
        printf("The ContainerName parameter, or the ContainerSid parameter is either NULL or not valid\n");
        break;

		case S_OK:
				break;

		case E_ACCESSDENIED:
				printf("The caller does not have permission to create the profile\n");
				break;

		case E_INVALIDARG:
				printf("Problem with contaner name\n");
			  break;
  }

  if(!SetSecCapabilities(pSid, &secap))
        {
          printf("SetSecurityCapabilities failed, last error: %d\n", GetLastError());
          return FALSE;
        }

  if (InitializeProcThreadAttributeList(NULL,
			1,
			NULL,
			&sz_attr))
		    {
			     printf("1. InitializeProcThreadAttributeList() failed, last error: %d \n", GetLastError());
			     return FALSE;
		    }


  if(!InitializeProcThreadAttributeList(startup.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(sz_attr),
			1,
			NULL,
			&sz_attr))
        {
            printf("2. InitializeProcThreadAttributeList() failed, last error: %d", GetLastError());
			      return FALSE;
        }

  if(!UpdateProcThreadAttribute(startup.lpAttributeList,
			0,
			PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
			&secap,
			sizeof(secap),
			NULL,
			NULL))
        {
            printf("UpdateProcThreadAttribute() failed, last error: %d", GetLastError());
			      return FALSE;
        }

  if(!CreateProcessA(path,
			NULL,
			NULL,
			NULL,
			FALSE,
			EXTENDED_STARTUPINFO_PRESENT,
			NULL,
			NULL,
			(LPSTARTUPINFOA)&startup,
			&process))
      {
        printf("Failed to create process %s, last error: %d\n", path, GetLastError());
			  return FALSE;
      }

	printf("Less Privileged App Container (LPAC) name: %ws\n", container_name);
	printf("Less Privileged App Container (LPAC) description: %ws\n", container_desc);

	if (ConvertSidToStringSidA(pSid, &str_sid))
		printf("SID: %s\n\n", str_sid);

	if (str_sid)
		LocalFree(str_sid);

    printf("%s sandboxed in LPAC\n", path);

    if(startup.lpAttributeList)
        DeleteProcThreadAttributeList(startup.lpAttributeList);

    if(secap.Capabilities)
        free(secap.Capabilities);

    if(pSid)
        FreeSid(pSid);

    return TRUE;
}

BOOL SetSecCapabilities(PSID container_sid, SECURITY_CAPABILITIES *capabilities)
{
  SID_AND_ATTRIBUTES *attr = nullptr;
	DWORD szSid = SECURITY_MAX_SID_SIZE;

  attr = (SID_AND_ATTRIBUTES *)malloc(sizeof(SID_AND_ATTRIBUTES));

  ZeroMemory(capabilities, sizeof(SECURITY_CAPABILITIES));
  ZeroMemory(attr, sizeof(SID_AND_ATTRIBUTES));

  attr[0].Sid = malloc(SECURITY_MAX_SID_SIZE);

	if (!CreateWellKnownSid(WinCapabilityPrivateNetworkClientServerSid,
		NULL,
		attr[0].Sid,
		&szSid))
	{
	if (attr[0].Sid)
					LocalFree(attr[0].Sid);

	free(attr);
	attr = NULL;
	printf("CreateWellKnownSid() failed, last error: %d", GetLastError());
	return FALSE;
	}

  attr[0].Attributes = SE_GROUP_ENABLED;

	capabilities->CapabilityCount = 1;
  capabilities->Capabilities = attr;
	capabilities->AppContainerSid = container_sid;

  return TRUE;
}
