#include <Windows.h>
#include <stdio.h>
#define H_FUNC_VIRTUALALLOC 0x97bc257
#define H_MODULE_KERNEL32 0xadd31df0

typedef LPVOID (WINAPI * fnVirtualAlloc)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY  InLoadOrderLinks;
    LIST_ENTRY  InMemoryOrderLinks;
    LIST_ENTRY  InInitializationOrderLinks;
    PVOID       DllBase;
    PVOID       EntryPoint;
    ULONG       SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN       InheritedAddressSpace;
    BOOLEAN       ReadImageFileExecOptions;
    BOOLEAN       BeingDebugged;
    BOOLEAN       Spare;
    HANDLE        Mutant;
    PVOID         ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;


UINT_PTR HashString(LPVOID string, BOOL isWide)
{
    ULONG Hash = 5381;
    PUCHAR Ptr = string;
    
    do
    {   
        UCHAR c = *Ptr;  

        if (!*Ptr && !isWide)
        {
            break;
        }

        if (c >= 'a')
        {
            c -= 0x20;
        }

        Hash = ((Hash << 5) + Hash) + c;
        
        if (isWide && (!*Ptr && !*++Ptr)){
            break;
        }

        ++Ptr;
        
    } while (TRUE);
    
    return Hash;
}

PVOID GetExportAddress(PVOID pModuleBase, UINT_PTR dwFunctionHash) 
{

    PIMAGE_DOS_HEADER pImageDOSHeader = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pImageDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }

    PIMAGE_NT_HEADERS pImageNTHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pImageDOSHeader + pImageDOSHeader->e_lfanew);
    if (pImageNTHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return NULL;
    }

    DWORD exportRVA = pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if(!exportRVA)
    {
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY pImageExportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)pModuleBase + exportRVA);

    PDWORD pAddressTable  = (PDWORD)((PUCHAR)pModuleBase + pImageExportDir->AddressOfFunctions);
    PDWORD pNameTable     = (PDWORD)((PUCHAR)pModuleBase + pImageExportDir->AddressOfNames);
    PWORD  pOrdinalTable  = (PWORD) ((PUCHAR)pModuleBase + pImageExportDir->AddressOfNameOrdinals);

    for (DWORD i=0; i < pImageExportDir->NumberOfNames; i++)
    {
        PCHAR pFuncName = (PCHAR)((PUCHAR)pModuleBase + pNameTable[i]);
       
        if(dwFunctionHash && HashString(pFuncName, FALSE) == dwFunctionHash)
        {
          return (PVOID)((PUCHAR)pModuleBase + pAddressTable[pOrdinalTable[i]]);
        }
    }

    return NULL;

}

int main() {
    PEB *ppeb_address = (PEB *)__readgsqword(0x60);

    if (!ppeb_address || !ppeb_address->Ldr) {
        printf("Failed to locate PEB or Loader Data\n");
        return 1;
    }

    PPEB_LDR_DATA pLdr = ppeb_address->Ldr;
    PLIST_ENTRY pListHead     = &pLdr->InLoadOrderModuleList;
    PLIST_ENTRY pCurrentEntry = pListHead->Flink;

    while (pCurrentEntry != pListHead)
    {
        PLDR_DATA_TABLE_ENTRY pModuleEntry = CONTAINING_RECORD(
            pCurrentEntry,
            LDR_DATA_TABLE_ENTRY,
            InLoadOrderLinks
        );

        if (pModuleEntry->BaseDllName.Buffer != NULL)
        {
            UINT_PTR moduleHash = HashString(pModuleEntry->BaseDllName.Buffer, TRUE);

            if (moduleHash == H_MODULE_KERNEL32)
            {
                printf("Kernel32.dll found: 0x%p\n", pModuleEntry->DllBase);

                fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)GetExportAddress(
                    pModuleEntry->DllBase, 
                    H_FUNC_VIRTUALALLOC  
                );

                if (pVirtualAlloc)
                {
                    printf("VirtualAlloc found: 0x%p\n", pVirtualAlloc);

                    
                    LPVOID pMemoryBuffer = pVirtualAlloc(
                        NULL,
                        0x1000,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE
                    );

                    if (pMemoryBuffer)
                        printf("Memory allocated at: 0x%p\n", pMemoryBuffer);
                }

                break;
            }
        }

        pCurrentEntry = pCurrentEntry->Flink;
    }

    return 0;
}