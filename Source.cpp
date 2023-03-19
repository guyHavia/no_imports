#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

using namespace std;

typedef struct _LDR_DATA_TABLE_ENTRY_COMPLETED
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    // won't be using anything below this point
} LDR_DATA_TABLE_ENTRY_COMPLETED, * PLDR_DATA_TABLE_ENTRY_COMPLETED;

typedef HMODULE(WINAPI* LoadLibraryFunc)(LPCSTR);
typedef FARPROC(WINAPI* GetProcAddressFunc)(HMODULE, LPCSTR);
typedef int(*MessageBoxAType)(HWND, LPCSTR, LPCSTR, UINT);



int myStrcmp(const char* str1, const char* str2)
{
    /* int str1_length, str2_length;
     for (str1_length = 0; str1[str1_length] != '\0'; str1_length++);
     for (str2_length = 0; str2[str2_length] != '\0'; str2_length++);

     if (str1_length != str2_length)
     {
         return 1;
     }
     else
     {
         for (int i = 0;  i < str1_length;  i++)
         {
             if (str1[i] != str2[i])
             {
                 return 1;
             }
         }
         return 0;
     }*/
    int counter = 0;
    while (str1[counter] != '\0' && str2[counter] != '\0')
    {
        // if one string is bigger than the other
        if (str1[counter + 1] == '\0' && str2[counter + 1] != '\0' ||
            str2[counter + 1] == '\0' && str1[counter + 1] != '\0')
        {
            return 0;
        }
        else
        {
            if (str1[counter] != str2[counter])
            {
                return 0;
            }
        }
        counter++;
    }
    return 1;
}

HMODULE myGetModuleHandleA(const char* module_name)
{
    PEB* PEB_ptr = NULL;
    _asm
    {
        xor eax, eax;
        mov eax, fs: [0x30] ;
        mov[PEB_ptr], eax;
    }
    if (PEB_ptr)
    {
        PEB_LDR_DATA* peb_ldr_data = PEB_ptr->Ldr;
        LIST_ENTRY* list_head = &(peb_ldr_data->InMemoryOrderModuleList);
        LIST_ENTRY* list_next;
        LDR_DATA_TABLE_ENTRY_COMPLETED* ldr_entry;
        char BaseDllName_string[32];
        int counter = 0;
        for (list_next = list_head->Flink; list_next != list_head; list_next = list_next->Flink)
        {
            ldr_entry = (LDR_DATA_TABLE_ENTRY_COMPLETED*)((char*)list_next - sizeof(LIST_ENTRY));
            WCHAR* BaseDllName_WCHAR = ldr_entry->BaseDllName.Buffer;
            //wcstombs(BaseDllName_string, BaseDllName_WCHAR, sizeof(BaseDllName_string));
            // if myStrcmp(BaseDllName_string, module_name) == 1

            // always the 3rd module (counter=2) is kernel32.dll
            if (counter == 2)
            {
                return (HMODULE)ldr_entry->DllBase;
            }
            counter++;
        }
        return NULL;
    }
    else
    {
        printf("peb is zero");
        return NULL;
    }
}


FARPROC myGetProcAddress(void* Mymodule, const char* search_name)
{
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)Mymodule;
    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((DWORD_PTR)Mymodule + dosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER32 optionalHeader = ntHeader->OptionalHeader;
    IMAGE_EXPORT_DIRECTORY* exportDescriptor = (IMAGE_EXPORT_DIRECTORY*)((DWORD_PTR)Mymodule +
        optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names_RVA_array = (DWORD*)((DWORD_PTR)Mymodule + exportDescriptor->AddressOfNames);
    DWORD* function_RVA_array = (DWORD*)((DWORD_PTR)Mymodule + exportDescriptor->AddressOfFunctions);
    WORD* name_ordinals_array = (WORD*)((DWORD_PTR)Mymodule + exportDescriptor->AddressOfNameOrdinals);

    for (int i = 0; i < exportDescriptor->NumberOfFunctions; ++i)
    {
        char* func_name = (char*)((DWORD_PTR)Mymodule + names_RVA_array[i]);
        DWORD exported_RVA = function_RVA_array[name_ordinals_array[i]];
        if (myStrcmp(func_name, search_name) == 1)
        {
            cout << func_name << "\n";
            return (FARPROC)((DWORD_PTR)Mymodule + exported_RVA);
        }
    }
    return 0;
}



int main()
{
    void* kernel32_dll = myGetModuleHandleA("KERNEL32.DLL");

    if (kernel32_dll)
    {
        GetProcAddressFunc GetProcAddress_address = (GetProcAddressFunc)myGetProcAddress(kernel32_dll, "GetProcAddress");
        LoadLibraryFunc loadLibrary_address = (LoadLibraryFunc)myGetProcAddress(kernel32_dll, "LoadLibraryA");
        
        HMODULE user32_dll = loadLibrary_address("user32.dll");
        MessageBoxAType My_MessageBox = (MessageBoxAType)GetProcAddress_address(user32_dll, "MessageBoxA");

        My_MessageBox(NULL, "guy Message", "im guy", MB_YESNOCANCEL);
        return 0;
    }
    else
    {
        return -1;
    }
}