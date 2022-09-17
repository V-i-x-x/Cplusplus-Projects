// Memory Editor.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <iostream>
#include "windows.h"
#pragma comment(lib,"user32.lib")
using namespace std;

int _tmain(int argc,_TCHAR* argv[])
{
	cout << "welcome to my program" << endl;
	// we can use FINDWINDOWA with char
	HWND hwnd = FindWindow(0,L"Tutorial-i386");
	if (hwnd == 0) {
		cout << "Error could not find the program" << endl;
	}
	else {
		cout << "The Program is Up and Running" << endl;
		DWORD proc_id;
		GetWindowThreadProcessId(hwnd, &proc_id);
		cout << "Process id: " << proc_id << endl;
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_id);
		if (!hProc) {
			cout << "Error could not open the process" << endl;
		}
		else {
			cout << "Process Opened Succesfully" << endl;
			DWORD POINTER= 0x00634660;
			DWORD Pointed;
			WORD Offsets[] = { 0x0C, 0x14, 0x00, 0x18 };
			int size = sizeof(Offsets) / sizeof(Offsets[0]);
			int value = 0;
			int newvalue = 0;
			for (int i = 0; i<size; i++)
			{
				ReadProcessMemory(hProc, (LPCVOID)(POINTER), &Pointed, 4, NULL);
				POINTER = Pointed + Offsets[i];
			}
			ReadProcessMemory(hProc, (LPCVOID)(POINTER), &value, 4, NULL);
			cout << "your current value is: " << value << endl;
			cout << "Please enter your new value:";
			cin >> newvalue;
			int success = WriteProcessMemory(hProc, (LPVOID)(POINTER), &newvalue, (DWORD) sizeof(newvalue), NULL);
			if (success > 0) {
				ReadProcessMemory(hProc, (LPCVOID)(POINTER), &value, 4, NULL);
				cout << "your new current value is: " << newvalue << endl;
				cin.get();
			}
			else {
				cout << "Error could not write to memory" << endl;
			}

		}
	}
	cin.get();
    return 0;
}

