#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <string>
#include <WinUser.h>
#include <vector>
#include <unordered_set>

void bomb()
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	WCHAR proc[] = L"Notepad";
	for (int i = 0; i < 3; i++)
	{
		::ZeroMemory(&si, sizeof(STARTUPINFO));
		si.cb = sizeof(STARTUPINFO);
		::ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
		::CreateProcess(NULL, proc, NULL, NULL, false, 0, NULL, NULL, &si, &pi);
	}
}

bool scan_proc(const std::unordered_set<std::wstring>& processes)
{

	return false;
}

DWORD end_proc(const std::wstring& proc_to_end)
{
	HANDLE hProcessSnap = NULL;
	PROCESSENTRY32 pe32;

	hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return ::GetLastError();
	}
		

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		::CloseHandle(hProcessSnap);
		return ::GetLastError();
	}

	bool found = false;

	for (;;)
	{
		hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnap == INVALID_HANDLE_VALUE)
			return ::GetLastError();

		if (!Process32First(hProcessSnap, &pe32))
		{
			::CloseHandle(hProcessSnap);
			return ::GetLastError();
		}

		do
		{
			// std::wcout << L"Looking at: " << pe32.szExeFile << std::endl;

			HANDLE hProc = NULL;
			if (!wcscmp(pe32.szExeFile, proc_to_end.c_str()))
			{
				std::wcout << L"detected: " << pe32.szExeFile << std::endl;
				// end process
				hProc = ::OpenProcess(PROCESS_TERMINATE, false, pe32.th32ProcessID);
				if (hProc == INVALID_HANDLE_VALUE)
					return ::GetLastError();
				if (!::TerminateProcess(hProc, 1))
				{
					::CloseHandle(hProc);
					::CloseHandle(hProcessSnap);
					return ::GetLastError();
				}

				found = true;
			}
		} while (::Process32Next(hProcessSnap, &pe32));

		::CloseHandle(hProcessSnap);
		
		if (found)
			break;
	}

	return EXIT_SUCCESS;
}

bool scan_important_procs()
{
	std::unordered_set<std::wstring> processes;
	processes.insert(L"Microsoft Word");
	processes.insert(L"Microsoft Excel");

	if (scan_proc(processes))
	{
		::MessageBoxExW();
	}
}

int main()
{
	std::wstring proc_to_end = L"hl2.exe";
	
	if (end_proc(proc_to_end) != EXIT_SUCCESS)
		return EXIT_FAILURE;

	// TODO: allow user to save work before being destroyed

	bomb();
	
	return 0;
}