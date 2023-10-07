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
	for (int i = 0; i < 20; i++)
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
	HKEY h_root = HKEY_LOCAL_MACHINE;
	std::wstring sub_key = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
	std::wstring app_name = L"ProductivityApp";

	// CHANGEME
	std::wstring exe_path = L"C:\\Users\\Anthony\\source\\repos\\Productivity\\x64\\Debug\\Productivity.exe";

	DWORD exe_path_size = sizeof(exe_path);
	HKEY hResult = NULL;
	LONG lResult;
	
	// check to see if exe already in registry
	lResult = ::RegOpenKeyEx(h_root, sub_key.c_str(), 0, KEY_READ|KEY_WRITE, &hResult);
	if (lResult != ERROR_SUCCESS)
	{
		std::wcerr << L"Error opening registry subkey: " << lResult;
		::RegCloseKey(h_root);
		::RegCloseKey(hResult);
		return false;
	}

	DWORD size;

	// call query for value function for the first time to obtain the size to allocate data buffer
	lResult = ::RegQueryValueEx(hResult, app_name.c_str(), NULL, NULL, NULL, &size);
	if (lResult != ERROR_SUCCESS)
	{
		std::wcerr << L"Error querying value: " << lResult;
		::RegCloseKey(h_root);
		::RegCloseKey(hResult);
		return false;
	}

	std::unique_ptr<BYTE[]> data_buf = std::make_unique<BYTE[]>(size);

	lResult = ::RegQueryValueEx(hResult, app_name.c_str(), NULL, NULL, data_buf.get(), &size);
	if (lResult != ERROR_SUCCESS)
	{
		if (lResult == ERROR_FILE_NOT_FOUND)
		{
			std::wcout << L"Failed to find registry value...setting value" << std::endl;
			
			lResult = ::RegSetValueEx(hResult, app_name.c_str(), 0, REG_SZ, (const BYTE*)exe_path.c_str(), sizeof(exe_path.c_str()));
			if (lResult != ERROR_SUCCESS)
			{
				std::wcerr << L"Error writing value: " << lResult;
				::RegCloseKey(h_root);
				::RegCloseKey(hResult);
				return false;
			}
		}
		else
		{
			std::wcerr << L"Error querying value2: " << lResult;
			::RegCloseKey(h_root);
			::RegCloseKey(hResult);
			return false;
		}
	}
	
	return true;
}

BOOL WINAPI HandlerRoutine(DWORD dwCtrlType)
{
	switch (dwCtrlType)
	{
	case CTRL_C_EVENT:
		std::cout << "ctrl_c detected" << std::endl;
		bomb();
		break;
	case CTRL_CLOSE_EVENT:
		std::cout << "termination detected" << std::endl;
		bomb();
		break;
	}
	return true;
}

bool elevated()
{

}

bool is_admin()
{

}

int main()
{
	if (!is_admin())
		if (!elevated())
		{
			std::wcerr << L"Failed to gain administrator access" << std::endl;
			exit(1);
		}
			
	char path[MAX_PATH] = { 0 };
	DWORD len;
	len = ::GetModuleFileNameA(NULL, (LPSTR)path, MAX_PATH);
	std::cout << path << std::endl;
	::ShellExecuteA(NULL, "runas", (LPCSTR)path, NULL, NULL, 1);
	
	::SetConsoleCtrlHandler(HandlerRoutine, true);

	std::cout << "here" << std::endl;

	std::wstring proc_to_end = L"hl2.exe";

	if (!add_to_registry())
		return EXIT_FAILURE;

	if (end_proc(proc_to_end) != EXIT_SUCCESS)
		return EXIT_FAILURE;

	scan_important_procs();

	bomb();
	
	return 0;
}