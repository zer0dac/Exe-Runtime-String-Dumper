#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

#define MIN_ASCII_LEN 4
#define MIN_WIDE_LEN 4
#define READ_CHUNK 0x10000  

static int is_printable_ascii(unsigned char c) {
    return (c >= 0x20 && c <= 0x7E); 
}

void scan_ascii(const uint8_t* buf, SIZE_T len, SIZE_T baseAddr) {
    SIZE_T i = 0;
    while (i < len) {
        SIZE_T j = i;
        while (j < len && is_printable_ascii(buf[j])) j++;
        if (j - i >= MIN_ASCII_LEN) {
            // print found string
            printf("ASCII @ 0x%p: ", (void*)(baseAddr + i));
            fwrite(buf + i, 1, j - i, stdout);
            printf("\n");
        }
        i = (j < len) ? j + 1 : j;
    }
}

void scan_wide(const uint8_t* buf, SIZE_T len, SIZE_T baseAddr) {
    SIZE_T i = 0;
    while (i + 1 < len) {
        SIZE_T j = i;
        while (j + 1 < len) {
            uint16_t ch = buf[j] | (buf[j + 1] << 8);
            if (ch >= 0x20 && ch <= 0x7E) {
                j += 2;
            }
            else break;
        }
        if ((j - i) / 2 >= MIN_WIDE_LEN) {
            SIZE_T wcharCount = (j - i) / 2;
            wprintf(L"UNICODE @ 0x%p: ", (void*)(baseAddr + i));
            wchar_t* wbuf = (wchar_t*)malloc((wcharCount + 1) * sizeof(wchar_t));
            if (wbuf) {
                for (SIZE_T k = 0; k < wcharCount; ++k) {
                    wbuf[k] = (wchar_t)(buf[i + k * 2] | (buf[i + k * 2 + 1] << 8));
                }
                wbuf[wcharCount] = 0;
                wprintf(L"%ls\n", wbuf);
                free(wbuf);
            }
        }
        i = (j + 2 < len) ? j + 2 : j + 1;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        DWORD err = GetLastError();
        printf("OpenProcess failed: %u. Try running as administrator.\n", err);
        return 1;
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t maxAddr = (uintptr_t)si.lpMaximumApplicationAddress;

    while (addr < maxAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T q = VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi));
        if (q == 0) break;

        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_GUARD) == 0 &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {

            SIZE_T regionSize = mbi.RegionSize;
            uint8_t* buffer = (uint8_t*)malloc(regionSize);
            if (buffer) {
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(hProc, mbi.BaseAddress, buffer, regionSize, &bytesRead)) {
                    scan_ascii(buffer, bytesRead, (SIZE_T)mbi.BaseAddress);
                    scan_wide(buffer, bytesRead, (SIZE_T)mbi.BaseAddress);
                }
                free(buffer);
            }
        }

        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }

    CloseHandle(hProc);
    return 0;
}
