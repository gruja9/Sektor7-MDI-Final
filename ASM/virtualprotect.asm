; Function to change memory page protection via ntdll!NtProtectVirtualMemory, used with the x86 executex64 stub.

; This function is in the form (where the param is a pointer to a WOW64CONTEXT2):
;     typedef BOOL (WINAPI * X64FUNCTION)( DWORD dwParameter );

;typedef struct _WOW64CONTEXT2 {
    ;union {
        ;HANDLE hProcess;
        ;BYTE bPadding0[8];
    ;} h;
;
    ;union {
        ;UINT32 addrLow;
        ;BYTE bPadding1[4];
    ;} sLow;
;
    ;union {
        ;UINT32 addrHigh;
        ;BYTE bPadding11[4];
    ;} sHigh;
;
    ;union {
        ;DWORD dwSize;
        ;BYTE bPadding2[8];
    ;} p;
;
    ;union {
        ;DWORD dwOldProtect;
        ;BYTE bPadding3[8];
    ;} t;
;} WOW64CONTEXT2, * LPWOW64CONTEXT2;

[BITS 64]
[ORG 0]
  cld                    ; Clear the direction flag.
  mov rsi, rcx           ; RCX is a pointer to our WOW64CONTEXT parameter
  mov rdi, rsp           ; save RSP to RDI so we can restore it later, we do this as we are going to force alignment below...
  and rsp, 0xFFFFFFFFFFFFFFF0 ; Ensure RSP is 16 byte aligned (as we originate from a wow64 (x86) process we cant guarantee alignment)
  call start             ; Call start, this pushes the address of 'api_call' onto the stack.
delta:                   ;
%include "./block_api.asm"
start:                   ;
  pop r11                ; Pop off the address of 'api_call' for calling later.
  ; setup the parameters for NtProtectVirtualMemory...
  lea rdx, [rsi+8]       ; *BaseAddress = &ctx2->sLow.addrLow
  mov r9, 0x40           ; NewAccessProtection = 0x40
  mov rcx, [rsi]         ; ProcessHandle = ctx2->h.hProcess
  lea rax, [rsi+24]      ; RAX is now a pointer to ctx2->t.dwOldProtect
  push rax               ; OldAccessProtection = &ctx2->t.dwOldProtect
  lea r8, [rsi+16]       ; NumberOfBytesToProtect = &ctx2->p.dwSize
  ; perform the call to NtProtectVirtualMemory...
  mov r10d, 0xAAE67919   ; hash( "ntdll.dll", "NtProtectVirtualMemory" ) 
  call r11               ; NtProtectVirtualMemory( ctx2->h.hProcess, &ctx2->sLow.addrLow, &ctx2->p.dwSize, ctx2->r.dwProtection, &ctx2->t.dwOldProtect)
  test rax, rax          ; check the NTSTATUS return value
  jz success             ; if its zero we have successfully created the thread so we should return TRUE
  mov rax, 0             ; otherwise we should return FALSE
  jmp cleanup            ;
success:
  mov rax, 1             ; return TRUE
cleanup:
  mov rsp, rdi           ; restore the stack
  ret                    ; and return to caller
