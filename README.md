# BoKASAN: Binary-only Kernel Address Sanitizer for Effective Kernel Fuzzing


## Repo Organization

[src](https://github.com/seclab-yonsei/bokasan/tree/main/src)

- Source code of BoKASAN kernel module

[scripts](https://github.com/seclab-yonsei/bokasan/tree/main/scripts)

- Source code of script files to update image and run qemu

[syzkaller](https://github.com/seclab-yonsei/bokasan/tree/main/syzkaller)

- Syzkaller diff and config file

[image](https://github.com/seclab-yonsei/bokasan/tree/main/image)

- Script to make Linux image

[poc](https://github.com/seclab-yonsei/bokasan/tree/main/poc)

- POC code of Linux kernel 1-day

## Tested Environment

Host machine
  - Ubuntu 16.04 and 20.04
  - Intel(R) Core(TM) i7-12700
  - 64GB RAM
  - 1TB SSD

Target Linux kernel
  - 4.19

## Requirements

Install prerequisites

```console
$ sudo apt install build-essential bison flex libelf-dev libssl-dev gcc-7 debootstrap qemu-system-x86
```

## Build BoKASAN

### Build Target Kernel

Download target kernel

```console
$ mkdir kernel && cd kernel
$ wget https://mirrors.edge.kernel.org/pub/linux/kernel/v4.x/linux-4.19.tar.gz
$ tar -zxvf linux-4.19.tar.gz
```

Generate default kernel config

```console
$ make CC=gcc-7 defconfig
$ make CC=gcc-7 kvm_guest.config
```

Enable `CONFIG_FUNCTION_TRACER` and other required configs in the `.config` file

```
CONFIG_FUNCTION_TRACER=y

# Required for Fuzzing
CONFIG_KCOV=y

# Debug info for symbolization.
CONFIG_DEBUG_INFO_DWARF4=y

# Required for Debian Stretch and later
CONFIG_CONFIGFS_FS=y
CONFIG_SECURITYFS=y
```

(optional) Enable some FS configs to test the bugs in FS

```
CONFIG\_XFS\_FS=y
CONFIG\_BTRFS\_FS=y
CONFIG\_F2FS\_FS=y
```

Compile the target kernel

```console
$ make CC=gcc-7 -j$(nproc)
```

### Make Kernel Image

Generate kernel image using [this script](https://github.com/google/syzkaller/blob/master/tools/create-image.sh)

```console
$ cd image
$ ./create-image.sh
```

It will generate `bullseye.img`

### Build BoKASAN module

Set `KDIR` in the Makefile to target kernel's source code path. Default path is `../kernel/linux-4.19`

```
KDIR=../kernel/linux-4.19
```

Compile BoKASAN module. It will generate `bokasan.ko`

```console
$ cd src
$ make CC=gcc-7
```

Put BoKASAN module to kernel image

```console
$ cd ../scripts
$ sudo ./mount.sh
```

If the image including BoKASAN is successfully created, BoKASAN will be loaded after kernel boot. We can test it as followings:

```console
$ ./qemu.sh

... boot messages ...

root@syzkaller:~# lsmod
Module                  Size  Used by
bokasan               303104  0
```

Please change `KERNEL` and `IMAGE` in `qemu.sh` if you want to use other kernel or Linux image

## Running

### Testing POC

To test syz dataset, compile the poc codes by executing the following scripts

```console
$ cd [BOKASAN HOME]/poc/syz
$ python3 compile.py
$ sudo ./mount.sh
```

Run target Linux kerenl using `qemu.sh`

```console
$ cd [BOKASAN HOME]/scripts
$ ./qemu.sh
```

Execute `repro_setpid` under `poc_syz/xxx` directory

```console
root@syzkaller:~# cd ./poc_syz/use-after-free_con_scroll
root@syzkaller:~/poc_syz/use-after-free_con_scroll# ./repro_setpid 
...
[   31.928399] ==================================================================
[   31.928401] BUG: KASAN: use-after-free (page) in con_scroll+0x198/0x1e0 vaddr: ffff8800001ffffe
[   31.928402] Kernel panic - not syncing: bokasan panic...
[   31.928402] 
[   31.928404] CPU: 0 PID: 1793 Comm: repro_setpid Tainted: G        W  O      4.19.0 #3
[   31.928404] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014
[   31.928404] Call Trace:
[   31.928406]  dump_stack+0x5c/0x7b
[   31.928408]  panic+0xe4/0x243
[   31.928409]  ? con_scroll+0x198/0x1e0
[   31.928410]  report_poison_1+0x133/0xa10 [bokasan]
[   31.928411]  ? check_poison+0xbe/0xd0 [bokasan]
[   31.928411]  ? fh_do_page_fault+0x8e/0xe0 [bokasan]
[   31.928412]  ? async_page_fault+0x1e/0x30
[   31.928413]  ? __memmove+0xe8/0x1a0
[   31.928414]  ? con_scroll+0x198/0x1e0
[   31.928414]  ? do_con_trol+0xfc3/0x18e0
[   31.928415]  ? do_con_write.part.29+0x1d5/0x9d0
[   31.928415]  ? con_write+0x52/0x60
```

### Fuzzing

Install Syzkaller following their guidelines: [Installing Syzkaller](https://github.com/google/syzkaller/blob/master/docs/linux/setup.md)

Download Go to build Syzkaller

```console
$ wget https://dl.google.com/go/go1.20.1.linux-amd64.tar.gz
$ tar -xf go1.20.1.linux-amd64.tar.gz
$ export GOROOT=`pwd`/go
$ export PATH=$GOROOT/bin:$PATH
```

Download Syzkaller

```console
$ cd [BOKASAN HOME]/syzkaller
$ git clone https://github.com/google/syzkaller.git
```

If you want to test BoKASAN on the same environment used in the papar, use follow commit id.

```console
$ cd syzkaller
$ git checkout fdb2bb2c23ee7
```

Apply `syzkaller.patch` or manually edit the changes and build Syzkaller
 
```console
$ git apply ../syzkaller.patch
$ make
```

Run Syzkaller using `syz.cfg`

```console
$ cd [BOKASAN HOME]/syzkaller
$ ./syzkaller/bin/syz-manager -config ./syz.cfg
```

You can increase the number of VM by changing `count` in the cfg file for faster fuzzing

```
{ 
 "target": "linux/amd64", 
 "http": "0.0.0.0:1337", 
 "workdir": "./result", 
 "kernel_obj": "../kernel/linux-4.19", 
 "image": "../image/bullseye.img", 
 "sshkey": "../image/bullseye.id_rsa", 
 "syzkaller": "./syzkaller", 
 "procs": 1,
 "type": "qemu", 
 "reproduce" : false, 
 "disable_syscalls": ["perf_event_open", "mount"], 
 "vm": { 
   "count": 1, 
   "kernel": "../kernel/linux-4.19/arch/x86/boot/bzImage", 
   "cpu": 1, 
   "mem": 4096
  } 
 }
```

After a few hours of fuzzing, you can see the KASAN log generated by BoKASAN

```console
$ grep -r KASAN ./result/*/*/description
./result/crashes/1cbb99b42651838e67b1c173f9fbd925a2893205/description:KASAN: use-after-free (page) in screen_glyph_unicode vaddr: ADDR
./result/crashes/683bbb89821f1ed4d7673f7083e2f2dd4e98d419/description:KASAN: use-after-free (page) in vgacon_invert_region vaddr: ADDR
./result/crashes/c419d748077ef598b85636470c9be4e0d0544613/description:KASAN: use-after-free (page) in do_con_write.part.29 vaddr: ADDR
./result/crashes/dc67eb0291eeb0b3984cbcffb91aedb5c1cefd60/description:KASAN: use-after-free (page) in csi_J vaddr: ADDR
./result/crashes/debaabb58b6970ce7331d5155b4c2b9ad528e315/description:KASAN: use-after-free (page) in vc_do_resize vaddr: ADDR
```

## Publication

```
BoKASAN: Binary-only Kernel Address Sanitizer for Effective Kernel Fuzzing

@inproceedings{cho2023bokasan,
  title={{BoKASAN: Binary-only Kernel Address Sanitizer for Effective Kernel Fuzzing}},
  author={Cho, Mingi and An, Dohyeon and Jin, Hoyong and Kwon, Taekyoung}
  booktitle={Proceedings of the 32nd USENIX Security Symposium (Security)},
  month=aug,
  year=2023,
}
```
