# Introduction

Kernel module to protect some file from privileged attacker. The targe file will be immutable except by allowed process

DEPRECATED: currently only tested for kernel version < 5.6.0

# Files

- inode_hook.c: protect file by hooking file system inode
- syscall_hook.c: protect file by hooking system call table