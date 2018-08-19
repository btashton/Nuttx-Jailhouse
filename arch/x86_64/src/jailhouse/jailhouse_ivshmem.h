#ifndef __ARCH_X86_64_INCLUDE_INTEL64_IVSHMEM_H
#define __ARCH_X86_64_INCLUDE_INTEL64_IVSHMEM_H

#define VENDORID	0x1af4
#define DEVICEID	0x1110

#define IVSHMEM_CFG_SHMEM_PTR	0x40
#define IVSHMEM_CFG_SHMEM_SZ	0x48

#define JAILHOUSE_SHMEM_PROTO_UNDEFINED	0x0000

#define IVSHMEM_SIZE 0x100000

#define MAX_NDEV	1

#define IVSHMEM_WAIT 10
#define IVSHMEM_WAKE 11

#endif /* __ARCH_X86_64_INCLUDE_INTEL64_IVSHMEM_H */
