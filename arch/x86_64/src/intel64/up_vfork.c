/****************************************************************************
 * arch/mips/src/mips32/up_vfork.c
 *
 *   Copyright (C) 2013 Gregory Nutt. All rights reserved.
 *   Author: Gregory Nutt <gnutt@nuttx.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name NuttX nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <debug.h>

#include <nuttx/sched.h>
#include <nuttx/arch.h>
#include <arch/irq.h>

#include "up_vfork.h"
#include "sched/sched.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#ifndef CONFIG_STACK_ALIGNMENT
#  define CONFIG_STACK_ALIGNMENT 1
#endif

#define PAGE_SLOT_SIZE 0x1000000

/****************************************************************************
 * Private Functions
 ****************************************************************************/

void* page_map[8];

void* find_free_page(struct task_tcb_s * tcb){
    uint64_t i;
    // each slot is 16MB .text .data, stack is allocated using kernel heap
    // slot 0 is used by non affected nuttx threads
    // We have total 512MB of memory available to be used
    for(i = 1; i < 32; i++){
        if(page_map[i] == NULL){
            page_map[i] = tcb;
            return (void*)(i * PAGE_SLOT_SIZE); // 16MB blocks
        }
    }
    return (void*)-1;
}


/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: up_vfork
 *
 * Description:
 *   The vfork() function has the same effect as fork(), except that the
 *   behavior is undefined if the process created by vfork() either modifies
 *   any data other than a variable of type pid_t used to store the return
 *   value from vfork(), or returns from the function in which vfork() was
 *   called, or calls any other function before successfully calling _exit()
 *   or one of the exec family of functions.
 *
 *   The overall sequence is:
 *
 *   1) User code calls vfork().  vfork() collects context information and
 *      transfers control up up_vfork().
 *   2) up_vfork()and calls task_vforksetup().
 *   3) task_vforksetup() allocates and configures the child task's TCB.  This
 *      consists of:
 *      - Allocation of the child task's TCB.
 *      - Initialization of file descriptors and streams
 *      - Configuration of environment variables
 *      - Setup the intput parameters for the task.
 *      - Initialization of the TCB (including call to up_initial_state()
 *   4) up_vfork() provides any additional operating context. up_vfork must:
 *      - Allocate and initialize the stack
 *      - Initialize special values in any CPU registers that were not
 *        already configured by up_initial_state()
 *   5) up_vfork() then calls task_vforkstart()
 *   6) task_vforkstart() then executes the child thread.
 *
 * task_vforkabort() may be called if an error occurs between steps 3 and 6.
 *
 * Input Parameters:
 *   context - Caller context information saved by vfork()
 *
 * Returned Value:
 *   Upon successful completion, vfork() returns 0 to the child process and
 *   returns the process ID of the child process to the parent process.
 *   Otherwise, -1 is returned to the parent, no child process is created,
 *   and errno is set to indicate the error.
 *
 ****************************************************************************/

pid_t up_vfork(const uint64_t* context, uint64_t* ret_rsp)
{
  struct tcb_s *parent = this_task();
  struct task_tcb_s *child;
  size_t stacksize;
  uint64_t newsp;
  uint64_t newbp;
  uint64_t stackutil;
  pid_t ret;

  /* Allocate and initialize a TCB for the child task. */
  child = task_vforksetup((void*)*ret_rsp);
  if (!child)
    {
      sinfo("task_vforksetup failed\n");
      return (pid_t)ERROR;
    }

  sinfo("Parent=%p Child=%p\n", parent, child);

  // Copy everything
  memcpy(child->cmn.xcp.regs, context, 672);

  /* Get the size of the parent task's stack.  Due to alignment operations,
   * the adjusted stack size may be smaller than the stack size originally
   * requrested.
   */

  stacksize = parent->adj_stack_size + CONFIG_STACK_ALIGNMENT - 1;

  /* Allocate the stack for the TCB */

  ret = up_create_stack((FAR struct tcb_s *)child, stacksize,
                        parent->flags & TCB_FLAG_TTYPE_MASK);
  if (ret != OK)
    {
      serr("ERROR: up_create_stack failed: %d\n", ret);
      task_vforkabort(child, -ret);
      return (pid_t)ERROR;
    }

  /* How much of the parent's stack was utilized?  The MIPS uses
   * a push-down stack so that the current stack pointer should
   * be lower than the initial, adjusted stack pointer.  The
   * stack usage should be the difference between those two.
   */

  DEBUGASSERT((uint64_t)parent->adj_stack_ptr > (uint64_t) ret_rsp);
  stackutil = (uint64_t)parent->adj_stack_ptr - (uint64_t) ret_rsp;

  sinfo("stacksize:%d stackutil:%d\n", stacksize, stackutil);

  /* Make some feeble effort to perserve the stack contents.  This is
   * feeble because the stack surely contains invalid pointers and other
   * content that will not work in the child context.  However, if the
   * user follows all of the caveats of vfork() usage, even this feeble
   * effort is overkill.
   */

  newsp = (uint64_t)child->cmn.adj_stack_ptr - stackutil;
  memcpy((void *)newsp, (const void *)ret_rsp, stackutil);

  if (context[REG_RBP] <= (uint64_t)parent->adj_stack_ptr &&
      context[REG_RBP] >= (uint64_t)parent->adj_stack_ptr - stacksize)
    {
      uint64_t frameutil = (uint64_t)parent->adj_stack_ptr - context[REG_RBP];
      newbp = (uint64_t)child->cmn.adj_stack_ptr - frameutil;
    }
  else
    {
      newbp = context[REG_RBP];
    }

  sinfo("Old stack base:%016x SP:%016x FP:%016x\n",
        parent->adj_stack_ptr, (uint64_t)ret_rsp, context[REG_RBP]);
  sinfo("New stack base:%016x SP:%016x FP:%016x\n",
        child->cmn.adj_stack_ptr, newsp, newbp);

  child->cmn.xcp.regs[REG_RAX] = 0;
  child->cmn.xcp.regs[REG_RSP] = newsp;
  child->cmn.xcp.regs[REG_RBP] = newbp;

  sinfo("strating child=%p\n", child);

  /* And, finally, start the child task.  On a failure, task_vforkstart()
   * will discard the TCB by calling task_vforkabort().
   */

  ret = task_vforkstart(child);

  sinfo("return with child=%d\n", ret);
  return ret;
}

int execvs_setupargs(struct task_tcb_s* tcb,
        int argc, char* argv[], int envc, char* envv[]){
    // Now we have to organize the stack as Linux exec will do
    // ---------
    // argv
    // ---------
    // NULL
    // ---------
    // envv
    // ---------
    // NULL
    // ---------
    // auxv
    // ---------
    // a_type = AT_NULL(0)
    // ---------
    // Stack_top
    // ---------

    Elf64_auxv_t* auxptr;
    uint64_t argv_size, envv_size, total_size;
    uint64_t done;
    char** argv_ptr, ** envv_ptr;
    void* sp;

    argv_size = 0;
    for(int i = 0; i < argc; i++){
        argv_size += strlen(argv[i]) + 1;
    }
    envv_size = 0;
    for(int i = 0; i < envc; i++){
        envv_size += strlen(envv[i]) + 1;
    }
    total_size = argv_size + envv_size;

    total_size += sizeof(char*) * (argc + 1); // argvs + NULL
    total_size += sizeof(char*) * (envc + 1); // envp + NULL
    total_size += sizeof(Elf64_auxv_t) * 3; // 3 aux vectors
    total_size += sizeof(uint64_t);         // argc

    sp = up_stack_frame((struct tcb_s*)tcb, total_size);
    if (!sp) return -ENOMEM;

    sinfo("Setting up stack args at %p\n", sp);

    *((uint64_t*)sp) = argc;
    sp += sizeof(uint64_t);

    sinfo("Setting up stack argc is %d\n", *(((uint64_t*)sp) - 1));

    done = 0;
    argv_ptr = ((char**)sp);
    for(int i = 0; i < argc; i++){
        argv_ptr[i] = (char*)(sp + total_size - argv_size - envv_size + done);
        strcpy(argv_ptr[i], argv[i]);
        done += strlen(argv[i]) + 1;
    }

    done = 0;
    envv_ptr = ((char**)sp + sizeof(char*) * (argc + 1));
    for(int i = 0; i < envc; i++){
        envv_ptr[i] = (char*)(sp + total_size - envv_size + done);
        strcpy(envv_ptr[i], argv[i]);
        done += strlen(envv[i]) + 1;
    }

    auxptr = (Elf64_auxv_t*)(sp + (argc + 1 + envc + 1) * sizeof(char*));

    auxptr[0].a_type = 1; //AT_IGNORE
    auxptr[0].a_un.a_val = 0x0;

    auxptr[1].a_type = 3; //AT_PHDR
    auxptr[1].a_un.a_val = 0x0;

    auxptr[2].a_type = 0; //AT_NULL
    auxptr[2].a_un.a_val = 0x0;

    return OK;
}

int execvs(void* base, int bsize,
        void* entry,
        int argc, char* argv[],
        int envc, char* envv[])
{
    struct tcb_s *otcb = this_task();
    struct task_tcb_s *tcb;
    uint64_t new_page_start_address;
    uint64_t stack;
    pid_t pid;
    int ret;

    // First try to create a new task
    sinfo("Entry: %016llx, base: %016llx\n", entry, base);

    /* Allocate a TCB for the new task. */

    tcb = (FAR struct task_tcb_s *)kmm_zalloc(sizeof(struct task_tcb_s));
    if (!tcb)
    {
        return -ENOMEM;
    }

    // Allocate the newly created task to a new address space
    /* Find new pages for the task, every task is assumed to be 64MB, 32 pages */
    new_page_start_address = (uint64_t)find_free_page(tcb);
    if (new_page_start_address == -1)
    {
        sinfo("page exhausted\n");
        ret = -ENOMEM;
        goto errout_with_tcb;
    }

    // clear and copy the memory
    memset((void*)new_page_start_address, 0, 0x4000000);
    memcpy((void*)new_page_start_address + LINUX_ELF_OFFSET, base, bsize); //Load to the mighty 0x400000

    /* Initialize the user heap and stack */
    /*umm_initialize((FAR void *)CONFIG_ARCH_HEAP_VBASE,*/
                 /*up_addrenv_heapsize(&binp->addrenv));*/

    //Stack start at the end of address space
    stack = kmm_zalloc(0x800000);

    /* Initialize the task */
    /* The addresses are the virtual address of new task */
    ret = task_init((FAR struct tcb_s *)tcb, argv[0], 200,
                  (uint32_t*)stack, 0x800000, entry, NULL);
    if (ret < 0)
    {
        ret = -get_errno();
        berr("task_init() failed: %d\n", ret);
        goto errout_with_tcb;
    }

    ret = execvs_setupargs(tcb, argc, argv, envc, envv);
    if (ret < 0)
    {
        ret = -get_errno();
        berr("execvs_setupargs() failed: %d\n", ret);
        goto errout_with_tcbinit;
    }

    // setup the tcb page_table entries
    // load the pages for now, going to do some setup
    for(int i = 0; i < 32; i++)
    {
        tcb->cmn.xcp.page_table[i] = (new_page_start_address + 0x200000 * i) | 0x83;
    }

    // Don't given a fuck about nuttx task start and management, we are doing this properly in Linux way
    tcb->cmn.xcp.regs[REG_RIP] = entry;
    printf("RIP: %llx\n", tcb->cmn.xcp.regs[REG_RIP]);

  printf("Dump (256 bytes):\n");
  for(int i = 0; i < 64; i++){
    printf(" %016llx   ", (new_page_start_address + 0x3fffe00 + i * 8));
    for(int j = 0; j < 8; j++){
      printf("%02x ", *((uint8_t*)(new_page_start_address + 0x3fffe00 + i * 8 + j)));
    }
    printf("  %016llx   ", *((uint64_t*)(new_page_start_address + 0x3fffe00 + i * 8)));
    for(int j = 0; j < 8; j++){
      if(!((*((uint8_t*)(new_page_start_address + 0x3fffe00 + i * 8 + j)) > 126) || (*((uint8_t*)(new_page_start_address + 0x3fffe00 + i * 8 + j)) < 32)))
        printf("%c", *((uint8_t*)(new_page_start_address + 0x3fffe00 + i * 8 + j)));
      else
        printf(".");
    }
    printf("\n");
  }

    /* Get the assigned pid before we start the task */
    pid = tcb->cmn.pid;

    sinfo("activate: new task=%d\n", pid);
    /* Then activate the task at the provided priority */
    ret = task_activate((FAR struct tcb_s *)tcb);
    if (ret < 0)
    {
        ret = -get_errno();
        berr("task_activate() failed: %d\n", ret);
        goto errout_with_tcbinit;
    }

    exit(0);

    return OK; //Although we shall never return

errout_with_tcbinit:
    tcb->cmn.stack_alloc_ptr = NULL;
    sched_releasetcb(&tcb->cmn, TCB_FLAG_TTYPE_TASK);
    return ret;

errout_with_tcb:
    kmm_free(tcb);
    return ret;
}
