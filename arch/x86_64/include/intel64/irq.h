/****************************************************************************
 * arch/x86_64/include/intel64/irq.h
 *
 *   Copyright (C) 2011 Gregory Nutt. All rights reserved.
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

/* This file should never be included directed but, rather, only indirectly
 * through nuttx/irq.h
 */

#ifndef __ARCH_X86_64_INCLUDE_INTEL64_IRQ_H
#define __ARCH_X86_64_INCLUDE_INTEL64_IRQ_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#ifndef __ASSEMBLY__
#  include <stdint.h>
#  include <stdbool.h>
#  include <arch/arch.h>
#endif

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* ISR and IRQ numbers */

#define ISR0     0 /* Division by zero exception */
#define ISR1     1 /* Debug exception */
#define ISR2     2 /* Non maskable interrupt */
#define ISR3     3 /* Breakpoint exception */
#define ISR4     4 /* 'Into detected overflow' */
#define ISR5     5 /* Out of bounds exception */
#define ISR6     6 /* Invalid opcode exception */
#define ISR7     7 /* No coprocessor exception */
#define ISR8     8 /* Double fault (pushes an error code) */
#define ISR9     9 /* Coprocessor segment overrun */
#define ISR10   10 /* Bad TSS (pushes an error code) */
#define ISR11   11 /* Segment not present (pushes an error code) */
#define ISR12   12 /* Stack fault (pushes an error code) */
#define ISR13   13 /* General protection fault (pushes an error code) */
#define ISR14   14 /* Page fault (pushes an error code) */
#define ISR15   15 /* Unknown interrupt exception */
#define ISR16   16 /* Coprocessor fault */
#define ISR17   17 /* Alignment check exception */
#define ISR18   18 /* Machine check exception */
#define ISR19   19 /* SIMD Float-Point Exception*/
#define ISR20   20 /* Virtualization Exception */
#define ISR21   21 /* Reserved */
#define ISR22   22 /* Reserved */
#define ISR23   23 /* Reserved */
#define ISR24   24 /* Reserved */
#define ISR25   25 /* Reserved */
#define ISR26   26 /* Reserved */
#define ISR27   27 /* Reserved */
#define ISR28   28 /* Reserved */
#define ISR29   29 /* Reserved */
#define ISR30   30 /* Security Exception */
#define ISR31   31 /* Reserved */

#define IRQ0    32 /* System timer (cannot be changed) */
#define IRQ1    33 /* Keyboard controller (cannot be changed) */
#define IRQ2    34 /* Cascaded signals from IRQs 8�15 */
#define IRQ3    35 /* Serial port controller for COM2/4 */
#define IRQ4    36 /* serial port controller for COM1/3 */
#define IRQ5    37 /* LPT port 2 or sound card */
#define IRQ6    38 /* Floppy disk controller */
#define IRQ7    39 /* LPT port 1 or sound card */
#define IRQ8    40 /* Real time clock (RTC) */
#define IRQ9    41 /* Open interrupt/available or SCSI host adapter */
#define IRQ10   42 /* Open interrupt/available or SCSI or NIC */
#define IRQ11   43 /* Open interrupt/available or SCSI or NIC */
#define IRQ12   44 /* Mouse on PS/2 connector */
#define IRQ13   45 /* Math coprocessor */
#define IRQ14   46 /* Primary ATA channel */
#define IRQ15   47 /* Secondary ATA channel */

#define NR_IRQS 48

/* Common register save structure created by up_saveusercontext() and by
 * ISR/IRQ interrupt processing.
 */

// data segments
#define REG_FS            (0)  /* "    " "" "     " "" "       " "        " */
#define REG_GS            (1)  /* "    " "" "     " "" "       " "        " */
#define REG_ES            (2)  /* "    " "" "     " "" "       " "        " */
#define REG_DS            (3)  /* Data segment selector */

// Remaining regs
#define REG_RAX           (4)  /* "   " "" "   " */
#define REG_RBX           (5)  /* "   " "" "   " */
#define REG_RBP           (6)  /* "   " "" "   " */
#define REG_R10           (7)  /* "   " "" "   " */
#define REG_R11           (8)  /* "   " "" "   " */
#define REG_R12           (9)  /* "   " "" "   " */
#define REG_R13          (10)  /* "   " "" "   " */
#define REG_R14          (11)  /* "   " "" "   " */
#define REG_R15          (12)  /* "   " "" "   " */

// ABI calling convention
#define REG_R9           (13)  /* "   " "" "   " */
#define REG_R8           (14)  /* "   " "" "   " */
#define REG_RCX          (15)  /* "   " "" "   " */
#define REG_RDX          (16)  /* "   " "" "   " */
#define REG_RSI          (17)  /* "   " "" "   " */
#define REG_RDI          (18)  /* "   " "" "   " */

// IRQ saved
#define REG_ERRCODE      (19)  /* Error code (NOTE 2) */
#define REG_RIP          (20)  /* Pushed by process on interrupt processing */
#define REG_CS           (21)  /* "    " "" "     " "" "       " "        " */
#define REG_RFLAGS       (22)  /* "    " "" "     " "" "       " "        " */
#define REG_RSP          (23)  /* "    " "" "     " "" "       " "        " */
#define REG_SS           (24)  /* "    " "" "     " "" "       " "        " */
/*
 * NOTE 2: This is not really state data.  Rather, this is just a convenient
 *   way to pass parameters from the interrupt handler to C code.
 */

#define XCPTCONTEXT_REGS (25)
#define XCPTCONTEXT_SIZE (8 * XCPTCONTEXT_REGS)

/****************************************************************************
 * Public Types
 ****************************************************************************/

/* This struct defines the way the registers are stored */

#ifndef __ASSEMBLY__
struct xcptcontext
{
  /* The following function pointer is non-zero if there are pending signals
   * to be processed.
   */

#ifndef CONFIG_DISABLE_SIGNALS
  void *sigdeliver; /* Actual type is sig_deliver_t */

  /* These are saved copies of instruction pointer and EFLAGS used during
   * signal processing.
   */

  uint64_t saved_rip;
  uint64_t saved_rflags;
#endif

  /* Register save area */

   uint64_t regs[XCPTCONTEXT_REGS];
};
#endif

/****************************************************************************
 * Inline functions
 ****************************************************************************/

#ifndef __ASSEMBLY__

/* Name: up_irq_save, up_irq_restore, and friends.
 *
 * NOTE: This function should never be called from application code and,
 * as a general rule unless you really know what you are doing, this
 * function should not be called directly from operation system code either:
 * Typically, the wrapper functions, enter_critical_section() and
 * leave_critical section(), are probably what you really want.
 */

/* Get the current FLAGS register contents */

static inline irqstate_t irqflags()
{
  irqstate_t flags;

  asm volatile(
    "\tpushfq\n"
    "\tpop %0\n"
    : "=rm" (flags)
    :
    : "memory");
  return flags;
}

/* Get a sample of the FLAGS register, determine if interrupts are disabled.
 * If the X86_FLAGS_IF is cleared by cli, then interrupts are disabled.  If
 * if the X86_FLAGS_IF is set by sti, then interrupts are enable.
 */

static inline bool up_irq_disabled(irqstate_t flags)
{
  return ((flags & X86_64_RFLAGS_IF) == 0);
}

static inline bool up_irq_enabled(irqstate_t flags)
{
  return ((flags & X86_64_RFLAGS_IF) != 0);
}

/* Disable interrupts unconditionally */

static inline void up_irq_disable(void)
{
  asm volatile("cli": : :"memory");
}

/* Enable interrupts unconditionally */

static inline void up_irq_enable(void)
{
  asm volatile("sti": : :"memory");
}

/* Disable interrupts, but return previous interrupt state */

static inline irqstate_t up_irq_save(void)
{
  irqstate_t flags = irqflags();
  up_irq_disable();
  return flags;
}

/* Conditionally disable interrupts */

static inline void up_irq_restore(irqstate_t flags)
{
  if (up_irq_enabled(flags))
    {
      up_irq_enable();
    }
}

/****************************************************************************
 * Public Data
 ****************************************************************************/

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

#ifdef __cplusplus
#define EXTERN extern "C"
extern "C"
{
#else
#define EXTERN extern
#endif

#undef EXTERN
#ifdef __cplusplus
}
#endif

#endif /* __ASSEMBLY__ */
#endif /* __ARCH_X86_INCLUDE_I486_IRQ_H */

