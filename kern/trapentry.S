/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>

#include <kern/picirq.h>


###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */

// @see https://pdos.csail.mit.edu/6.828/2016/readings/i386/s09_10.htm
/*
    Table 9-7. Error-Code Summary

    Description                       Interrupt     Error Code
    Number

    Divide error                       0            No
    Debug exceptions                   1            No
    Breakpoint                         3            No
    Overflow                           4            No
    Bounds check                       5            No
    Invalid opcode                     6            No
    Coprocessor not available          7            No
    System error                       8            Yes (always 0)
    Coprocessor Segment Overrun        9            No
    Invalid TSS                       10            Yes
    Segment not present               11            Yes
    Stack exception                   12            Yes
    General protection fault          13            Yes
    Page fault                        14            Yes
    Coprocessor error                 16            No
    Two-byte SW interrupt             0-255         No
 */

TRAPHANDLER_NOEC(t_divide, T_DIVIDE)          # devide error
TRAPHANDLER_NOEC(t_debug, T_DEBUG)            # debug exception
TRAPHANDLER_NOEC(t_nmi, T_NMI)                # non-maskableinterrupt
TRAPHANDLER_NOEC(t_brkpt, T_BRKPT)            # breakpoint
TRAPHANDLER_NOEC(t_oflow, T_OFLOW)            # overflow
TRAPHANDLER_NOEC(t_bound, T_BOUND)            # bounds check
TRAPHANDLER_NOEC(t_illop, T_ILLOP)            # illegal opcode
TRAPHANDLER_NOEC(t_device, T_DEVICE)          # device not available

TRAPHANDLER(t_dblflt, T_DBLFLT)               # double fault
# 9 is reserved
TRAPHANDLER(t_tss, T_TSS)                     # invalid task switch segment
TRAPHANDLER(t_segnp, T_SEGNP)                 # segment not present
TRAPHANDLER(t_stack, T_STACK)                 # stack exception
TRAPHANDLER(t_gpflt, T_GPFLT)                 # general protection fault
TRAPHANDLER(t_pgflt, T_PGFLT)                 # page fault
# 15 is reserved
TRAPHANDLER_NOEC(t_fperr, T_FPERR)            # floating point error
TRAPHANDLER(t_align, T_ALIGN)                 # alignment check
TRAPHANDLER_NOEC(t_mchk, T_MCHK)              # machine check
TRAPHANDLER_NOEC(t_simderr, T_SIMDERR)        # SIMD floating point error
# end is 19

# 48 sys_call
TRAPHANDLER_NOEC(t_syscall, T_SYSCALL)        # system call

/*
TRAPHANDLER_NOEC(irq_timer, IRQ_OFFSET + IRQ_TIMER)
TRAPHANDLER_NOEC(irq_kbd, IRQ_OFFSET + IRQ_KBD)
TRAPHANDLER_NOEC(irq_serial, IRQ_OFFSET + IRQ_SERIAL)
TRAPHANDLER_NOEC(irq_spurious, IRQ_OFFSET + IRQ_SPURIOUS)
TRAPHANDLER_NOEC(irq_e1000, IRQ_OFFSET + IRQ_E1000)
TRAPHANDLER_NOEC(irq_ide, IRQ_OFFSET + IRQ_IDE)
TRAPHANDLER_NOEC(irq_error, IRQ_OFFSET + IRQ_ERROR)
*/

.data
.globl idt_table
idt_table:
    .long t_divide
    .long t_debug
    .long t_nmi
    .long t_brkpt
    .long t_oflow
    .long t_bound
    .long t_illop
    .long t_device
    .long t_dblflt
    .long t_tss
    .long t_segnp
    .long t_stack
    .long t_gpflt
    .long t_pgflt
    .long t_fperr
    .long t_align
    .long t_mchk
    .long t_simderr
    .long t_syscall

/*
 * Lab 3: Your code here for _alltraps
 */

.text
.globl _alltraps
_alltraps:
	# Setup remainder of trapframe
    # push in reverse order to make the stack look like a struct Trapframe
    # Everything below
	pushl %ds
	pushl %es
	pushal    # Push all General Registers
    # @see http://www.fermimn.gov.it/linux/quarta/x86/pusha.htm

    # load GD_KD into %ds and %es
	movl $GD_KD, %eax
	movw %ax, %ds
	movw %ax, %es

	pushl %esp  # pass a pointer to the Trapframe as an argument to trap()
	call trap
