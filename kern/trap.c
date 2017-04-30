#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/cpu.h>
#include <kern/spinlock.h>
#include <kern/time.h>

static struct Taskstate ts;

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf;

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = { { 0 } };
struct Pseudodesc idt_pd = {
	sizeof(idt) - 1, (uint32_t) idt
};

// Dummy function declarations to be used as entry points in
// trapentry.S
void t_divide(); // 0
void t_debug();	 // 1
void t_nmi();    // 2
void t_brkpt();  // 3
void t_oflow();  // 4
void t_bound();  // 5
void t_illop();  // 6
void t_device(); // 7
void t_dblflt(); // 8
//void t_coproc();// 9 reserved
void t_tss();    // 10
void t_segnp();  // 11
void t_stack();  // 12
void t_gpflt();  // 13
void t_pgflt();  // 14
//void t_res();  // 15 reserved
void t_fperr();  // 16
void t_align();  // 17
void t_mchk();   // 18
void t_simderr();// 19

void t_syscall();// 48
// void t_default();

void irq_timer();
void irq_kbd();
void irq_serial();
void irq_spurious();
/* void irq_e1000(); */
void irq_ide();
void irq_error();


static const char *trapname(int trapno)
{
	static const char * const excnames[] = {
		"Divide error",                 // 0
		"Debug",                        // 1
		"Non-Maskable Interrupt",       // 2
		"Breakpoint",                   // 3
		"Overflow",                     // 4
		"BOUND Range Exceeded",         // 5
		"Invalid Opcode",               // 6
		"Device Not Available",         // 7
		"Double Fault",                 // 8
		"Coprocessor Segment Overrun",  // ??
		"Invalid TSS",                  // 10
		"Segment Not Present",          // 11
		"Stack Fault",                  // 12
		"General Protection",           // 13
		"Page Fault",                   // 14
		"(unknown trap)",               // ??
		"x87 FPU Floating-Point Error", // ??
		"Alignment Check",              // 17
		"Machine-Check",                // 18
		"SIMD Floating-Point Exception" // 19
	};

	if (trapno < ARRAY_SIZE(excnames))   // define in inc/types.h
		return excnames[trapno];
	if (trapno == T_SYSCALL)            // 48
		return "System call";
	if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16)
		return "Hardware Interrupt";
	return "(unknown trap)";
}


// trap_init() should initialize the IDT with the addresses of these handlers.
void
trap_init(void)
{
	extern struct Segdesc gdt[];
    // John: using iteration, instead SETGATE()
    // ref: PKU

	// LAB 3: Your code here.
    SETGATE(idt[T_DIVIDE], 0, GD_KT, t_divide, 0);
    SETGATE(idt[T_DEBUG], 0, GD_KT, t_debug, 0);
    SETGATE(idt[T_NMI], 0, GD_KT, t_nmi, 0);

    // Debuggers typically use breakpoints as a way of displaying registers, variables, etc., at crucial points in a task.
    SETGATE(idt[T_BRKPT], 0, GD_KT, t_brkpt, 3);

    SETGATE(idt[T_OFLOW], 0, GD_KT, t_oflow, 0);
    SETGATE(idt[T_BOUND], 0, GD_KT, t_bound, 0);
    SETGATE(idt[T_ILLOP], 0, GD_KT, t_illop, 0);
    SETGATE(idt[T_DEVICE], 0, GD_KT, t_device, 0);
    SETGATE(idt[T_DBLFLT], 0, GD_KT, t_dblflt, 0);
    SETGATE(idt[T_TSS], 0, GD_KT, t_tss, 0);
    SETGATE(idt[T_SEGNP], 0, GD_KT, t_segnp, 0);
    SETGATE(idt[T_STACK], 0, GD_KT, t_stack, 0);
    SETGATE(idt[T_GPFLT], 0, GD_KT, t_gpflt, 0);
    SETGATE(idt[T_PGFLT], 0, GD_KT, t_pgflt, 0);
    SETGATE(idt[T_FPERR], 0, GD_KT, t_fperr, 0);
    SETGATE(idt[T_ALIGN], 0, GD_KT, t_align, 0);
    SETGATE(idt[T_MCHK], 0, GD_KT, t_mchk, 0);
    SETGATE(idt[T_SIMDERR], 0, GD_KT, t_simderr, 0);

    /*  using globl extern, make grade has something wrong in test 2
    extern uint32_t idt_table[];
    int i;
    for(i=0; i<19; i++) {
        switch(i) {
            case T_BRKPT:
                SETGATE(idt[i], 0, GD_KT, idt_table[i], 3);
                break;
            default:
                SETGATE(idt[i], 0, GD_KT, idt_table[i], 0);
                break;
        }
    }
    */

    // External interrupt 32-47
    // istrap: 0 --> interrupt
	SETGATE(idt[IRQ_OFFSET + IRQ_TIMER], 0, GD_KT, irq_timer, 0);
	SETGATE(idt[IRQ_OFFSET + IRQ_KBD], 0, GD_KT, irq_kbd, 0);
	SETGATE(idt[IRQ_OFFSET + IRQ_SERIAL], 0, GD_KT, irq_serial, 0);
	SETGATE(idt[IRQ_OFFSET + IRQ_SPURIOUS], 0, GD_KT, irq_spurious, 0);
	/* SETGATE(idt[IRQ_OFFSET + IRQ_E1000], 0, GD_KT, irq_e1000, 0); */
	SETGATE(idt[IRQ_OFFSET + IRQ_IDE], 0, GD_KT, irq_ide, 0);
	SETGATE(idt[IRQ_OFFSET + IRQ_ERROR], 0, GD_KT, irq_error, 0);

    // system-call >> 48
	SETGATE(idt[T_SYSCALL], 0, GD_KT, t_syscall, 3);

	// Per-CPU setup
	trap_init_percpu();
}

// ref: lab3
// the processor ensures that the kernel can be entered only under carefully controlled conditions.
// On the x86, two mechanisms work together to provide this protection: IDT + TSS
//
// Initialize and load the per-CPU TSS and IDT
// the task state segment (TSS) specifies the segment selector and address where kernel stack lives.
void
trap_init_percpu(void)
{
	// The example code here sets up the Task State Segment (TSS) and
	// the TSS descriptor for CPU 0. But it is incorrect if we are
	// running on other CPUs because each CPU has its own kernel stack.
	// Fix the code so that it works for all CPUs.
	//
	// Hints:
	//   - The macro "thiscpu" always refers to the current CPU's
	//     struct CpuInfo;
	//   - The ID of the current CPU is given by cpunum() or
	//     thiscpu->cpu_id;
	//   - Use "thiscpu->cpu_ts" as the TSS for the current CPU,
	//     rather than the global "ts" variable;
	//   - Use gdt[(GD_TSS0 >> 3) + i] for CPU i's TSS descriptor;
	//   - You mapped the per-CPU kernel stacks in mem_init_mp()
	//
	// ltr sets a 'busy' flag in the TSS selector, so if you
	// accidentally load the same TSS on more than one CPU, you'll
	// get a triple fault.  If you set up an individual CPU's TSS
	// wrong, you may not get a fault until you try to return from
	// user space on that CPU.
	//
	// LAB 4: Your code here:

	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	thiscpu->cpu_ts.ts_esp0 = KSTACKTOP - thiscpu->cpu_id * (KSTKSIZE + KSTKGAP);
	thiscpu->cpu_ts.ts_ss0 = GD_KD;
	// @TODO why stack segment point to GD_KD(kernel data segment)
	thiscpu->cpu_ts.ts_iomb = sizeof(struct Taskstate);

	// Initialize the TSS slot of the gdt.
	gdt[(GD_TSS0 >> 3) + thiscpu->cpu_id] = SEG16(STS_T32A, (uint32_t) (&(thiscpu->cpu_ts)),
					sizeof(struct Taskstate) - 1, 0);
	gdt[(GD_TSS0 >> 3) + thiscpu->cpu_id].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	ltr(GD_TSS0 + thiscpu->cpu_id * sizeof(struct Segdesc));

	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p from CPU %d\n", tf, cpunum());
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf("  cr2  0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" <%s, %s, %s>\n",
			tf->tf_err & 4 ? "user" : "kernel",
			tf->tf_err & 2 ? "write" : "read",
			tf->tf_err & 1 ? "protection" : "not-present");
	else
		cprintf("\n");
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0) {
		cprintf("  esp  0x%08x\n", tf->tf_esp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void
print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

// John:
// each handler need to have enety body to handle exception & interruptions
// In lab3, Jos just destroy the env(process), then back to kernel envrionment -- This is NOT actual handler
static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle spurious interrupts
	// The hardware sometimes raises these because of noise on the
	// IRQ line or other reasons. We don't care.
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_SPURIOUS) {
		cprintf("Spurious interrupt on irq 7\n");
		print_trapframe(tf);
		return;
	}

    int32_t ret_code;
	// Handle processor exceptions.
	// LAB 3: Your code here.
    switch(tf->tf_trapno) {
        case (T_PGFLT):
            page_fault_handler(tf);
            return;
        case (T_BRKPT):
        case (T_DEBUG):
            monitor(tf);
            return;
        case (T_SYSCALL):
            ret_code = syscall(
                tf->tf_regs.reg_eax,
                tf->tf_regs.reg_edx,
                tf->tf_regs.reg_ecx,
                tf->tf_regs.reg_ebx,
                tf->tf_regs.reg_edi,
                tf->tf_regs.reg_esi);
            tf->tf_regs.reg_eax = ret_code;
            return;
    }
		// switch: using break to jump out of the control flow
		// However, using return instead here to avoid invoke SYSTEM_CALL
		// @NOTE bug appearence in lab4-ex6


	// Handle clock interrupts. Don't forget to acknowledge the
	// interrupt using lapic_eoi() before calling the scheduler!
	// LAB 4: Your code here.
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_TIMER) {
        lapic_eoi();
        sched_yield();
		return;
	}

	// Add time tick increment to clock interrupts.
	// Be careful! In multiprocessors, clock interrupts are
	// triggered on every CPU.
	// LAB 6: Your code here.


	// Handle keyboard and serial interrupts.
	// LAB 5: Your code here.
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_KBD) {
        kbd_intr();
        return;
    }
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_SERIAL) {
        serial_intr();
        return;
    }

	// Unexpected trap: The user process or the kernel has a bug.
	print_trapframe(tf);
	if (tf->tf_cs == GD_KT)
		panic("unhandled trap in kernel");
	else {
		env_destroy(curenv);
		return;
	}
}

void
trap(struct Trapframe *tf)
{
	// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	asm volatile("cld" ::: "cc");

	// Halt the CPU if some other CPU has called panic()
	extern char *panicstr;
	if (panicstr)
		asm volatile("hlt");

	// Re-acqurie the big kernel lock if we were halted in
	// sched_yield()
	if (xchg(&thiscpu->cpu_status, CPU_STARTED) == CPU_HALTED)
		lock_kernel();
	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	assert(!(read_eflags() & FL_IF));

	/* cprintf("Incoming TRAP frame at %p\n", tf); */

    // GD_UT: user text
	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		// Acquire the big kernel lock before doing any
		// serious kernel work.
		// LAB 4: Your code here.
        lock_kernel();
		assert(curenv);

		// Garbage collect if current enviroment is a zombie
		if (curenv->env_status == ENV_DYING) {
			env_free(curenv);
			curenv = NULL;
			sched_yield();
		}

		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.

		// now, the code is running in kernel mode, but curenv is not
		// kernel, curenv is the env just before the trap occured.
		// so, the trap fram copy is needed, for saving the trapped
		// env's registers.
		// tf is on the kernel stack.
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);

	// If we made it to this point, then no other environment was
	// scheduled, so we should return to the current environment
	// if doing so makes sense.
	if (curenv && curenv->env_status == ENV_RUNNING)
		env_run(curenv);
	else
		sched_yield();
}

void
page_fault_handler(struct Trapframe *tf)
{
	uint32_t fault_va;

    // CR2: Contains a value called Page Fault Linear Address (PFLA).
    // When a page fault occurs, the address the program attempted to access is stored in the CR2 register.
    // John: from wiki- https://www.wikiwand.com/en/Control_register
    //
	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();

	// Handle kernel-mode page faults.

	// LAB 3: Your code here.
	if ((tf->tf_cs & 1) == 0) {
		print_trapframe(tf);
		panic("page_fault_handler: page fault in kernel, faulting addr %08x", fault_va);
	}

	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Call the environment's page fault upcall, if one exists.  Set up a
	// page fault stack frame on the user exception stack (below
	// UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
	//
	// The page fault upcall might cause another page fault, in which case
	// we branch to the page fault upcall recursively, pushing another
	// page fault stack frame on top of the user exception stack.
	//
	// It is convenient for our code which returns from a page fault
	// (lib/pfentry.S) to have one word of scratch space at the top of the
	// trap-time stack; it allows us to more easily restore the eip/esp. In
	// the non-recursive case, we don't have to worry about this because
	// the top of the regular user stack is free.  In the recursive case,
	// this means we have to leave an extra word between the current top of
	// the exception stack and the new stack frame because the exception
	// stack _is_ the trap-time stack.
	//
	// If there's no page fault upcall, the environment didn't allocate a
	// page for its exception stack or can't write to it, or the exception
	// stack overflows, then destroy the environment that caused the fault.
	// Note that the grade script assumes you will first check for the page
	// fault upcall and print the "user fault va" message below if there is
	// none.  The remaining three checks can be combined into a single test.
    //
    // @TODO how to combine the three check into a single test?
    //
    // Hints:
    //   user_mem_assert() and env_run() are useful here.
    //   To change what the user environment runs, modify 'curenv->env_tf'
    //   (the 'tf' variable points at 'curenv->env_tf').

    // LAB 4: Your code here.

    // CORNER-1 If the user didn't set a pgfault handler
    // CORNER-2 the trap-time stack pointer is out of bounds.
    if (curenv->env_pgfault_upcall == NULL ||
            tf->tf_esp > UXSTACKTOP ||
            (tf->tf_esp > USTACKTOP && tf->tf_esp < (UXSTACKTOP - PGSIZE))) {
        goto destroy;
        // well, goto is nice manner sometimes.
        // NOTE if didn't check exception overflow first, may be cuase error.
    }

    // ref: ZhangChi report P16
    //   1. trap into kernel(stack) --> set the exception_stack(NOTE still within kernel)
    //   2. switch from kernel stack to exception stack(exeute the inter_handle_prog)
    //   3. return to user normal stack from _exceptino stack_
    //   =======================================================
    //   INFO exception stack is setted by the the user env itself, for the inter_handle_prog
    //   @see lib/pgfault.c
    uint32_t exception_stack_top;
    if (tf->tf_esp < USTACKTOP) {
        // currently, in user normal stack
        // Switching from user stack to user exception stack
        exception_stack_top = UXSTACKTOP - sizeof(struct UTrapframe);
    } else {
        // Recursive fault, we're already in the exception stack running the
        // handler code.
        // Note the -4 at the end, that's for the empty word separating the
        // two exception trapframes.
        exception_stack_top = tf->tf_esp - sizeof(struct UTrapframe) - 4;
    }

    // CORNER-3
	// Make sure we can write to the top of our exception stack. This implicitly
	// checks two conditions:
	// 1) if the user process mapped a page from UXSTACKTOP to UXSTACKTOP - PGSIZE
	// 2) if we've ran over the exception stack, beyond UXSTACKTOP - PGSIZE
    // @TODO what's the meaning of PTE_P
    //
    // NOTE
    // ref: ZhangChi report
    //      the user exception stack is asked by the user when register the handler
    user_mem_assert(curenv, (void *)exception_stack_top, sizeof(struct UTrapframe), PTE_W | PTE_U | PTE_P);

	// Write the UTrapframe to the exception stack
	struct UTrapframe *u_tf = (struct UTrapframe *) exception_stack_top;
	u_tf->utf_fault_va = fault_va;
	u_tf->utf_err = tf->tf_err;
	u_tf->utf_regs = tf->tf_regs;
	u_tf->utf_eip = tf->tf_eip;
	u_tf->utf_eflags = tf->tf_eflags;
	u_tf->utf_esp = tf->tf_esp;

	// Now adjust the trap frame so that the user process returns to executing
	// in the exception stack and runs code from the handler.
	tf->tf_esp = (uintptr_t) exception_stack_top;
	tf->tf_eip = (uintptr_t) curenv->env_pgfault_upcall;

	env_run(curenv);
    // NOTE restart -> switch to exception stack
    //

    // NOTE   user-mode      |    kern-mode  |   user-mode
    //     user normal stack -> kernel stack -> exception stack
    //       user program    |   system-call |   exception handler
    // INFO
    // We can see that, exce_handler is indeed a user env, howerver, the stack it runned
    // is different from the normal user env.
		// @see upcall kern/syscall.c :131

destroy:
	// Destroy the environment that caused the fault.
	cprintf("<%08x> user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);
}
