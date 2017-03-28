#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>

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

/*
void irq_timer();
void irq_kbd();
void irq_serial();
void irq_spurious();
void irq_e1000();
void irq_ide();
void irq_error();
*/


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
	return "(unknown trap)";
}


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

    // system-call >> 48
	SETGATE(idt[T_SYSCALL], 0, GD_KT, t_syscall, 3);

	// Per-CPU setup
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void
trap_init_percpu(void)
{
	// Setup a TSS so that we get the right stack
	// when we trap to the kernel.
	ts.ts_esp0 = KSTACKTOP;
	ts.ts_ss0 = GD_KD;

	// Initialize the TSS slot of the gdt.
	gdt[GD_TSS0 >> 3] = SEG16(STS_T32A, (uint32_t) (&ts),
					sizeof(struct Taskstate) - 1, 0);
	gdt[GD_TSS0 >> 3].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	ltr(GD_TSS0);

	// Load the IDT
	lidt(&idt_pd);
}

void
print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p\n", tf);
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
	// Handle processor exceptions.
	// LAB 3: Your code here.
    switch(tf->tf_trapno) {
        case (T_PGFLT):
            page_fault_handler(tf);
            break;
        case (T_BRKPT):
        case (T_DEBUG):
            monitor(tf);
            break;
				case (T_SYSCALL):
						tf->tf_regs.reg_eax =  syscall(
								tf->tf_regs.reg_eax,
								tf->tf_regs.reg_edx,
								tf->tf_regs.reg_ecx,
								tf->tf_regs.reg_ebx,
								tf->tf_regs.reg_edi,
								tf->tf_regs.reg_esi
						);
						break;
        default:
            // Unexpected trap: The user process or the kernel has a bug.
            print_trapframe(tf);
            if (tf->tf_cs == GD_KT)
                panic("unhandled trap in kernel");
            else {
                env_destroy(curenv);
                return;
            }
    }
}

void
trap(struct Trapframe *tf)
{
	// The environment may have set DF and some versions
	// of GCC rely on DF being clear
	asm volatile("cld" ::: "cc");

	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	assert(!(read_eflags() & FL_IF));

	cprintf("Incoming TRAP frame at %p\n", tf);

    // GD_UT: user text
	if ((tf->tf_cs & 3) == 3) {
		// Trapped from user mode.
		assert(curenv);

		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);

	// Return to the current environment, which should be running.
	assert(curenv && curenv->env_status == ENV_RUNNING);
	env_run(curenv);
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

	// Destroy the environment that caused the fault.
	cprintf("<%08x> user fault va %08x ip %08x\n",
		curenv->env_id, fault_va, tf->tf_eip);
	print_trapframe(tf);
	env_destroy(curenv);
}
