#include <inc/mmu.h>
#include <inc/memlayout.h>

// Page fault upcall entrypoint.
// John: the entrypoint for every user-pgfault-handler

// This is where we ask the kernel to redirect us to whenever we cause
// a page fault in user space (see the call to sys_set_pgfault_handler
// in pgfault.c).
//
// When a page fault actually occurs, the kernel switches our ESP to
// point to the user exception stack if we're not already on the user
// exception stack, and then it pushes a UTrapframe onto our user
// exception stack:
//
//	trap-time esp
//	trap-time eflags
//	trap-time eip
//	utf_regs.reg_eax
//	...
//	utf_regs.reg_esi
//	utf_regs.reg_edi
//	utf_err (error code)
//	utf_fault_va            <-- %esp
//
// If this is a recursive fault, the kernel will reserve for us a
// blank word above the trap-time esp for scratch work when we unwind
// the recursive call.
//
// We then have call up to the appropriate page fault handler in C
// code, pointed to by the global variable '_pgfault_handler'.

.text
.globl _pgfault_upcall
_pgfault_upcall:
	// Call the C page fault handler.
	pushl %esp			// function argument: pointer to UTF
	movl _pgfault_handler, %eax
	call *%eax
	addl $4, %esp		// pop function argument

  // 
  // ret 指令做的事情就是从stack上popl %eip，然后从这个eip开始执行。
  // 一个Excepiton Stack的图对这个的理解有帮助。
  // 下面的指令的目的就是把(1)的状态转化为 (2)的状态，同时，恢复
  // trap-time-regs, trap-time-esp, trap-time-eflags.
  //  
  //  +-------------------------+  <--- UXSTACKTOP
  //  |             .           |
  //  |             .           |
  //  +-------------------------+  <--- trap-time ESP
  //  |   Reserved 4 bytes      |
  //  +-------------------------+   
  //  |   trap-time-esp    (4B) |
  //  +-------------------------+   
  //  |   trap-time-eflags (4B) |
  //  +-------------------------+   
  //  |   trap-time-eip    (4B) |
  //  +-------------------------|  <--- start of struct PushRegs
  //  |   trap-time-regs   (32B)|
  //  |   ...                   |
  //  |   trap-time-regs        |
  //  +-------------------------|  <--- end of struct PushRegs
  //  |   err              (4B) |
  //  +-------------------------+   
  //  |   fault_va         (4B) | 
  //  +-------------------------+  <-- %esp when handler is run 
  //            (1)
  //  
  //  +----trap-time-stack------+
  //  |            ...          |
  //  +-------------------------+
  //  |   trap-time-eip    (4B) |
  //  +-------------------------+   <-- trap_time_esp
  //            (2)
  //  

	// Now the C page fault handler has returned and you must return
	// to the trap time state.
	// Push trap-time %eip onto the trap-time stack.
	//
	// Explanation:
	//   We must prepare the trap-time stack for our eventual return to
	//   re-execute the instruction that faulted.
	//   Unfortunately, we can't return directly from the exception stack:
	//   We can't call 'jmp', since that requires that we load the address
	//   into a register, and all registers must have their trap-time
	//   values after the return.
	//   We can't call 'ret' from the exception stack either, since if we
	//   did, %esp would have the wrong value.
	//   So instead, we push the trap-time %eip onto the *trap-time* stack!
	//   Below we'll switch to that stack and call 'ret', which will
	//   restore %eip to its pre-fault value.
	//
	//   In the case of a recursive fault on the exception stack,
	//   note that the word we're pushing now will fit in the
	//   blank word that the kernel reserved for us.
	//
	// Throughout the remaining code, think carefully about what
	// registers are available for intermediate calculations.  You
	// may find that you have to rearrange your code in non-obvious
	// ways as registers become unavailable as scratch space.
	//
	// LAB 4: Your code here.

	movl 0x28(%esp), %eax  // Save trap-time eip(esp+0x28) in eax
	movl %esp, %ebp        // Save our current stack
	movl 0x30(%esp), %esp  // Switch to trap-time stack
	pushl %eax             // Push trap-time eip to the trap-time stack
	movl %esp, 0x30(%ebp)  // We now have to update the trap-time esp with its new value
	movl %ebp, %esp        // Go back to our exception stack

	// Restore the trap-time registers.  After you do this, you
	// can no longer modify any general-purpose registers.
	// LAB 4: Your code here.

	// Pop fault_va and err, both can be ignored
	popl %eax
	popl %eax
	popal // Pop all registers back

	// Restore eflags from the stack.  After you do this, you can
	// no longer use arithmetic operations or anything else that
	// modifies eflags.
	// LAB 4: Your code here.

	// Skip %eip
	addl $0x4, %esp
	popfl

	// Switch back to the adjusted trap-time stack.
	// LAB 4: Your code here.
	popl %esp

	// Return to re-execute the instruction that faulted.
	// LAB 4: Your code here.

    ret  // get the content indicated by esp

    // INFO understand trap-time stack!!!  -  just switch stack
    // NOTE simultaneously switching stacks and re-loading the EIP
    // ref: 6.828 + ZhangChi report
