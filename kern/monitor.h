#ifndef JOS_KERN_MONITOR_H
#define JOS_KERN_MONITOR_H
#ifndef JOS_KERNEL
# error "This is a JOS kernel header; user programs should not #include it"
#endif

struct Trapframe;

// Activate the kernel monitor,
// optionally providing a trap frame indicating the current state
// (NULL if none).
void monitor(struct Trapframe *tf);

// Functions implementing monitor commands.
int mon_help(int argc, char **argv, struct Trapframe *tf);
int mon_kerninfo(int argc, char **argv, struct Trapframe *tf);
int mon_backtrace(int argc, char **argv, struct Trapframe *tf);
char *convert_12bit_to_binary(uint32_t raw_binary);  // for mon_showmappings()
int mon_showmappings(int argc, char **argv, struct Trapframe *tf);
int mon_setperms(int argc, char **argv, struct Trapframe *tf);
void dump_virtaddr(uintptr_t start_va, uintptr_t end_va);
void dump_physaddr(physaddr_t start_pa, physaddr_t end_pa);
int mon_dump(int argc, char **argv, struct Trapframe *tf);

#endif	// !JOS_KERN_MONITOR_H
