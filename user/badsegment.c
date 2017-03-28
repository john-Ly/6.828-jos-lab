// program to cause a general protection exception

#include <inc/lib.h>

void
umain(int argc, char **argv)
{
	// Try to load the kernel's TSS selector into the DS register.
	asm volatile("movw $0x28,%ax; movw %ax,%ds");
	// TSS0 0x28 -- General Protection

	// asm volatile("movw $0x20,%ax; movw %ax,%ds");  // user CPL = 3
	// pass, cause CPL = 3

	// asm volatile("movw $0x10,%ax; movw %ax,%ds");  // kernel CPL = 0
	// user program try to exeute in ring 0 -- General Protection
}
