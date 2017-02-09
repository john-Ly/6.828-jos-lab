// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/pmap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display backtrace of all stack frames", mon_backtrace },
    { "showmappings", "Display backtrace of all stack frames", mon_showmappings },
    { "setperms", "Display backtrace of all stack frames", mon_setperms },
};

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
    uint8_t max_num_args = 5, i;
    uint32_t current_ebp, prev_ebp, saved_eip;
    uint32_t args[max_num_args];
    char *addr_fmt = "  ebp %08x eip %08x args %08x %08x %08x %08x %08x\n";
    char *stack_info = "\t%s:%d: %.*s+%d\n";
    struct Eipdebuginfo eip_info;

	cprintf("Stack backtrace\n");
    current_ebp = read_ebp();

    while(current_ebp !=0) {
        prev_ebp =  read_byte_at_addr((uint32_t *) current_ebp);
        saved_eip = read_byte_at_addr((uint32_t *) \
                (current_ebp + 1 * sizeof(uint32_t)));

        for (i = 0; i < max_num_args; i++) {
            args[i] = read_byte_at_addr((uint32_t *) (current_ebp + (i + 2) * \
                        sizeof(uint32_t)));
        }

        cprintf(addr_fmt, current_ebp, saved_eip, args[0], args[1], args[2], \
                args[3], args[4]);

        debuginfo_eip(saved_eip, &eip_info);
        cprintf(stack_info, eip_info.eip_file, eip_info.eip_line, \
                eip_info.eip_fn_namelen, eip_info.eip_fn_name, \
                saved_eip - eip_info.eip_fn_addr);

        current_ebp = prev_ebp;
    }
	return 0;
}

char * // pte's low 12-bit -- I remeber it's a interview question :(
convert_12bit_to_binary(uint32_t raw_binary) {
    // can use strlen for the general case
    // @XXX fatal error : char *a = "xxxx";
    // It's a constant string variable above(can not be edited)
    static char output[] = "000000000000";
    uint32_t bin = raw_binary;
    int i;

    for (i = 11; i >= 0; i--) {
        if (bin & 0x1)
            output[i] = '1';
        else
            output[i] = '0';
        bin = bin >> 1;
    }
    return output;
}

int
mon_showmappings(int argc, char **argv, struct Trapframe *tf) {
    if (argc != 3) {
        cprintf("Usage: showmappings 0xbegin_addr 0xend_addr\n");
        return 0;
    }

    pte_t *pte;
    pte_t pte_copy;

    char *end_ptr = argv[1] + strlen(argv[1]) + 1;
    uintptr_t current_va = (uintptr_t) strtol(argv[1], &end_ptr, 16);
    end_ptr = argv[2] + strlen(argv[2]) + 1;
    uintptr_t end_va = (uintptr_t) strtol(argv[2], &end_ptr, 16);

    if (current_va != ROUNDUP(current_va,PGSIZE) ||
            end_va != ROUNDUP(end_va,PGSIZE) ||
            current_va > end_va) {
        cprintf("showmappings: Invalid address\n");
        return 0;
    }

    /*
    in while(), continue won't change the iteration variable
    in for(), continue will change the iteration variable
    so, for() loop is a goot coding style

    while ( condition ) {
        if ( condition ) {
            ...
            current_va += PGSIZE; @NOTE!!!!!!!!!!!!!!!!!!!
            continue;
        } else { ... }
        ...
        current_va += PGSIZE;
    }
    */

    for (; current_va <= end_va; current_va += PGSIZE) {
        pte = pgdir_walk(kern_pgdir, (void *) current_va, 0); // '0' shouldn't create
        if (!pte || !(*pte & PTE_P)) {
            cprintf("virtual <%08x> - not mapped\n", current_va);
            continue;
        } else {
            // cause '[' is used for escape sequence in lab-1 challenge
            cprintf("virtual <%08x> - physical <%08x> - perm ", current_va, PTE_ADDR(*pte));
            pte_copy = *pte;

            cprintf("<");
            for (int i = 0; i < 9; i++) {
                if (pte_copy & PTE_AVAIL) {
                    cprintf("AV");
                    pte_copy &= ~PTE_AVAIL; // turn that bit off
                } else if (pte_copy & PTE_G) {
                    cprintf("G");
                    pte_copy &= ~PTE_G;
                } else if (pte_copy & PTE_PS) {
                    cprintf("PS");
                    pte_copy &= ~PTE_PS;
                } else if (pte_copy & PTE_D) {
                    cprintf("D");
                    pte_copy &= ~PTE_D;
                } else if (pte_copy & PTE_A) {
                    cprintf("A");
                    pte_copy &= ~PTE_A;
                } else if (pte_copy & PTE_PCD) {
                    cprintf("CD");
                    pte_copy &= ~PTE_PCD;
                } else if (pte_copy & PTE_PWT) {
                    cprintf("WT");
                    pte_copy &= ~PTE_PWT;
                } else if (pte_copy & PTE_U) {
                    cprintf("U");
                    pte_copy &= ~PTE_U;
                } else if (pte_copy & PTE_W) {
                    cprintf("W");
                    pte_copy &= ~PTE_W;
                } else {
                    cprintf("-");
                }
            } // for()
            cprintf("P"); // the page is present
        }
        // (*pte & 0xfff) --> fetch the low 12-bit
        cprintf("> <%s>\n", convert_12bit_to_binary(*pte & 0xfff));
    }
    return 0;
}

int
mon_setperms(int argc, char **argv, struct Trapframe *tf) {
    if (argc != 3) {
        cprintf("Usage: setm 0x-virtualaddr 0x-perms\n");
        return 0;
    }

    pte_t *pte;
    pde_t *pde;
    char *end_ptr = argv[1] + strlen(argv[1]) + 1;
    uintptr_t va = (uintptr_t) strtol(argv[1], &end_ptr, 16);
    end_ptr = argv[2] + strlen(argv[2]) + 1;
    uintptr_t perms = (uintptr_t) strtol(argv[2], &end_ptr, 16);

    pte = pgdir_walk(kern_pgdir, (void *) va, 0);
    if (!pte)
        panic("Page not mapped.\n");

    cprintf("Virt Addr: 0x%08x\n", va);
    cprintf("Permissions before setting: ");
    cprintf("<%s>\n", convert_12bit_to_binary(*pte & 0xfff));

    perms &= 0xfff;   // ensure perms are only lowest 12 bits
    *pte &= ~0xfff;   // zero out page's permissions
    *pte |= perms;    // set new permissions

    // @TODO the same contents between pde & pte
    pde = &kern_pgdir[PDX(va)]; // now do the same for the page directory entry
    *pde &= ~0xfff;
    *pde |= perms;
    /* uintptr_t p = *pde; */
    /* cprintf("%x\n", p); */

    cprintf(" Permissions after setting: ");
    cprintf("<%s>\n", convert_12bit_to_binary(*pte & 0xfff));

    return 0;
}


/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

    /* if (0xffff0000 == ROUNDUP(0xffff0000,PGSIZE) ) */
        /* cprintf("YES\n"); */

    /* int x = 1, y = 3, z = 4; */
    /* cprintf("x %d, y %x, z %d\n", x, y, z); */

    /* unsigned int i = 0x00646c72; */
    /* cprintf("H%x Wo%s\n", 57616, &i); */

    /* can't work! */
    /* @TODO ref:http://os-tres.net/blog/2012/11/05/the-cs372h-operating-systems-class-lab-1/ */
    /* cprintf("[32;45m395[40;31m decimal [37mis %o octal!\n", 395); */
    /* cprintf("[32;45mHello[40;31m, colorful[37m world!\n"); */

    while (1) {
        buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
