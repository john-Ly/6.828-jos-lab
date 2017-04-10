// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW		0x800

// Assembly language pgfault entrypoint defined in lib/pfentry.S.
extern void _pgfault_upcall(void);

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *) utf->utf_fault_va;
	uint32_t err = utf->utf_err;
	int r;

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

    // LAB 4: Your code here.

    // @TODO uvpd when to works?
    // kern_pgdir can be seen as page directory or page table
    if ( !(uvpd[PDX(addr)] & PTE_P ) )
        panic("pgfault : page dir PTE_P not set.\n");

    if ((err & FEC_WR) == 0)
        panic("pgfault: faulting address [%08x] not a write\n", addr);

	if (!(uvpt[PGNUM(addr)] & PTE_COW))
		panic("pgfault: fault was not on a copy-on-write page\n");

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.

	// LAB 4: Your code here.

    // Allocate a page of memory and map it at 'va' with permission
    // 'perm' in the address space of 'envid'.
	if ((r = sys_page_alloc(0, (void *)PFTEMP, PTE_P | PTE_U | PTE_W)) != 0)
		panic("pgfault : sys_page_alloc: %e\n", r);

	// Copy over -- the right page contains 'addr'
	void *src_addr = (void *) ROUNDDOWN(addr, PGSIZE);
	memmove(PFTEMP, src_addr, PGSIZE);
    // @TODO PFTEMP is only can be increased up ?? @see inc/memlayout.h

    // TODO: avoid memory leak(reference count)
    //  invole the mechanism COW
    //  ref: http://www.cnblogs.com/bdhmwz/p/5105346.html
    if( (r = sys_page_unmap(0, src_addr)) < 0)
        panic("pgfault : sys_page_unmap error : %e.\n",r);

	// Remap
    if ((r = sys_page_map(0, PFTEMP, 0, src_addr, PTE_P | PTE_U | PTE_W)) != 0)
        panic("pgfault : sys_page_map: %e\n", r);

    // delete map of PFTEMP -> new page
    if( (r = sys_page_unmap(0, PFTEMP)) < 0)
        panic("pgfault : sys_page_unmap error : %e.\n",r);

    return;
	/* panic("pgfault not implemented"); */
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;
    uint32_t perm = PTE_P | PTE_COW;
	envid_t this_envid = thisenv->env_id;

	// LAB 4: Your code here.
	if (uvpt[pn] & PTE_SHARE) {
		if ((r = sys_page_map(this_envid, (void *) (pn*PGSIZE), envid, (void *) (pn*PGSIZE), uvpt[pn] & PTE_SYSCALL)) < 0)
			panic("sys_page_map: %e\n", r);
    } else if (uvpt[pn] & PTE_COW || uvpt[pn] & PTE_W) {
		if (uvpt[pn] & PTE_U)
			perm |= PTE_U;

		// Map page COW, U and P in child
		if ((r = sys_page_map(this_envid, (void *) (pn*PGSIZE), envid, (void *) (pn*PGSIZE), perm)) < 0)
			panic("sys_page_map: %e\n", r);

		// Map page COW, U and P in parent
		if ((r = sys_page_map(this_envid, (void *) (pn*PGSIZE), this_envid, (void *) (pn*PGSIZE), perm)) < 0)
			panic("sys_page_map: %e\n", r);

	} else { // map pages that are present but not writable or COW with their original permissions
		if ((r = sys_page_map(this_envid, (void *) (pn*PGSIZE), envid, (void *) (pn*PGSIZE), uvpt[pn] & PTE_SYSCALL)) < 0)
			panic("sys_page_map: %e\n", r);
	}

	/* panic("duppage not implemented"); */
	return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t
fork(void)
{
	// LAB 4: Your code here.
    int r;
    envid_t envid;

    set_pgfault_handler(pgfault);
    envid = sys_exofork();

    if (envid < 0)
        panic("fork: sys_exofork error,  %e\n", envid);
    if (envid == 0) { // child
        // Fix thisenv like dumbfork does and return 0
        thisenv = &envs[ENVX(sys_getenvid())];
        return 0;

	// We're in the parent
    // Iterate over all pages until UTOP. Map all pages that are present
	// and let duppage worry about the permissions.
	// Note that we don't remap anything above UTOP because the kernel took
	// care of that for us in env_setup_vm().
	uint32_t page_num;
	pte_t *pte;
    // @NOTE PGSIZE only copy the right page
	for (page_num = 0; page_num < PGNUM(UTOP - PGSIZE); page_num++) {
		uint32_t pdx = ROUNDDOWN(page_num, NPDENTRIES) / NPDENTRIES;
		if ((uvpd[pdx] & PTE_P) == PTE_P &&
			((uvpt[page_num] & PTE_P) == PTE_P)) {
				duppage(envid, page_num);
		}
	}


    // Allocate create exception stack, parent's exception stack cannot
    // be duppaged ! because at this time it's page fault are using it,
    // and it should be writable.
    r = sys_page_alloc(envid, (void*)(UXSTACKTOP-PGSIZE), PTE_U | PTE_P | PTE_W);
    if (r < 0)
        panic("fork : sys_page_alloc error : %e\n", r);

    // Set child's page fault handler -- initialize
    // child_env->env_pgfault_upcall
		r = sys_env_set_pgfault_upcall(envid, (void*)_pgfault_upcall);
    if (r < 0)
        panic("fork : sys_env_set_pgfault_upcall error : %e\n", r);

    // Child is ready to run, make it RUNNABLE
    r = sys_env_set_status(envid, ENV_RUNNABLE);
    if (r < 0)
        panic("fork : sys_env_set_status error : %e\n", r);
    }
}

// Challenge!
int
sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
