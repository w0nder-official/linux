// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/init/main.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  GK 2/5/95  -  Changed to support mounting root fs via NFS
 *  Added initrd & change_root: Werner Almesberger & Hans Lermen, Feb '96
 *  Moan early if gcc is old, avoiding bogus kernels - Paul Gortmaker, May '96
 *  Simplified starting of init:  Michael A. Griffith <grif@acm.org>
 */

#define DEBUG		/* Enable initcall_debug */

#include <linux/types.h>
#include <linux/export.h>
#include <linux/extable.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/binfmts.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/stackprotector.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/memblock.h>
#include <linux/acpi.h>
#include <linux/bootconfig.h>
#include <linux/console.h>
#include <linux/nmi.h>
#include <linux/percpu.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/kmsan.h>
#include <linux/vmalloc.h>
#include <linux/kernel_stat.h>
#include <linux/start_kernel.h>
#include <linux/security.h>
#include <linux/smp.h>
#include <linux/profile.h>
#include <linux/kfence.h>
#include <linux/rcupdate.h>
#include <linux/srcu.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/buildid.h>
#include <linux/writeback.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/memcontrol.h>
#include <linux/cgroup.h>
#include <linux/tick.h>
#include <linux/sched/isolation.h>
#include <linux/interrupt.h>
#include <linux/taskstats_kern.h>
#include <linux/delayacct.h>
#include <linux/unistd.h>
#include <linux/utsname.h>
#include <linux/rmap.h>
#include <linux/mempolicy.h>
#include <linux/key.h>
#include <linux/debug_locks.h>
#include <linux/debugobjects.h>
#include <linux/lockdep.h>
#include <linux/kmemleak.h>
#include <linux/padata.h>
#include <linux/pid_namespace.h>
#include <linux/device/driver.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/sched/init.h>
#include <linux/signal.h>
#include <linux/idr.h>
#include <linux/kgdb.h>
#include <linux/ftrace.h>
#include <linux/async.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/pti.h>
#include <linux/blkdev.h>
#include <linux/sched/clock.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/context_tracking.h>
#include <linux/random.h>
#include <linux/moduleloader.h>
#include <linux/list.h>
#include <linux/integrity.h>
#include <linux/proc_ns.h>
#include <linux/io.h>
#include <linux/cache.h>
#include <linux/rodata_test.h>
#include <linux/jump_label.h>
#include <linux/kcsan.h>
#include <linux/init_syscalls.h>
#include <linux/stackdepot.h>
#include <linux/randomize_kstack.h>
#include <linux/pidfs.h>
#include <linux/ptdump.h>
#include <linux/time_namespace.h>
#include <net/net_namespace.h>

#include <asm/io.h>
#include <asm/setup.h>
#include <asm/sections.h>
#include <asm/cacheflush.h>

#define CREATE_TRACE_POINTS
#include <trace/events/initcall.h>

#include <kunit/test.h>

static int kernel_init(void *);

/*
 * Debug helper: via this flag we know that we are in 'early bootup code'
 * where only the boot processor is running with IRQ disabled.  This means
 * two things - IRQ must not be enabled before the flag is cleared and some
 * operations which are not allowed with IRQ disabled are allowed while the
 * flag is set.
 */
bool early_boot_irqs_disabled __read_mostly;

enum system_states system_state __read_mostly;
EXPORT_SYMBOL(system_state);

/*
 * Boot command-line arguments
 */
#define MAX_INIT_ARGS CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS CONFIG_INIT_ENV_ARG_LIMIT

/* Default late time init is NULL. archs can override this later. */
void (*__initdata late_time_init)(void);

/* Untouched command line saved by arch-specific code. */
char __initdata boot_command_line[COMMAND_LINE_SIZE];
/* Untouched saved command line (eg. for /proc) */
char *saved_command_line __ro_after_init;
unsigned int saved_command_line_len __ro_after_init;
/* Command line for parameter parsing */
static char *static_command_line;
/* Untouched extra command line */
static char *extra_command_line;
/* Extra init arguments */
static char *extra_init_args;

#ifdef CONFIG_BOOT_CONFIG
/* Is bootconfig on command line? */
static bool bootconfig_found;
static size_t initargs_offs;
#else
# define bootconfig_found false
# define initargs_offs 0
#endif

static char *execute_command;
static char *ramdisk_execute_command = "/init";

/*
 * Used to generate warnings if static_key manipulation functions are used
 * before jump_label_init is called.
 */
bool static_key_initialized __read_mostly;
EXPORT_SYMBOL_GPL(static_key_initialized);

/*
 * If set, this is an indication to the drivers that reset the underlying
 * device before going ahead with the initialization otherwise driver might
 * rely on the BIOS and skip the reset operation.
 *
 * This is useful if kernel is booting in an unreliable environment.
 * For ex. kdump situation where previous kernel has crashed, BIOS has been
 * skipped and devices will be in unknown state.
 */
unsigned int reset_devices;
EXPORT_SYMBOL(reset_devices);

static int __init set_reset_devices(char *str)
{
	reset_devices = 1;
	return 1;
}

__setup("reset_devices", set_reset_devices);

static const char *argv_init[MAX_INIT_ARGS+2] = { "init", NULL, };
const char *envp_init[MAX_INIT_ENVS+2] = { "HOME=/", "TERM=linux", NULL, };
static const char *panic_later, *panic_param;

static bool __init obsolete_checksetup(char *line)
{
	const struct obs_kernel_param *p;
	bool had_early_param = false;

	p = __setup_start;
	do {
		int n = strlen(p->str);
		if (parameqn(line, p->str, n)) {
			if (p->early) {
				/* Already done in parse_early_param?
				 * (Needs exact match on param part).
				 * Keep iterating, as we can have early
				 * params and __setups of same names 8( */
				if (line[n] == '\0' || line[n] == '=')
					had_early_param = true;
			} else if (!p->setup_func) {
				pr_warn("Parameter %s is obsolete, ignored\n",
					p->str);
				return true;
			} else if (p->setup_func(line + n))
				return true;
		}
		p++;
	} while (p < __setup_end);

	return had_early_param;
}

/*
 * This should be approx 2 Bo*oMips to start (note initial shift), and will
 * still work even if initially too large, it will just take slightly longer
 */
unsigned long loops_per_jiffy = (1<<12);
EXPORT_SYMBOL(loops_per_jiffy);

static int __init debug_kernel(char *str)
{
	console_loglevel = CONSOLE_LOGLEVEL_DEBUG;
	return 0;
}

static int __init quiet_kernel(char *str)
{
	console_loglevel = CONSOLE_LOGLEVEL_QUIET;
	return 0;
}

early_param("debug", debug_kernel);
early_param("quiet", quiet_kernel);

static int __init loglevel(char *str)
{
	int newlevel;

	/*
	 * Only update loglevel value when a correct setting was passed,
	 * to prevent blind crashes (when loglevel being set to 0) that
	 * are quite hard to debug
	 */
	if (get_option(&str, &newlevel)) {
		console_loglevel = newlevel;
		return 0;
	}

	return -EINVAL;
}

early_param("loglevel", loglevel);

#ifdef CONFIG_BLK_DEV_INITRD
static void * __init get_boot_config_from_initrd(size_t *_size)
{
	u32 size, csum;
	char *data;
	u32 *hdr;
	int i;

	if (!initrd_end)
		return NULL;

	data = (char *)initrd_end - BOOTCONFIG_MAGIC_LEN;
	/*
	 * Since Grub may align the size of initrd to 4, we must
	 * check the preceding 3 bytes as well.
	 */
	for (i = 0; i < 4; i++) {
		if (!memcmp(data, BOOTCONFIG_MAGIC, BOOTCONFIG_MAGIC_LEN))
			goto found;
		data--;
	}
	return NULL;

found:
	hdr = (u32 *)(data - 8);
	size = le32_to_cpu(hdr[0]);
	csum = le32_to_cpu(hdr[1]);

	data = ((void *)hdr) - size;
	if ((unsigned long)data < initrd_start) {
		pr_err("bootconfig size %d is greater than initrd size %ld\n",
			size, initrd_end - initrd_start);
		return NULL;
	}

	if (xbc_calc_checksum(data, size) != csum) {
		pr_err("bootconfig checksum failed\n");
		return NULL;
	}

	/* Remove bootconfig from initramfs/initrd */
	initrd_end = (unsigned long)data;
	if (_size)
		*_size = size;

	return data;
}
#else
static void * __init get_boot_config_from_initrd(size_t *_size)
{
	return NULL;
}
#endif

#ifdef CONFIG_BOOT_CONFIG

static char xbc_namebuf[XBC_KEYLEN_MAX] __initdata;

#define rest(dst, end) ((end) > (dst) ? (end) - (dst) : 0)

static int __init xbc_snprint_cmdline(char *buf, size_t size,
				      struct xbc_node *root)
{
	struct xbc_node *knode, *vnode;
	char *end = buf + size;
	const char *val, *q;
	int ret;

	xbc_node_for_each_key_value(root, knode, val) {
		ret = xbc_node_compose_key_after(root, knode,
					xbc_namebuf, XBC_KEYLEN_MAX);
		if (ret < 0)
			return ret;

		vnode = xbc_node_get_child(knode);
		if (!vnode) {
			ret = snprintf(buf, rest(buf, end), "%s ", xbc_namebuf);
			if (ret < 0)
				return ret;
			buf += ret;
			continue;
		}
		xbc_array_for_each_value(vnode, val) {
			/*
			 * For prettier and more readable /proc/cmdline, only
			 * quote the value when necessary, i.e. when it contains
			 * whitespace.
			 */
			q = strpbrk(val, " \t\r\n") ? "\"" : "";
			ret = snprintf(buf, rest(buf, end), "%s=%s%s%s ",
				       xbc_namebuf, q, val, q);
			if (ret < 0)
				return ret;
			buf += ret;
		}
	}

	return buf - (end - size);
}
#undef rest

/* Make an extra command line under given key word */
static char * __init xbc_make_cmdline(const char *key)
{
	struct xbc_node *root;
	char *new_cmdline;
	int ret, len = 0;

	root = xbc_find_node(key);
	if (!root)
		return NULL;

	/* Count required buffer size */
	len = xbc_snprint_cmdline(NULL, 0, root);
	if (len <= 0)
		return NULL;

	new_cmdline = memblock_alloc(len + 1, SMP_CACHE_BYTES);
	if (!new_cmdline) {
		pr_err("Failed to allocate memory for extra kernel cmdline.\n");
		return NULL;
	}

	ret = xbc_snprint_cmdline(new_cmdline, len + 1, root);
	if (ret < 0 || ret > len) {
		pr_err("Failed to print extra kernel cmdline.\n");
		memblock_free(new_cmdline, len + 1);
		return NULL;
	}

	return new_cmdline;
}

static int __init bootconfig_params(char *param, char *val,
				    const char *unused, void *arg)
{
	if (strcmp(param, "bootconfig") == 0) {
		bootconfig_found = true;
	}
	return 0;
}

static int __init warn_bootconfig(char *str)
{
	/* The 'bootconfig' has been handled by bootconfig_params(). */
	return 0;
}

static void __init setup_boot_config(void)
{
	static char tmp_cmdline[COMMAND_LINE_SIZE] __initdata;
	const char *msg, *data;
	int pos, ret;
	size_t size;
	char *err;

	/* Cut out the bootconfig data even if we have no bootconfig option */
	data = get_boot_config_from_initrd(&size);
	/* If there is no bootconfig in initrd, try embedded one. */
	if (!data)
		data = xbc_get_embedded_bootconfig(&size);

	strscpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
	err = parse_args("bootconfig", tmp_cmdline, NULL, 0, 0, 0, NULL,
			 bootconfig_params);

	if (IS_ERR(err) || !(bootconfig_found || IS_ENABLED(CONFIG_BOOT_CONFIG_FORCE)))
		return;

	/* parse_args() stops at the next param of '--' and returns an address */
	if (err)
		initargs_offs = err - tmp_cmdline;

	if (!data) {
		/* If user intended to use bootconfig, show an error level message */
		if (bootconfig_found)
			pr_err("'bootconfig' found on command line, but no bootconfig found\n");
		else
			pr_info("No bootconfig data provided, so skipping bootconfig");
		return;
	}

	if (size >= XBC_DATA_MAX) {
		pr_err("bootconfig size %ld greater than max size %d\n",
			(long)size, XBC_DATA_MAX);
		return;
	}

	ret = xbc_init(data, size, &msg, &pos);
	if (ret < 0) {
		if (pos < 0)
			pr_err("Failed to init bootconfig: %s.\n", msg);
		else
			pr_err("Failed to parse bootconfig: %s at %d.\n",
				msg, pos);
	} else {
		xbc_get_info(&ret, NULL);
		pr_info("Load bootconfig: %ld bytes %d nodes\n", (long)size, ret);
		/* keys starting with "kernel." are passed via cmdline */
		extra_command_line = xbc_make_cmdline("kernel");
		/* Also, "init." keys are init arguments */
		extra_init_args = xbc_make_cmdline("init");
	}
	return;
}

static void __init exit_boot_config(void)
{
	xbc_exit();
}

#else	/* !CONFIG_BOOT_CONFIG */

static void __init setup_boot_config(void)
{
	/* Remove bootconfig data from initrd */
	get_boot_config_from_initrd(NULL);
}

static int __init warn_bootconfig(char *str)
{
	pr_warn("WARNING: 'bootconfig' found on the kernel command line but CONFIG_BOOT_CONFIG is not set.\n");
	return 0;
}

#define exit_boot_config()	do {} while (0)

#endif	/* CONFIG_BOOT_CONFIG */

early_param("bootconfig", warn_bootconfig);

bool __init cmdline_has_extra_options(void)
{
	return extra_command_line || extra_init_args;
}

/* Change NUL term back to "=", to make "param" the whole string. */
static void __init repair_env_string(char *param, char *val)
{
	if (val) {
		/* param=val or param="val"? */
		if (val == param+strlen(param)+1)
			val[-1] = '=';
		else if (val == param+strlen(param)+2) {
			val[-2] = '=';
			memmove(val-1, val, strlen(val)+1);
		} else
			BUG();
	}
}

/* Anything after -- gets handed straight to init. */
static int __init set_init_arg(char *param, char *val,
			       const char *unused, void *arg)
{
	unsigned int i;

	if (panic_later)
		return 0;

	repair_env_string(param, val);

	for (i = 0; argv_init[i]; i++) {
		if (i == MAX_INIT_ARGS) {
			panic_later = "init";
			panic_param = param;
			return 0;
		}
	}
	argv_init[i] = param;
	return 0;
}

/*
 * Unknown boot options get handed to init, unless they look like
 * unused parameters (modprobe will find them in /proc/cmdline).
 */
static int __init unknown_bootoption(char *param, char *val,
				     const char *unused, void *arg)
{
	size_t len = strlen(param);
	/*
	 * Well-known bootloader identifiers:
	 * 1. LILO/Grub pass "BOOT_IMAGE=...";
	 * 2. kexec/kdump (kexec-tools) pass "kexec".
	 */
	const char *bootloader[] = { "BOOT_IMAGE=", "kexec", NULL };

	/* Handle params aliased to sysctls */
	if (sysctl_is_alias(param))
		return 0;

	repair_env_string(param, val);

	/* Handle bootloader identifier */
	for (int i = 0; bootloader[i]; i++) {
		if (strstarts(param, bootloader[i]))
			return 0;
	}

	/* Handle obsolete-style parameters */
	if (obsolete_checksetup(param))
		return 0;

	/* Unused module parameter. */
	if (strnchr(param, len, '.'))
		return 0;

	if (panic_later)
		return 0;

	if (val) {
		/* Environment option */
		unsigned int i;
		for (i = 0; envp_init[i]; i++) {
			if (i == MAX_INIT_ENVS) {
				panic_later = "env";
				panic_param = param;
			}
			if (!strncmp(param, envp_init[i], len+1))
				break;
		}
		envp_init[i] = param;
	} else {
		/* Command line option */
		unsigned int i;
		for (i = 0; argv_init[i]; i++) {
			if (i == MAX_INIT_ARGS) {
				panic_later = "init";
				panic_param = param;
			}
		}
		argv_init[i] = param;
	}
	return 0;
}

static int __init init_setup(char *str)
{
	unsigned int i;

	execute_command = str;
	/*
	 * In case LILO is going to boot us with default command line,
	 * it prepends "auto" before the whole cmdline which makes
	 * the shell think it should execute a script with such name.
	 * So we ignore all arguments entered _before_ init=... [MJ]
	 */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("init=", init_setup);

static int __init rdinit_setup(char *str)
{
	unsigned int i;

	ramdisk_execute_command = str;
	/* See "auto" comment in init_setup */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("rdinit=", rdinit_setup);

#ifndef CONFIG_SMP
static inline void setup_nr_cpu_ids(void) { }
static inline void smp_prepare_cpus(unsigned int maxcpus) { }
#endif

/*
 * We need to store the untouched command line for future reference.
 * We also need to store the touched command line since the parameter
 * parsing is performed in place, and we should allow a component to
 * store reference of name/value for future reference.
 */
static void __init setup_command_line(char *command_line)
{
	size_t len, xlen = 0, ilen = 0;

	if (extra_command_line)
		xlen = strlen(extra_command_line);
	if (extra_init_args) {
		extra_init_args = strim(extra_init_args); /* remove trailing space */
		ilen = strlen(extra_init_args) + 4; /* for " -- " */
	}

	len = xlen + strlen(boot_command_line) + ilen + 1;

	saved_command_line = memblock_alloc_or_panic(len, SMP_CACHE_BYTES);

	len = xlen + strlen(command_line) + 1;

	static_command_line = memblock_alloc_or_panic(len, SMP_CACHE_BYTES);

	if (xlen) {
		/*
		 * We have to put extra_command_line before boot command
		 * lines because there could be dashes (separator of init
		 * command line) in the command lines.
		 */
		strcpy(saved_command_line, extra_command_line);
		strcpy(static_command_line, extra_command_line);
	}
	strcpy(saved_command_line + xlen, boot_command_line);
	strcpy(static_command_line + xlen, command_line);

	if (ilen) {
		/*
		 * Append supplemental init boot args to saved_command_line
		 * so that user can check what command line options passed
		 * to init.
		 * The order should always be
		 * " -- "[bootconfig init-param][cmdline init-param]
		 */
		if (initargs_offs) {
			len = xlen + initargs_offs;
			strcpy(saved_command_line + len, extra_init_args);
			len += ilen - 4;	/* strlen(extra_init_args) */
			strcpy(saved_command_line + len,
				boot_command_line + initargs_offs - 1);
		} else {
			len = strlen(saved_command_line);
			strcpy(saved_command_line + len, " -- ");
			len += 4;
			strcpy(saved_command_line + len, extra_init_args);
		}
	}

	saved_command_line_len = strlen(saved_command_line);
}

/*
 * We need to finalize in a non-__init function or else race conditions
 * between the root thread and the init thread may cause start_kernel to
 * be reaped by free_initmem before the root thread has proceeded to
 * cpu_idle.
 *
 * gcc-3.4 accidentally inlines this function, so use noinline.
 */

static __initdata DECLARE_COMPLETION(kthreadd_done);

static noinline void __ref __noreturn rest_init(void)
{
	struct task_struct *tsk;
	int pid;

	rcu_scheduler_starting();
	/*
	 * We need to spawn init first so that it obtains pid 1, however
	 * the init task will end up wanting to create kthreads, which, if
	 * we schedule it before we create kthreadd, will OOPS.
	 */
	pid = user_mode_thread(kernel_init, NULL, CLONE_FS);
	/*
	 * Pin init on the boot CPU. Task migration is not properly working
	 * until sched_init_smp() has been run. It will set the allowed
	 * CPUs for init to the non isolated CPUs.
	 */
	rcu_read_lock();
	tsk = find_task_by_pid_ns(pid, &init_pid_ns);
	tsk->flags |= PF_NO_SETAFFINITY;
	set_cpus_allowed_ptr(tsk, cpumask_of(smp_processor_id()));
	rcu_read_unlock();

	numa_default_policy();
	pid = kernel_thread(kthreadd, NULL, NULL, CLONE_FS | CLONE_FILES);
	rcu_read_lock();
	kthreadd_task = find_task_by_pid_ns(pid, &init_pid_ns);
	rcu_read_unlock();

	/*
	 * Enable might_sleep() and smp_processor_id() checks.
	 * They cannot be enabled earlier because with CONFIG_PREEMPTION=y
	 * kernel_thread() would trigger might_sleep() splats. With
	 * CONFIG_PREEMPT_VOLUNTARY=y the init task might have scheduled
	 * already, but it's stuck on the kthreadd_done completion.
	 */
	system_state = SYSTEM_SCHEDULING;

	complete(&kthreadd_done);

	/*
	 * The boot idle thread must execute schedule()
	 * at least once to get things moving:
	 */
	schedule_preempt_disabled();
	/* Call into cpu_idle with preempt disabled */
	cpu_startup_entry(CPUHP_ONLINE);
}

/* Check for early params. */
static int __init do_early_param(char *param, char *val,
				 const char *unused, void *arg)
{
	const struct obs_kernel_param *p;

	for (p = __setup_start; p < __setup_end; p++) {
		if (p->early && parameq(param, p->str)) {
			if (p->setup_func(val) != 0)
				pr_warn("Malformed early option '%s'\n", param);
		}
	}
	/* We accept everything at this stage. */
	return 0;
}

void __init parse_early_options(char *cmdline)
{
	parse_args("early options", cmdline, NULL, 0, 0, 0, NULL,
		   do_early_param);
}

/* Arch code calls this early on, or if not, just before other parsing. */
void __init parse_early_param(void)
{
	static int done __initdata;
	static char tmp_cmdline[COMMAND_LINE_SIZE] __initdata;

	if (done)
		return;

	/* All fall through to do_early_param. */
	strscpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
	parse_early_options(tmp_cmdline);
	done = 1;
}

void __init __weak arch_post_acpi_subsys_init(void) { }

void __init __weak smp_setup_processor_id(void)
{
}

void __init __weak smp_prepare_boot_cpu(void)
{
}

# if THREAD_SIZE >= PAGE_SIZE
void __init __weak thread_stack_cache_init(void)
{
}
#endif

void __init __weak poking_init(void) { }

void __init __weak pgtable_cache_init(void) { }

void __init __weak trap_init(void) { }

bool initcall_debug;
core_param(initcall_debug, initcall_debug, bool, 0644);

#ifdef TRACEPOINTS_ENABLED
static void __init initcall_debug_enable(void);
#else
static inline void initcall_debug_enable(void)
{
}
#endif

#ifdef CONFIG_RANDOMIZE_KSTACK_OFFSET
DEFINE_STATIC_KEY_MAYBE_RO(CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT,
			   randomize_kstack_offset);
DEFINE_PER_CPU(u32, kstack_offset);

static int __init early_randomize_kstack_offset(char *buf)
{
	int ret;
	bool bool_result;

	ret = kstrtobool(buf, &bool_result);
	if (ret)
		return ret;

	if (bool_result)
		static_branch_enable(&randomize_kstack_offset);
	else
		static_branch_disable(&randomize_kstack_offset);
	return 0;
}
early_param("randomize_kstack_offset", early_randomize_kstack_offset);
#endif

static void __init print_unknown_bootoptions(void)
{
	char *unknown_options;
	char *end;
	const char *const *p;
	size_t len;

	if (panic_later || (!argv_init[1] && !envp_init[2]))
		return;

	/*
	 * Determine how many options we have to print out, plus a space
	 * before each
	 */
	len = 1; /* null terminator */
	for (p = &argv_init[1]; *p; p++) {
		len++;
		len += strlen(*p);
	}
	for (p = &envp_init[2]; *p; p++) {
		len++;
		len += strlen(*p);
	}

	unknown_options = memblock_alloc(len, SMP_CACHE_BYTES);
	if (!unknown_options) {
		pr_err("%s: Failed to allocate %zu bytes\n",
			__func__, len);
		return;
	}
	end = unknown_options;

	for (p = &argv_init[1]; *p; p++)
		end += sprintf(end, " %s", *p);
	for (p = &envp_init[2]; *p; p++)
		end += sprintf(end, " %s", *p);

	/* Start at unknown_options[1] to skip the initial space */
	pr_notice("Unknown kernel command line parameters \"%s\", will be passed to user space.\n",
		&unknown_options[1]);
	memblock_free(unknown_options, len);
}

static void __init early_numa_node_init(void)
{
#ifdef CONFIG_USE_PERCPU_NUMA_NODE_ID
#ifndef cpu_to_node
	int cpu;

	/* The early_cpu_to_node() should be ready here. */
	for_each_possible_cpu(cpu)
		set_cpu_numa_node(cpu, early_cpu_to_node(cpu));
#endif
#endif
}

asmlinkage __visible __init __no_sanitize_address __noreturn __no_stack_protector
void start_kernel(void) //시작
{
	/* 로컬 변수 선언: 리눅스 커널 코딩 스타일 규칙
	 *
	 * 리눅스 커널 코딩 스타일 (Documentation/process/coding-style.rst):
	 * - 변수는 함수 시작 부분에 선언하는 것이 선호됨
	 * - "reverse fir tree order"로 선언: 긴 타입부터 짧은 타입 순서
	 *   * "fir tree" = 전나무 (크리스마스 트리 모양: 위가 좁고 아래가 넓음)
	 *   * "reverse fir tree" = 역전나무 (역삼각형: 위가 넓고 아래가 좁음)
	 *   * 즉, 변수 선언을 위에서 아래로 갈수록 짧아지게 배치
	 *   * 예시:
	 *     struct long_struct_name *descriptive_name;  // 가장 긴 타입 (위)
	 *     unsigned long foo, bar;                     // 중간 길이
	 *     unsigned int tmp;                           // 중간 길이
	 *     int ret;                                     // 가장 짧은 타입 (아래)
	 *   * 이렇게 하면 파서가 더 빠르게 처리할 수 있음 (Documentation/process/maintainer-tip.rst:651)
	 * - 같은 타입의 변수는 한 줄에 묶는 것이 좋음 (공간 절약)
	 * - 초기화는 선언과 분리하는 것이 선호됨
	 *
	 * 커널 커맨드 라인의 출처와 전달 과정:
	 *
	 * 1. 사용자가 부트로더에 커맨드 라인 입력
	 *    - GRUB 예시: GRUB 메뉴에서 'e' 키를 눌러 편집
	 *      linux /vmlinuz-5.x.x root=/dev/sda1 console=ttyS0,115200
	 *    - 또는 GRUB 설정 파일(/boot/grub/grub.cfg)에:
	 *      linux /vmlinuz root=/dev/sda1 console=ttyS0
	 *    - 이것은 "./linux --help" 같은 형식이 아니라, 부팅 시 커널에 전달되는 파라미터
	 *
	 * 2. 부트로더가 커맨드 라인을 메모리에 저장하는 과정 (x86 아키텍처)
	 *
	 *    [비유] 편지를 보내는 과정과 비슷합니다:
	 *    - 편지 내용(커맨드 라인 문자열)을 어딘가에 두고
	 *    - 편지함(boot_params)에 그 위치를 적어둠
	 *    - 받는 사람(커널)이 편지함을 열어서 위치를 보고 편지를 가져옴
	 *
	 *    [실제 메모리 레이아웃 예시]
	 *    메모리 주소          내용
	 *    ──────────────────────────────────────────────
	 *    0x10000            "root=/dev/sda1 console=ttyS0"  <- 커맨드 라인 문자열
	 *    ...                (다른 데이터들)
	 *    0x90000            boot_params 구조체 시작
	 *                       └─ hdr.cmd_line_ptr = 0x10000   <- 여기에 주소 저장!
	 *
	 *    [단계별 설명]
	 *
	 *    단계 1: GRUB이 커맨드 라인 문자열을 메모리에 저장
	 *    - 사용자가 입력한 "root=/dev/sda1 console=ttyS0" 문자열을
	 *      메모리의 특정 위치(예: 0x10000)에 복사
	 *    - 이 위치는 부트로더가 자유롭게 선택 가능 (0x10000 ~ 0xA0000 사이)
	 *
	 *    단계 2: GRUB이 그 주소를 boot_params 구조체에 기록
	 *    - boot_params는 부트로더와 커널이 정보를 주고받는 구조체
	 *      * 정의: arch/x86/include/uapi/asm/bootparam.h:116
	 *      * 크기: 약 4KB 정도의 큰 구조체
	 *      * 위치: 보통 0x90000 근처에 위치
	 *    - boot_params 안에는 setup_header 구조체가 포함되어 있음
	 *      * 정의: arch/x86/include/uapi/asm/bootparam.h:38
	 *      * boot_params.hdr가 이 구조체를 가리킴
	 *    - setup_header 안에 cmd_line_ptr 필드가 있음 (line 62)
	 *      * 타입: __u32 (32비트 정수 = 4바이트)
	 *      * 의미: 커맨드 라인 문자열이 있는 메모리 주소(물리 주소)
	 *      * GRUB이 여기에 0x10000 같은 값을 써넣음
	 *
	 *    단계 3: 커널이 부팅되면서 이 주소를 읽어서 커맨드 라인을 가져옴
	 *    - 코드 위치: arch/x86/kernel/head64.c:194-211 (copy_bootdata 함수)
	 *    - 과정:
	 *      1) boot_params 구조체를 메모리에서 읽어옴 (line 205)
	 *      2) get_cmd_line_ptr() 호출 (line 207)
	 *         - boot_params.hdr.cmd_line_ptr 값을 읽음 (line 187)
	 *         - 64비트 시스템에서는 ext_cmd_line_ptr도 함께 사용 (line 189)
	 *         - 결과: 예를 들어 0x10000 같은 물리 주소 반환
	 *      3) __va(cmd_line_ptr) 호출 (line 209)
	 *         - 물리 주소를 가상 주소로 변환
	 *         - 예: 물리 주소 0x10000 → 가상 주소 0xffff8800000010000
	 *      4) memcpy로 boot_command_line에 복사 (line 210)
	 *         - boot_command_line 정의: init/main.c:143
	 *         - 크기: COMMAND_LINE_SIZE (보통 2048 바이트)
	 *
	 *    [핵심 개념]
	 *    - cmd_line_ptr은 "포인터"입니다. 즉, 실제 문자열이 아니라
	 *      문자열이 있는 위치를 가리키는 주소입니다.
	 *    - 마치 집 주소를 적어두는 것과 같습니다:
	 *      * "서울시 강남구..." (주소 = cmd_line_ptr)
	 *      * vs 실제 집 (커맨드 라인 문자열)
	 *    - GRUB은 실제 문자열을 메모리에 두고, 그 주소만 boot_params에 기록
	 *    - 커널은 그 주소를 읽어서 실제 문자열을 가져옴
	 *
	 *    - ARM/ARM64 아키텍처의 경우:
	 *      * Device Tree의 "bootargs" 속성 사용
	 *      * 또는 레거시 ATAG(ARM Tagged List) 사용
	 *      * 예시: Device Tree에 "bootargs = "root=/dev/sda1 console=ttyS0";"
	 *
	 *    - EFI 시스템의 경우:
	 *      * EFI Loaded Image Protocol 사용
	 *      * efi_handle_cmdline() 함수: drivers/firmware/efi/libstub/efi-stub.c:105
	 *      * EFI에서 커맨드 라인을 가져와서 Device Tree나 boot_params에 설정
	 *
	 * 3. 커널이 커맨드 라인을 읽어서 처리
	 *    - x86: head64.c의 copy_bootdata()에서 boot_command_line에 복사
	 *    - setup_arch()에서 아키텍처별로 추가 처리 (arch/x86/kernel/setup.c:880)
	 *    - setup_command_line()에서 저장 (init/main.c:644)
	 *    - parse_args()로 파싱하여 각 파라미터 처리
	 *
	 * 참고:
	 * - "./linux --help" 같은 형식이 아님
	 * - 부팅 시 부트로더가 커널 이미지와 함께 커맨드 라인을 메모리에 준비
	 * - 커널은 부팅 초기에 이 메모리 위치에서 커맨드 라인을 읽어옴
	 * - 커맨드 라인은 커널 파라미터와 init 프로세스 인자를 모두 포함
	 * - "--" 구분자로 커널 파라미터와 init 인자를 구분
	 *
	 * 이 변수들의 용도:
	 *
	 * 1. command_line: 아키텍처별로 처리된 커널 커맨드 라인
	 *    - setup_arch(&command_line) 호출 시 포인터로 전달 (init/main.c:1023)
	 *    - setup_arch() 함수 정의: arch/*/kernel/setup.c (아키텍처별로 다름)
	 *    - setup_arch()에서 아키텍처별 커맨드 라인 파싱 및 처리 후 포인터 반환
	 *    - 사용 위치:
	 *      * setup_command_line(command_line): 커맨드 라인 저장 (init/main.c:1029)
	 *        - 함수 정의: init/main.c:644
	 *        - saved_command_line, static_command_line에 저장
	 *      * random_init_early(command_line): 랜덤 초기화 (init/main.c:1052)
	 *        - 커맨드 라인에서 랜덤 관련 파라미터 파싱
	 *
	 * 2. after_dashes: 커맨드 라인에서 "--" 이후의 인자들
	 *    - parse_args() 함수가 "--"를 만나면 그 이후 문자열을 반환
	 *    - parse_args() 정의: kernel/params.c:161
	 *    - "--"는 커널 파라미터와 init 프로세스 인자를 구분하는 구분자
	 *    - 사용 위치:
	 *      * parse_args("Booting kernel", ...) 반환값 저장 (init/main.c:1039)
	 *      * parse_args("Setting init args", after_dashes, ...) 호출 (init/main.c:1045)
	 *        - "--" 이후의 인자들을 init 프로세스에 전달하기 위해 파싱
	 *    - 예시: "console=ttyS0 -- init=/bin/sh"
	 *      * "console=ttyS0"는 커널 파라미터로 파싱
	 *      * "--" 이후의 "init=/bin/sh"는 after_dashes에 저장되어 init에 전달
	 *    - 참고: init 프로세스는 이 인자들을 argv로 받음
	 */
	char *command_line;
	char *after_dashes;

	/* init_task는 어디서 오는가?
	 * - 정의 위치: init/init_task.c:96 (struct task_struct init_task)
	 * - 커널 이미지에 정적으로 할당된 전역 변수 (컴파일 타임에 생성됨)
	 * - 부팅 시 가장 먼저 존재하는 태스크 (PID 0, "swapper" 프로세스)
	 * - 동적 할당 없이 바로 사용 가능하므로 부팅 초기에 안전하게 사용 가능
	 *
	 * init_task의 역할:
	 *
	 * 1. 모든 프로세스의 조상 (모든 프로세스의 부모/조부모)
	 *    - init_task는 PID 0을 가지며, 시스템의 모든 프로세스 트리의 루트
	 *    - init_task의 parent, real_parent는 자기 자신을 가리킴 (init/init_task.c:344-345)
	 *    - 모든 프로세스는 init_task.tasks 리스트에 연결됨 (kernel/fork.c:2416)
	 *    - init 프로세스(PID 1) 생성:
	 *      * rest_init()에서 user_mode_thread(kernel_init, ...) 호출 (init/main.c:722)
	 *      * kernel_init()이 나중에 실제 init 프로그램(/sbin/init 등) 실행 (init/main.c:1520-1593)
	 *      * fork 시 real_parent가 current(init_task)로 설정되어 자식이 됨 (kernel/fork.c:2415)
	 *    - 고아 프로세스 입양 메커니즘:
	 *      * 프로세스 종료 시 forget_original_parent() 호출 (kernel/exit.c:699)
	 *      * find_new_reaper()로 새로운 부모 찾기 (kernel/exit.c:637)
	 *      * 최종적으로 child_reaper(보통 PID 1)가 입양하지만, 네임스페이스 최상위는 init_task
	 *      * 실제 입양은 reparent_leader()에서 수행 (kernel/exit.c:675)
	 *    - 참고: 일반적으로 PID 1(init)이 고아를 입양하지만, init_task는 프로세스 트리 루트
	 *
	 * 2. CPU가 실행할 태스크가 없을 때 실행되는 idle 태스크 (swapper)
	 *    - 스케줄러가 실행할 다른 태스크가 없을 때 init_task가 실행됨
	 *    - 스케줄러는 idle_sched_class의 pick_task_idle()로 idle 태스크 선택 (kernel/sched/idle.c:473)
	 *    - 이때 init_task는 CPU를 낭비하지 않고 전력 절약을 위해 대기 상태로 전환
	 *    - 동작 방식 (코드 흐름):
	 *      * rest_init()에서 cpu_startup_entry(CPUHP_ONLINE) 호출 (init/main.c:757)
	 *      * cpu_startup_entry()가 무한 루프로 do_idle() 호출 (kernel/sched/idle.c:424-430)
	 *      * do_idle() 내부에서 need_resched()가 false일 때까지 반복 (kernel/sched/idle.c:280)
	 *      * arch_cpu_idle_enter() 호출 (kernel/sched/idle.c:319)
	 *      * cpuidle_idle_call() 또는 arch_cpu_idle() 호출 (kernel/sched/idle.c:332)
	 *      * x86의 경우: default_idle() -> raw_safe_halt() -> native_safe_halt() (arch/x86/kernel/process.c:765-767)
	 *      * native_safe_halt()에서 "sti; hlt" 어셈블리 명령 실행 (arch/x86/include/asm/irqflags.h:45-49)
	 *      * ARM의 경우: WFI (Wait For Interrupt) 명령 실행
	 *      * CPU 하드웨어 레벨에서 CPU를 저전력 대기 상태로 전환
	 *      * 인터럽트가 발생하면 CPU가 깨어나서 다시 스케줄링 수행
	 *    - 단순히 "pass"하는 것이 아니라 실제 CPU 명령어를 실행하여 하드웨어를 제어
	 *    - idle 태스크 설정:
	 *      * start_kernel() -> sched_init() -> init_idle(current, smp_processor_id()) (kernel/sched/core.c:8724)
	 *      * init_idle() 정의: kernel/sched/core.c:7889
	 *      * init_idle()에서 idle->sched_class = &idle_sched_class 설정 (kernel/sched/core.c:7943)
	 *      * init_idle()에서 idle 태스크 이름을 "swapper/0", "swapper/1" 등으로 설정 (kernel/sched/core.c:7946)
	 *    - 커맨드 이름이 "swapper"인 이유: 과거에는 메모리 스와핑을 담당했기 때문
	 *    - INIT_TASK_COMM 매크로 정의: include/linux/init_task.h:37 ("swapper")
	 *
	 * 3. 커널 부팅 초기 단계에서 실행되는 태스크
	 *    - start_kernel() 함수가 실행되는 동안 init_task가 현재 실행 중인 태스크
	 *    - 아직 다른 프로세스가 생성되기 전이므로 init_task가 유일한 실행 컨텍스트
	 *    - 스케줄러 초기화:
	 *      * sched_init() 호출: init/main.c:1061
	 *      * sched_init() 내부에서 init_idle() 호출로 idle 태스크로 설정
	 *    - 다른 프로세스 생성:
	 *      * rest_init() 호출: init/main.c:1202 (start_kernel()의 마지막 부분)
	 *      * rest_init()에서 init 프로세스(PID 1)와 kthreadd(PID 2) 생성
	 *      * 그 후 init_task는 idle 태스크로 전환되어 cpu_startup_entry() 진입
	 *    - 정적으로 할당되어 있어 동적 메모리 할당자(kmalloc)가 준비되기 전에도 사용 가능
	 *    - init_task는 컴파일 타임에 생성되므로 부팅 초기 단계에서 안전하게 사용 가능
	 *    - 참고: current 매크로가 init_task를 가리키는 시점은 start_kernel() 시작부터
	 *            rest_init()에서 다른 프로세스 생성 전까지
	 *
	 * 4. 나중에 각 CPU마다 idle 태스크가 생성되지만, init_task는 최초의 것
	 *    - SMP(다중 프로세서) 시스템에서는 각 CPU마다 별도의 idle 태스크가 필요
	 *    - 부팅 CPU(boot CPU)는 init_task를 그대로 idle 태스크로 사용
	 *      * idle_thread_set_boot_cpu() 호출: kernel/sched/core.c:8728
	 *      * kernel/smpboot.c:37-40에서 per_cpu(idle_threads, boot_cpu) = current 설정
	 *    - 다른 CPU들의 idle 태스크 생성:
	 *      * idle_threads_init() 호출로 모든 CPU 초기화 (kernel/smpboot.c:64)
	 *      * idle_init() 함수에서 fork_idle() 호출 (kernel/smpboot.c:48-58)
	 *      * fork_idle() 정의: kernel/fork.c:2540
	 *      * fork_idle()은 copy_process()를 통해 init_task를 복제
	 *    - 각 CPU의 idle 태스크는 "swapper/0", "swapper/1" 등으로 이름이 붙음
	 *      * init_idle()에서 sprintf(idle->comm, "%s/%d", INIT_TASK_COMM, cpu)로 설정
	 *    - init_task는 부팅 CPU의 idle 태스크로 계속 사용됨
	 *
	 * 여기서 하는 일 (set_task_stack_end_magic):
	 * - init_task의 커널 스택 끝에 매직 넘버(STACK_END_MAGIC)를 설정
	 * - 함수 정의: kernel/fork.c:871
	 * - 스택 오버플로우 감지를 위한 초기화
	 * - 매직 넘버 값: 0x57AC6E9D (include/linux/sched/task_stack.h)
	 * - 디버깅이나 크래시 상황에서 스택이 넘쳤는지 확인 가능
	 * - 매직 넘버가 덮어써지면 스택 오버플로우로 판단
	 *
	 * 추가 정보:
	 * - init_task는 절대 종료되지 않음 (usage 카운트가 2로 설정되어 해제 불가, init/init_task.c:124)
	 * - init_task는 PID 0을 가지며, 이는 특별한 의미를 가짐 (일반 프로세스는 PID 1부터 시작)
	 * - init_task는 커널 스레드이므로 사용자 공간이 없음 (mm = NULL, active_mm = &init_mm, init/init_task.c:122-123)
	 * - 모든 프로세스는 init_task.tasks 리스트에 연결되어 전역 프로세스 리스트를 형성 (kernel/fork.c:2416)
	 * - init_task는 root 권한을 가짐 (init_cred: UID/GID 0, 모든 capability, init/init_task.c:71-90)
	 */
	set_task_stack_end_magic(&init_task);
	/*
	 * smp_setup_processor_id - 부팅 CPU의 프로세서 ID 설정 및 논리-물리 CPU 매핑 초기화
	 *
	 * 이 함수는 커널 부팅 초기 단계에서 호출되어 부팅 CPU의 물리적 식별자를 확인하고,
	 * 논리적 CPU 번호와 물리적 CPU ID 간의 매핑을 설정합니다.
	 *
	 * 주요 작업:
	 *   1. MPIDR 레지스터에서 부팅 CPU의 물리적 ID 읽기
	 *   2. 논리적 CPU 0번과 물리적 CPU ID 간의 매핑 설정 (cpu_logical_map)
	 *   3. 나머지 CPU들의 초기 매핑 설정
	 *   4. Per-CPU 변수 접근을 위한 오프셋 초기화 (set_my_cpu_offset(0))
	 *
	 * 호출 시점:
	 *   - start_kernel() 함수의 초기화 과정 중 매우 이른 단계에 호출됨
	 *   - init_task 스택 매직 넘버 설정 직후
	 *   - 디버그 객체 초기화 전
	 *   - 인터럽트 비활성화 전
	 *
	 * 왜 이 시점에 필요한가:
	 *   - 이후 초기화 코드들이 CPU 식별이 필요할 수 있음
	 *   - Per-CPU 변수 접근이 가능해야 함 (lockdep 등)
	 *   - SMP 관련 초기화를 위한 기반 설정
	 *
	 * 아키텍처별 구현:
	 *   - ARM: arch/arm/kernel/setup.c:611
	 *   - ARM64: arch/arm64/kernel/setup.c:90
	 *   - RISC-V: arch/riscv/kernel/smp.c:59
	 *   - x86: 기본 구현 없음 (다른 방식으로 처리)
	 *   - 기본 (weak): init/main.c:799 (빈 함수)
	 *
	 * 참고:
	 *   - 이 함수는 아키텍처별로 다른 구현을 가질 수 있음 (__weak로 선언됨)
	 *   - 링커가 아키텍처별 구현을 찾으면 그것을 사용하고, 없으면 기본 구현 사용
	 *   - SMP 시스템에서만 의미가 있으며, UP 시스템에서는 대부분 빈 구현
	 */
	smp_setup_processor_id();
	debug_objects_early_init();
	init_vmlinux_build_id();

	cgroup_init_early();

	local_irq_disable();
	early_boot_irqs_disabled = true;

	/*
	 * Interrupts are still disabled. Do necessary setups, then
	 * enable them.
	 */
	boot_cpu_init();
	page_address_init();
	pr_notice("%s", linux_banner);
	setup_arch(&command_line);
	/* Static keys and static calls are needed by LSMs */
	jump_label_init();
	static_call_init();
	early_security_init();
	setup_boot_config();
	setup_command_line(command_line);
	setup_nr_cpu_ids();
	setup_per_cpu_areas();
	smp_prepare_boot_cpu();	/* arch-specific boot-cpu hooks */
	early_numa_node_init();
	boot_cpu_hotplug_init();

	pr_notice("Kernel command line: %s\n", saved_command_line);
	/* parameters may set static keys */
	parse_early_param();
	after_dashes = parse_args("Booting kernel",
				  static_command_line, __start___param,
				  __stop___param - __start___param,
				  -1, -1, NULL, &unknown_bootoption);
	print_unknown_bootoptions();
	if (!IS_ERR_OR_NULL(after_dashes))
		parse_args("Setting init args", after_dashes, NULL, 0, -1, -1,
			   NULL, set_init_arg);
	if (extra_init_args)
		parse_args("Setting extra init args", extra_init_args,
			   NULL, 0, -1, -1, NULL, set_init_arg);

	/* Architectural and non-timekeeping rng init, before allocator init */
	random_init_early(command_line);

	/*
	 * These use large bootmem allocations and must precede
	 * initalization of page allocator
	 */
	setup_log_buf(0);
	vfs_caches_init_early();
	sort_main_extable();
	trap_init();
	mm_core_init();
	maple_tree_init();
	poking_init();
	ftrace_init();

	/* trace_printk can be enabled here */
	early_trace_init();

	/*
	 * Set up the scheduler prior starting any interrupts (such as the
	 * timer interrupt). Full topology setup happens at smp_init()
	 * time - but meanwhile we still have a functioning scheduler.
	 */
	sched_init();

	if (WARN(!irqs_disabled(),
		 "Interrupts were enabled *very* early, fixing it\n"))
		local_irq_disable();
	radix_tree_init();

	/*
	 * Set up housekeeping before setting up workqueues to allow the unbound
	 * workqueue to take non-housekeeping into account.
	 */
	housekeeping_init();

	/*
	 * Allow workqueue creation and work item queueing/cancelling
	 * early.  Work item execution depends on kthreads and starts after
	 * workqueue_init().
	 */
	workqueue_init_early();

	rcu_init();
	kvfree_rcu_init();

	/* Trace events are available after this */
	trace_init();

	if (initcall_debug)
		initcall_debug_enable();

	context_tracking_init();
	/* init some links before init_ISA_irqs() */
	early_irq_init();
	init_IRQ();
	tick_init();
	rcu_init_nohz();
	timers_init();
	srcu_init();
	hrtimers_init();
	softirq_init();
	timekeeping_init();
	time_init();

	/* This must be after timekeeping is initialized */
	random_init();

	/* These make use of the fully initialized rng */
	kfence_init();
	boot_init_stack_canary();

	perf_event_init();
	profile_init();
	call_function_init();
	WARN(!irqs_disabled(), "Interrupts were enabled early\n");

	early_boot_irqs_disabled = false;
	local_irq_enable();

	kmem_cache_init_late();

	/*
	 * HACK ALERT! This is early. We're enabling the console before
	 * we've done PCI setups etc, and console_init() must be aware of
	 * this. But we do want output early, in case something goes wrong.
	 */
	console_init();
	if (panic_later)
		panic("Too many boot %s vars at `%s'", panic_later,
		      panic_param);

	lockdep_init();

	/*
	 * Need to run this when irqs are enabled, because it wants
	 * to self-test [hard/soft]-irqs on/off lock inversion bugs
	 * too:
	 */
	locking_selftest();

#ifdef CONFIG_BLK_DEV_INITRD
	if (initrd_start && !initrd_below_start_ok &&
	    page_to_pfn(virt_to_page((void *)initrd_start)) < min_low_pfn) {
		pr_crit("initrd overwritten (0x%08lx < 0x%08lx) - disabling it.\n",
		    page_to_pfn(virt_to_page((void *)initrd_start)),
		    min_low_pfn);
		initrd_start = 0;
	}
#endif
	setup_per_cpu_pageset();
	numa_policy_init();
	acpi_early_init();
	if (late_time_init)
		late_time_init();
	sched_clock_init();
	calibrate_delay();

	arch_cpu_finalize_init();

	pid_idr_init();
	anon_vma_init();
	thread_stack_cache_init();
	cred_init();
	fork_init();
	proc_caches_init();
	uts_ns_init();
	time_ns_init();
	key_init();
	security_init();
	dbg_late_init();
	net_ns_init();
	vfs_caches_init();
	pagecache_init();
	signals_init();
	seq_file_init();
	proc_root_init();
	nsfs_init();
	pidfs_init();
	cpuset_init();
	mem_cgroup_init();
	cgroup_init();
	taskstats_init_early();
	delayacct_init();

	acpi_subsystem_init();
	arch_post_acpi_subsys_init();
	kcsan_init();

	/* Do the rest non-__init'ed, we're now alive */
	rest_init();

	/*
	 * Avoid stack canaries in callers of boot_init_stack_canary for gcc-10
	 * and older.
	 */
#if !__has_attribute(__no_stack_protector__)
	prevent_tail_call_optimization();
#endif
}

/* Call all constructor functions linked into the kernel. */
static void __init do_ctors(void)
{
/*
 * For UML, the constructors have already been called by the
 * normal setup code as it's just a normal ELF binary, so we
 * cannot do it again - but we do need CONFIG_CONSTRUCTORS
 * even on UML for modules.
 */
#if defined(CONFIG_CONSTRUCTORS) && !defined(CONFIG_UML)
	ctor_fn_t *fn = (ctor_fn_t *) __ctors_start;

	for (; fn < (ctor_fn_t *) __ctors_end; fn++)
		(*fn)();
#endif
}

#ifdef CONFIG_KALLSYMS
struct blacklist_entry {
	struct list_head next;
	char *buf;
};

static __initdata_or_module LIST_HEAD(blacklisted_initcalls);

static int __init initcall_blacklist(char *str)
{
	char *str_entry;
	struct blacklist_entry *entry;

	/* str argument is a comma-separated list of functions */
	do {
		str_entry = strsep(&str, ",");
		if (str_entry) {
			pr_debug("blacklisting initcall %s\n", str_entry);
			entry = memblock_alloc_or_panic(sizeof(*entry),
					       SMP_CACHE_BYTES);
			entry->buf = memblock_alloc_or_panic(strlen(str_entry) + 1,
						    SMP_CACHE_BYTES);
			strcpy(entry->buf, str_entry);
			list_add(&entry->next, &blacklisted_initcalls);
		}
	} while (str_entry);

	return 1;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
	struct blacklist_entry *entry;
	char fn_name[KSYM_SYMBOL_LEN];
	unsigned long addr;

	if (list_empty(&blacklisted_initcalls))
		return false;

	addr = (unsigned long) dereference_function_descriptor(fn);
	sprint_symbol_no_offset(fn_name, addr);

	/*
	 * fn will be "function_name [module_name]" where [module_name] is not
	 * displayed for built-in init functions.  Strip off the [module_name].
	 */
	strreplace(fn_name, ' ', '\0');

	list_for_each_entry(entry, &blacklisted_initcalls, next) {
		if (!strcmp(fn_name, entry->buf)) {
			pr_debug("initcall %s blacklisted\n", fn_name);
			return true;
		}
	}

	return false;
}
#else
static int __init initcall_blacklist(char *str)
{
	pr_warn("initcall_blacklist requires CONFIG_KALLSYMS\n");
	return 0;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
	return false;
}
#endif
__setup("initcall_blacklist=", initcall_blacklist);

static __init_or_module void
trace_initcall_start_cb(void *data, initcall_t fn)
{
	ktime_t *calltime = data;

	printk(KERN_DEBUG "calling  %pS @ %i\n", fn, task_pid_nr(current));
	*calltime = ktime_get();
}

static __init_or_module void
trace_initcall_finish_cb(void *data, initcall_t fn, int ret)
{
	ktime_t rettime, *calltime = data;

	rettime = ktime_get();
	printk(KERN_DEBUG "initcall %pS returned %d after %lld usecs\n",
		 fn, ret, (unsigned long long)ktime_us_delta(rettime, *calltime));
}

static __init_or_module void
trace_initcall_level_cb(void *data, const char *level)
{
	printk(KERN_DEBUG "entering initcall level: %s\n", level);
}

static ktime_t initcall_calltime;

#ifdef TRACEPOINTS_ENABLED
static void __init initcall_debug_enable(void)
{
	int ret;

	ret = register_trace_initcall_start(trace_initcall_start_cb,
					    &initcall_calltime);
	ret |= register_trace_initcall_finish(trace_initcall_finish_cb,
					      &initcall_calltime);
	ret |= register_trace_initcall_level(trace_initcall_level_cb, NULL);
	WARN(ret, "Failed to register initcall tracepoints\n");
}
# define do_trace_initcall_start	trace_initcall_start
# define do_trace_initcall_finish	trace_initcall_finish
# define do_trace_initcall_level	trace_initcall_level
#else
static inline void do_trace_initcall_start(initcall_t fn)
{
	if (!initcall_debug)
		return;
	trace_initcall_start_cb(&initcall_calltime, fn);
}
static inline void do_trace_initcall_finish(initcall_t fn, int ret)
{
	if (!initcall_debug)
		return;
	trace_initcall_finish_cb(&initcall_calltime, fn, ret);
}
static inline void do_trace_initcall_level(const char *level)
{
	if (!initcall_debug)
		return;
	trace_initcall_level_cb(NULL, level);
}
#endif /* !TRACEPOINTS_ENABLED */

int __init_or_module do_one_initcall(initcall_t fn)
{
	int count = preempt_count();
	char msgbuf[64];
	int ret;

	if (initcall_blacklisted(fn))
		return -EPERM;

	do_trace_initcall_start(fn);
	ret = fn();
	do_trace_initcall_finish(fn, ret);

	msgbuf[0] = 0;

	if (preempt_count() != count) {
		sprintf(msgbuf, "preemption imbalance ");
		preempt_count_set(count);
	}
	if (irqs_disabled()) {
		strlcat(msgbuf, "disabled interrupts ", sizeof(msgbuf));
		local_irq_enable();
	}
	WARN(msgbuf[0], "initcall %pS returned with %s\n", fn, msgbuf);

	add_latent_entropy();
	return ret;
}


static initcall_entry_t *initcall_levels[] __initdata = {
	__initcall0_start,
	__initcall1_start,
	__initcall2_start,
	__initcall3_start,
	__initcall4_start,
	__initcall5_start,
	__initcall6_start,
	__initcall7_start,
	__initcall_end,
};

/* Keep these in sync with initcalls in include/linux/init.h */
static const char *initcall_level_names[] __initdata = {
	"pure",
	"core",
	"postcore",
	"arch",
	"subsys",
	"fs",
	"device",
	"late",
};

static int __init ignore_unknown_bootoption(char *param, char *val,
			       const char *unused, void *arg)
{
	return 0;
}

static void __init do_initcall_level(int level, char *command_line)
{
	initcall_entry_t *fn;

	parse_args(initcall_level_names[level],
		   command_line, __start___param,
		   __stop___param - __start___param,
		   level, level,
		   NULL, ignore_unknown_bootoption);

	do_trace_initcall_level(initcall_level_names[level]);
	for (fn = initcall_levels[level]; fn < initcall_levels[level+1]; fn++)
		do_one_initcall(initcall_from_entry(fn));
}

static void __init do_initcalls(void)
{
	int level;
	size_t len = saved_command_line_len + 1;
	char *command_line;

	command_line = kzalloc(len, GFP_KERNEL);
	if (!command_line)
		panic("%s: Failed to allocate %zu bytes\n", __func__, len);

	for (level = 0; level < ARRAY_SIZE(initcall_levels) - 1; level++) {
		/* Parser modifies command_line, restore it each time */
		strcpy(command_line, saved_command_line);
		do_initcall_level(level, command_line);
	}

	kfree(command_line);
}

/*
 * Ok, the machine is now initialized. None of the devices
 * have been touched yet, but the CPU subsystem is up and
 * running, and memory and process management works.
 *
 * Now we can finally start doing some real work..
 */
static void __init do_basic_setup(void)
{
	cpuset_init_smp();
	driver_init();
	init_irq_proc();
	do_ctors();
	do_initcalls();
}

static void __init do_pre_smp_initcalls(void)
{
	initcall_entry_t *fn;

	do_trace_initcall_level("early");
	for (fn = __initcall_start; fn < __initcall0_start; fn++)
		do_one_initcall(initcall_from_entry(fn));
}

static int run_init_process(const char *init_filename)
{
	const char *const *p;

	argv_init[0] = init_filename;
	pr_info("Run %s as init process\n", init_filename);
	pr_debug("  with arguments:\n");
	for (p = argv_init; *p; p++)
		pr_debug("    %s\n", *p);
	pr_debug("  with environment:\n");
	for (p = envp_init; *p; p++)
		pr_debug("    %s\n", *p);
	return kernel_execve(init_filename, argv_init, envp_init);
}

static int try_to_run_init_process(const char *init_filename)
{
	int ret;

	ret = run_init_process(init_filename);

	if (ret && ret != -ENOENT) {
		pr_err("Starting init: %s exists but couldn't execute it (error %d)\n",
		       init_filename, ret);
	}

	return ret;
}

static noinline void __init kernel_init_freeable(void);

#if defined(CONFIG_STRICT_KERNEL_RWX) || defined(CONFIG_STRICT_MODULE_RWX)
bool rodata_enabled __ro_after_init = true;

#ifndef arch_parse_debug_rodata
static inline bool arch_parse_debug_rodata(char *str) { return false; }
#endif

static int __init set_debug_rodata(char *str)
{
	if (arch_parse_debug_rodata(str))
		return 0;

	if (str && !strcmp(str, "on"))
		rodata_enabled = true;
	else if (str && !strcmp(str, "off"))
		rodata_enabled = false;
	else
		pr_warn("Invalid option string for rodata: '%s'\n", str);
	return 0;
}
early_param("rodata", set_debug_rodata);
#endif

static void mark_readonly(void)
{
	if (IS_ENABLED(CONFIG_STRICT_KERNEL_RWX) && rodata_enabled) {
		/*
		 * load_module() results in W+X mappings, which are cleaned
		 * up with init_free_wq. Let's make sure that queued work is
		 * flushed so that we don't hit false positives looking for
		 * insecure pages which are W+X.
		 */
		flush_module_init_free_work();
		jump_label_init_ro();
		mark_rodata_ro();
		debug_checkwx();
		rodata_test();
	} else if (IS_ENABLED(CONFIG_STRICT_KERNEL_RWX)) {
		pr_info("Kernel memory protection disabled.\n");
	} else if (IS_ENABLED(CONFIG_ARCH_HAS_STRICT_KERNEL_RWX)) {
		pr_warn("Kernel memory protection not selected by kernel config.\n");
	} else {
		pr_warn("This architecture does not have kernel memory protection.\n");
	}
}

void __weak free_initmem(void)
{
	free_initmem_default(POISON_FREE_INITMEM);
}

static int __ref kernel_init(void *unused)
{
	int ret;

	/*
	 * Wait until kthreadd is all set-up.
	 */
	wait_for_completion(&kthreadd_done);

	kernel_init_freeable();
	/* need to finish all async __init code before freeing the memory */
	async_synchronize_full();

	system_state = SYSTEM_FREEING_INITMEM;
	kprobe_free_init_mem();
	ftrace_free_init_mem();
	kgdb_free_init_mem();
	exit_boot_config();
	free_initmem();
	mark_readonly();

	/*
	 * Kernel mappings are now finalized - update the userspace page-table
	 * to finalize PTI.
	 */
	pti_finalize();

	system_state = SYSTEM_RUNNING;
	numa_default_policy();

	rcu_end_inkernel_boot();

	do_sysctl_args();

	if (ramdisk_execute_command) {
		ret = run_init_process(ramdisk_execute_command);
		if (!ret)
			return 0;
		pr_err("Failed to execute %s (error %d)\n",
		       ramdisk_execute_command, ret);
	}

	/*
	 * We try each of these until one succeeds.
	 *
	 * The Bourne shell can be used instead of init if we are
	 * trying to recover a really broken machine.
	 */
	if (execute_command) {
		ret = run_init_process(execute_command);
		if (!ret)
			return 0;
		panic("Requested init %s failed (error %d).",
		      execute_command, ret);
	}

	if (CONFIG_DEFAULT_INIT[0] != '\0') {
		ret = run_init_process(CONFIG_DEFAULT_INIT);
		if (ret)
			pr_err("Default init %s failed (error %d)\n",
			       CONFIG_DEFAULT_INIT, ret);
		else
			return 0;
	}

	if (!try_to_run_init_process("/sbin/init") ||
	    !try_to_run_init_process("/etc/init") ||
	    !try_to_run_init_process("/bin/init") ||
	    !try_to_run_init_process("/bin/sh"))
		return 0;

	panic("No working init found.  Try passing init= option to kernel. "
	      "See Linux Documentation/admin-guide/init.rst for guidance.");
}

/* Open /dev/console, for stdin/stdout/stderr, this should never fail */
void __init console_on_rootfs(void)
{
	struct file *file = filp_open("/dev/console", O_RDWR, 0);

	if (IS_ERR(file)) {
		pr_err("Warning: unable to open an initial console.\n");
		return;
	}
	init_dup(file);
	init_dup(file);
	init_dup(file);
	fput(file);
}

static noinline void __init kernel_init_freeable(void)
{
	/* Now the scheduler is fully set up and can do blocking allocations */
	gfp_allowed_mask = __GFP_BITS_MASK;

	/*
	 * init can allocate pages on any node
	 */
	set_mems_allowed(node_states[N_MEMORY]);

	cad_pid = get_pid(task_pid(current));

	smp_prepare_cpus(setup_max_cpus);

	workqueue_init();

	init_mm_internals();

	do_pre_smp_initcalls();
	lockup_detector_init();

	smp_init();
	sched_init_smp();

	workqueue_init_topology();
	async_init();
	padata_init();
	page_alloc_init_late();

	do_basic_setup();

	kunit_run_all_tests();

	wait_for_initramfs();
	console_on_rootfs();

	/*
	 * check if there is an early userspace init.  If yes, let it do all
	 * the work
	 */
	int ramdisk_command_access;
	ramdisk_command_access = init_eaccess(ramdisk_execute_command);
	if (ramdisk_command_access != 0) {
		pr_warn("check access for rdinit=%s failed: %i, ignoring\n",
			ramdisk_execute_command, ramdisk_command_access);
		ramdisk_execute_command = NULL;
		prepare_namespace();
	}

	/*
	 * Ok, we have completed the initial bootup, and
	 * we're essentially up and running. Get rid of the
	 * initmem segments and start the user-mode stuff..
	 *
	 * rootfs is available now, try loading the public keys
	 * and default modules
	 */

	integrity_load_keys();
}
