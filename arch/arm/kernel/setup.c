// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/arch/arm/kernel/setup.c
 *
 *  Copyright (C) 1995-2001 Russell King
 */
#include <linux/efi.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/ioport.h>
#include <linux/delay.h>
#include <linux/utsname.h>
#include <linux/initrd.h>
#include <linux/console.h>
#include <linux/seq_file.h>
#include <linux/screen_info.h>
#include <linux/init.h>
#include <linux/kexec.h>
#include <linux/libfdt.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/smp.h>
#include <linux/proc_fs.h>
#include <linux/memblock.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/sort.h>
#include <linux/psci.h>

#include <asm/unified.h>
#include <asm/cp15.h>
#include <asm/cpu.h>
#include <asm/cputype.h>
#include <asm/efi.h>
#include <asm/elf.h>
#include <asm/early_ioremap.h>
#include <asm/fixmap.h>
#include <asm/procinfo.h>
#include <asm/psci.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <asm/smp_plat.h>
#include <asm/mach-types.h>
#include <asm/cacheflush.h>
#include <asm/cachetype.h>
#include <asm/tlbflush.h>
#include <asm/xen/hypervisor.h>

#include <asm/prom.h>
#include <asm/mach/arch.h>
#include <asm/mach/irq.h>
#include <asm/mach/time.h>
#include <asm/system_info.h>
#include <asm/system_misc.h>
#include <asm/traps.h>
#include <asm/unwind.h>
#include <asm/memblock.h>
#include <asm/virt.h>
#include <asm/kasan.h>

#include "atags.h"


#if defined(CONFIG_FPE_NWFPE) || defined(CONFIG_FPE_FASTFPE)
char fpe_type[8];

static int __init fpe_setup(char *line)
{
	memcpy(fpe_type, line, 8);
	return 1;
}

__setup("fpe=", fpe_setup);
#endif

unsigned int processor_id;
EXPORT_SYMBOL(processor_id);
unsigned int __machine_arch_type __read_mostly;
EXPORT_SYMBOL(__machine_arch_type);
unsigned int cacheid __read_mostly;
EXPORT_SYMBOL(cacheid);

unsigned int __atags_pointer __initdata;

unsigned int system_rev;
EXPORT_SYMBOL(system_rev);

const char *system_serial;
EXPORT_SYMBOL(system_serial);

unsigned int system_serial_low;
EXPORT_SYMBOL(system_serial_low);

unsigned int system_serial_high;
EXPORT_SYMBOL(system_serial_high);

unsigned int elf_hwcap __read_mostly;
EXPORT_SYMBOL(elf_hwcap);

unsigned int elf_hwcap2 __read_mostly;
EXPORT_SYMBOL(elf_hwcap2);


#ifdef MULTI_CPU
struct processor processor __ro_after_init;
#if defined(CONFIG_BIG_LITTLE) && defined(CONFIG_HARDEN_BRANCH_PREDICTOR)
struct processor *cpu_vtable[NR_CPUS] = {
	[0] = &processor,
};
#endif
#endif
#ifdef MULTI_TLB
struct cpu_tlb_fns cpu_tlb __ro_after_init;
#endif
#ifdef MULTI_USER
struct cpu_user_fns cpu_user __ro_after_init;
#endif
#ifdef MULTI_CACHE
struct cpu_cache_fns cpu_cache __ro_after_init;
#endif
#ifdef CONFIG_OUTER_CACHE
struct outer_cache_fns outer_cache __ro_after_init;
EXPORT_SYMBOL(outer_cache);
#endif

/*
 * Cached cpu_architecture() result for use by assembler code.
 * C code should use the cpu_architecture() function instead of accessing this
 * variable directly.
 */
int __cpu_architecture __read_mostly = CPU_ARCH_UNKNOWN;

struct stack {
	u32 irq[4];
	u32 abt[4];
	u32 und[4];
	u32 fiq[4];
} ____cacheline_aligned;

#ifndef CONFIG_CPU_V7M
static struct stack stacks[NR_CPUS];
#endif

char elf_platform[ELF_PLATFORM_SIZE];
EXPORT_SYMBOL(elf_platform);

static const char *cpu_name;
static const char *machine_name;
static char __initdata cmd_line[COMMAND_LINE_SIZE];
const struct machine_desc *machine_desc __initdata;

static union { char c[4]; unsigned long l; } endian_test __initdata = { { 'l', '?', '?', 'b' } };
#define ENDIANNESS ((char)endian_test.l)

DEFINE_PER_CPU(struct cpuinfo_arm, cpu_data);

/*
 * Standard memory resources
 */
static struct resource mem_res[] = {
	{
		.name = "Video RAM",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_MEM
	},
	{
		.name = "Kernel code",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_SYSTEM_RAM
	},
	{
		.name = "Kernel data",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_SYSTEM_RAM
	}
};

#define video_ram   mem_res[0]
#define kernel_code mem_res[1]
#define kernel_data mem_res[2]

static struct resource io_res[] = {
	{
		.name = "reserved",
		.start = 0x3bc,
		.end = 0x3be,
		.flags = IORESOURCE_IO | IORESOURCE_BUSY
	},
	{
		.name = "reserved",
		.start = 0x378,
		.end = 0x37f,
		.flags = IORESOURCE_IO | IORESOURCE_BUSY
	},
	{
		.name = "reserved",
		.start = 0x278,
		.end = 0x27f,
		.flags = IORESOURCE_IO | IORESOURCE_BUSY
	}
};

#define lp0 io_res[0]
#define lp1 io_res[1]
#define lp2 io_res[2]

static const char *proc_arch[] = {
	"undefined/unknown",
	"3",
	"4",
	"4T",
	"5",
	"5T",
	"5TE",
	"5TEJ",
	"6TEJ",
	"7",
	"7M",
	"?(12)",
	"?(13)",
	"?(14)",
	"?(15)",
	"?(16)",
	"?(17)",
};

#ifdef CONFIG_CPU_V7M
static int __get_cpu_architecture(void)
{
	return CPU_ARCH_ARMv7M;
}
#else
static int __get_cpu_architecture(void)
{
	int cpu_arch;

	if ((read_cpuid_id() & 0x0008f000) == 0) {
		cpu_arch = CPU_ARCH_UNKNOWN;
	} else if ((read_cpuid_id() & 0x0008f000) == 0x00007000) {
		cpu_arch = (read_cpuid_id() & (1 << 23)) ? CPU_ARCH_ARMv4T : CPU_ARCH_ARMv3;
	} else if ((read_cpuid_id() & 0x00080000) == 0x00000000) {
		cpu_arch = (read_cpuid_id() >> 16) & 7;
		if (cpu_arch)
			cpu_arch += CPU_ARCH_ARMv3;
	} else if ((read_cpuid_id() & 0x000f0000) == 0x000f0000) {
		/* Revised CPUID format. Read the Memory Model Feature
		 * Register 0 and check for VMSAv7 or PMSAv7 */
		unsigned int mmfr0 = read_cpuid_ext(CPUID_EXT_MMFR0);
		if ((mmfr0 & 0x0000000f) >= 0x00000003 ||
		    (mmfr0 & 0x000000f0) >= 0x00000030)
			cpu_arch = CPU_ARCH_ARMv7;
		else if ((mmfr0 & 0x0000000f) == 0x00000002 ||
			 (mmfr0 & 0x000000f0) == 0x00000020)
			cpu_arch = CPU_ARCH_ARMv6;
		else
			cpu_arch = CPU_ARCH_UNKNOWN;
	} else
		cpu_arch = CPU_ARCH_UNKNOWN;

	return cpu_arch;
}
#endif

int __pure cpu_architecture(void)
{
	BUG_ON(__cpu_architecture == CPU_ARCH_UNKNOWN);

	return __cpu_architecture;
}

static int cpu_has_aliasing_icache(unsigned int arch)
{
	int aliasing_icache;
	unsigned int id_reg, num_sets, line_size;

	/* PIPT caches never alias. */
	if (icache_is_pipt())
		return 0;

	/* arch specifies the register format */
	switch (arch) {
	case CPU_ARCH_ARMv7:
		set_csselr(CSSELR_ICACHE | CSSELR_L1);
		isb();
		id_reg = read_ccsidr();
		line_size = 4 << ((id_reg & 0x7) + 2);
		num_sets = ((id_reg >> 13) & 0x7fff) + 1;
		aliasing_icache = (line_size * num_sets) > PAGE_SIZE;
		break;
	case CPU_ARCH_ARMv6:
		aliasing_icache = read_cpuid_cachetype() & (1 << 11);
		break;
	default:
		/* I-cache aliases will be handled by D-cache aliasing code */
		aliasing_icache = 0;
	}

	return aliasing_icache;
}

static void __init cacheid_init(void)
{
	unsigned int arch = cpu_architecture();

	if (arch >= CPU_ARCH_ARMv6) {
		unsigned int cachetype = read_cpuid_cachetype();

		if ((arch == CPU_ARCH_ARMv7M) && !(cachetype & 0xf000f)) {
			cacheid = 0;
		} else if ((cachetype & (7 << 29)) == 4 << 29) {
			/* ARMv7 register format */
			arch = CPU_ARCH_ARMv7;
			cacheid = CACHEID_VIPT_NONALIASING;
			switch (cachetype & (3 << 14)) {
			case (1 << 14):
				cacheid |= CACHEID_ASID_TAGGED;
				break;
			case (3 << 14):
				cacheid |= CACHEID_PIPT;
				break;
			}
		} else {
			arch = CPU_ARCH_ARMv6;
			if (cachetype & (1 << 23))
				cacheid = CACHEID_VIPT_ALIASING;
			else
				cacheid = CACHEID_VIPT_NONALIASING;
		}
		if (cpu_has_aliasing_icache(arch))
			cacheid |= CACHEID_VIPT_I_ALIASING;
	} else {
		cacheid = CACHEID_VIVT;
	}

	pr_info("CPU: %s data cache, %s instruction cache\n",
		cache_is_vivt() ? "VIVT" :
		cache_is_vipt_aliasing() ? "VIPT aliasing" :
		cache_is_vipt_nonaliasing() ? "PIPT / VIPT nonaliasing" : "unknown",
		cache_is_vivt() ? "VIVT" :
		icache_is_vivt_asid_tagged() ? "VIVT ASID tagged" :
		icache_is_vipt_aliasing() ? "VIPT aliasing" :
		icache_is_pipt() ? "PIPT" :
		cache_is_vipt_nonaliasing() ? "VIPT nonaliasing" : "unknown");
}

/*
 * These functions re-use the assembly code in head.S, which
 * already provide the required functionality.
 */
extern struct proc_info_list *lookup_processor_type(unsigned int);

void __init early_print(const char *str, ...)
{
	extern void printascii(const char *);
	char buf[256];
	va_list ap;

	va_start(ap, str);
	vsnprintf(buf, sizeof(buf), str, ap);
	va_end(ap);

#ifdef CONFIG_DEBUG_LL
	printascii(buf);
#endif
	printk("%s", buf);
}

#ifdef CONFIG_ARM_PATCH_IDIV

static inline u32 __attribute_const__ sdiv_instruction(void)
{
	if (IS_ENABLED(CONFIG_THUMB2_KERNEL)) {
		/* "sdiv r0, r0, r1" */
		u32 insn = __opcode_thumb32_compose(0xfb90, 0xf0f1);
		return __opcode_to_mem_thumb32(insn);
	}

	/* "sdiv r0, r0, r1" */
	return __opcode_to_mem_arm(0xe710f110);
}

static inline u32 __attribute_const__ udiv_instruction(void)
{
	if (IS_ENABLED(CONFIG_THUMB2_KERNEL)) {
		/* "udiv r0, r0, r1" */
		u32 insn = __opcode_thumb32_compose(0xfbb0, 0xf0f1);
		return __opcode_to_mem_thumb32(insn);
	}

	/* "udiv r0, r0, r1" */
	return __opcode_to_mem_arm(0xe730f110);
}

static inline u32 __attribute_const__ bx_lr_instruction(void)
{
	if (IS_ENABLED(CONFIG_THUMB2_KERNEL)) {
		/* "bx lr; nop" */
		u32 insn = __opcode_thumb32_compose(0x4770, 0x46c0);
		return __opcode_to_mem_thumb32(insn);
	}

	/* "bx lr" */
	return __opcode_to_mem_arm(0xe12fff1e);
}

static void __init patch_aeabi_idiv(void)
{
	extern void __aeabi_uidiv(void);
	extern void __aeabi_idiv(void);
	uintptr_t fn_addr;
	unsigned int mask;

	mask = IS_ENABLED(CONFIG_THUMB2_KERNEL) ? HWCAP_IDIVT : HWCAP_IDIVA;
	if (!(elf_hwcap & mask))
		return;

	pr_info("CPU: div instructions available: patching division code\n");

	fn_addr = ((uintptr_t)&__aeabi_uidiv) & ~1;
	asm ("" : "+g" (fn_addr));
	((u32 *)fn_addr)[0] = udiv_instruction();
	((u32 *)fn_addr)[1] = bx_lr_instruction();
	flush_icache_range(fn_addr, fn_addr + 8);

	fn_addr = ((uintptr_t)&__aeabi_idiv) & ~1;
	asm ("" : "+g" (fn_addr));
	((u32 *)fn_addr)[0] = sdiv_instruction();
	((u32 *)fn_addr)[1] = bx_lr_instruction();
	flush_icache_range(fn_addr, fn_addr + 8);
}

#else
static inline void patch_aeabi_idiv(void) { }
#endif

static void __init cpuid_init_hwcaps(void)
{
	int block;
	u32 isar5;
	u32 isar6;
	u32 pfr2;

	if (cpu_architecture() < CPU_ARCH_ARMv7)
		return;

	block = cpuid_feature_extract(CPUID_EXT_ISAR0, 24);
	if (block >= 2)
		elf_hwcap |= HWCAP_IDIVA;
	if (block >= 1)
		elf_hwcap |= HWCAP_IDIVT;

	/* LPAE implies atomic ldrd/strd instructions */
	block = cpuid_feature_extract(CPUID_EXT_MMFR0, 0);
	if (block >= 5)
		elf_hwcap |= HWCAP_LPAE;

	/* check for supported v8 Crypto instructions */
	isar5 = read_cpuid_ext(CPUID_EXT_ISAR5);

	block = cpuid_feature_extract_field(isar5, 4);
	if (block >= 2)
		elf_hwcap2 |= HWCAP2_PMULL;
	if (block >= 1)
		elf_hwcap2 |= HWCAP2_AES;

	block = cpuid_feature_extract_field(isar5, 8);
	if (block >= 1)
		elf_hwcap2 |= HWCAP2_SHA1;

	block = cpuid_feature_extract_field(isar5, 12);
	if (block >= 1)
		elf_hwcap2 |= HWCAP2_SHA2;

	block = cpuid_feature_extract_field(isar5, 16);
	if (block >= 1)
		elf_hwcap2 |= HWCAP2_CRC32;

	/* Check for Speculation barrier instruction */
	isar6 = read_cpuid_ext(CPUID_EXT_ISAR6);
	block = cpuid_feature_extract_field(isar6, 12);
	if (block >= 1)
		elf_hwcap2 |= HWCAP2_SB;

	/* Check for Speculative Store Bypassing control */
	pfr2 = read_cpuid_ext(CPUID_EXT_PFR2);
	block = cpuid_feature_extract_field(pfr2, 4);
	if (block >= 1)
		elf_hwcap2 |= HWCAP2_SSBS;
}

static void __init elf_hwcap_fixup(void)
{
	unsigned id = read_cpuid_id();

	/*
	 * HWCAP_TLS is available only on 1136 r1p0 and later,
	 * see also kuser_get_tls_init.
	 */
	if (read_cpuid_part() == ARM_CPU_PART_ARM1136 &&
	    ((id >> 20) & 3) == 0) {
		elf_hwcap &= ~HWCAP_TLS;
		return;
	}

	/* Verify if CPUID scheme is implemented */
	if ((id & 0x000f0000) != 0x000f0000)
		return;

	/*
	 * If the CPU supports LDREX/STREX and LDREXB/STREXB,
	 * avoid advertising SWP; it may not be atomic with
	 * multiprocessing cores.
	 */
	if (cpuid_feature_extract(CPUID_EXT_ISAR3, 12) > 1 ||
	    (cpuid_feature_extract(CPUID_EXT_ISAR3, 12) == 1 &&
	     cpuid_feature_extract(CPUID_EXT_ISAR4, 20) >= 3))
		elf_hwcap &= ~HWCAP_SWP;
}

/*
 * cpu_init - initialise one CPU.
 *
 * cpu_init sets up the per-CPU stacks.
 */
void notrace cpu_init(void)
{
#ifndef CONFIG_CPU_V7M
	unsigned int cpu = smp_processor_id();
	struct stack *stk = &stacks[cpu];

	if (cpu >= NR_CPUS) {
		pr_crit("CPU%u: bad primary CPU number\n", cpu);
		BUG();
	}

	/*
	 * This only works on resume and secondary cores. For booting on the
	 * boot cpu, smp_prepare_boot_cpu is called after percpu area setup.
	 */
	set_my_cpu_offset(per_cpu_offset(cpu));

	cpu_proc_init();

	/*
	 * Define the placement constraint for the inline asm directive below.
	 * In Thumb-2, msr with an immediate value is not allowed.
	 */
#ifdef CONFIG_THUMB2_KERNEL
#define PLC_l	"l"
#define PLC_r	"r"
#else
#define PLC_l	"I"
#define PLC_r	"I"
#endif

	/*
	 * setup stacks for re-entrant exception handlers
	 */
	__asm__ (
	"msr	cpsr_c, %1\n\t"
	"add	r14, %0, %2\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %3\n\t"
	"add	r14, %0, %4\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %5\n\t"
	"add	r14, %0, %6\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %7\n\t"
	"add	r14, %0, %8\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %9"
	    :
	    : "r" (stk),
	      PLC_r (PSR_F_BIT | PSR_I_BIT | IRQ_MODE),
	      "I" (offsetof(struct stack, irq[0])),
	      PLC_r (PSR_F_BIT | PSR_I_BIT | ABT_MODE),
	      "I" (offsetof(struct stack, abt[0])),
	      PLC_r (PSR_F_BIT | PSR_I_BIT | UND_MODE),
	      "I" (offsetof(struct stack, und[0])),
	      PLC_r (PSR_F_BIT | PSR_I_BIT | FIQ_MODE),
	      "I" (offsetof(struct stack, fiq[0])),
	      PLC_l (PSR_F_BIT | PSR_I_BIT | SVC_MODE)
	    : "r14");
#endif
}

u32 __cpu_logical_map[NR_CPUS] = { [0 ... NR_CPUS-1] = MPIDR_INVALID };

/**
 * smp_setup_processor_id - 부팅 CPU의 프로세서 ID를 설정하고 논리-물리 CPU 매핑 초기화
 *
 * 이 함수는 커널 부팅 초기 단계에서 호출되어 부팅 CPU의 물리적 식별자(MPIDR)를 읽고,
 * 논리적 CPU 번호와 물리적 CPU ID 간의 매핑을 설정합니다.
 *
 * 주요 작업:
 * 1. MPIDR 레지스터에서 부팅 CPU의 물리적 ID 읽기
 * 2. 논리적 CPU 0번과 물리적 CPU ID 간의 매핑 설정
 * 3. 나머지 CPU들의 초기 매핑 설정
 * 4. Per-CPU 변수 접근을 위한 오프셋 초기화
 *
 * 호출 시점: init/main.c의 start_kernel()에서 초기화 과정 중 호출됨
 * 아키텍처: ARM 전용 구현 (다른 아키텍처는 각자의 구현 사용)
 */
void __init smp_setup_processor_id(void)
{
	int i;
	/*
	 * mpidr: Multiprocessor Affinity Register 값
	 *
	 * MPIDR 약자:
	 *   - M = Multiprocessor (멀티프로세서)
	 *   - PID = Processor ID (프로세서 식별자)
	 *   - R = Register (레지스터)
	 *   정식 명칭: Multiprocessor Affinity Register
	 *   ARM 아키텍처에서 각 CPU 코어의 고유 식별자와 어피니티 레벨 정보를 담는 레지스터
	 *
	 * 레지스터(Register)란:
	 *   - 레지스터는 메모리가 아닌 CPU 내부에 있는 고속 저장 공간입니다
	 *   - CPU가 직접 접근하는 가장 빠른 저장소로, 메모리 계층 구조의 최상위에 위치
	 *   - 물리적으로 CPU 칩 내부에 구현되어 있어 메모리(RAM)와는 완전히 다른 공간
	 *   - 용량은 매우 작지만(보통 수십~수백 바이트) 접근 속도가 매우 빠름 (1 사이클)
	 *   - 메모리 접근은 수백~수천 사이클이 걸리지만, 레지스터 접근은 1 사이클
	 *   - 레지스터는 CPU의 연산, 제어, 상태 저장 등에 사용됨
	 *   - 예: 범용 레지스터(r0-r15), 상태 레지스터, 제어 레지스터 등
	 *   - MPIDR은 CP15(시스템 제어 코프로세서)의 제어 레지스터 중 하나
	 *
	 * 제어 레지스터(Control Register)란:
	 *   - CPU의 동작을 제어하고 상태를 관리하는 특수 레지스터
	 *   - 범용 레지스터와 달리 특정 기능을 담당하는 전용 레지스터
	 *   - CP15 (Coprocessor 15): ARM의 시스템 제어 코프로세서
	 *     * MMU(Memory Management Unit) 제어
	 *     * 캐시 제어
	 *     * 인터럽트 제어
	 *     * CPU 식별 정보 (MPIDR 포함)
	 *     * 보안 및 권한 관리
	 *   - 제어 레지스터는 특수 어셈블리 명령어로만 접근 가능
	 *     * MRC (Move to Register from Coprocessor): 레지스터 읽기
	 *     * MCR (Move to Coprocessor from Register): 레지스터 쓰기
	 *   - 예: MMU 제어 레지스터, 캐시 제어 레지스터, MPIDR 등
	 *
	 * MPIDR 동작 방식:
	 *   - 읽기 전용 레지스터: 하드웨어가 부팅 시 자동으로 설정
	 *   - 각 CPU 코어마다 고유한 값: 하드웨어 설계 시 할당됨
	 *   - 어피니티 레벨(Affinity Level) 구조:
	 *     * Level 0 (비트 7:0):   CPU 코어 내 스레드 ID 또는 코어 ID
	 *     * Level 1 (비트 15:8):  클러스터 ID
	 *     * Level 2 (비트 23:16): 소켓/패키지 ID
	 *   - 비트 구성:
	 *     * 비트 31:30: SMP 모드 비트 (0x2 = SMP 활성화)
	 *     * 비트 24:    MT (Multithreading) 비트
	 *     * 비트 23:0:  하드웨어 ID (실제 CPU 식별자)
	 *   - 접근 방법:
	 *     * 어셈블리: "mrc p15, 0, r0, c0, c0, 5" (MPIDR 읽기)
	 *     * C 함수: read_cpuid_mpidr() (내부적으로 MRC 명령어 사용)
	 *   - 사용 예시:
	 *     * CPU 식별: 각 CPU가 자신의 고유 ID를 읽어서 구분
	 *     * 토폴로지 파싱: 어피니티 레벨로 CPU 계층 구조 파악
	 *     * 스케줄링: CPU 간 작업 분배 시 참조
	 *
	 * SMP (Symmetric Multi-Processing) 시스템:
	 *   - 여러 CPU가 동등한 권한으로 메모리와 I/O를 공유하며 동작하는 멀티프로세서 시스템
	 *   - 모든 CPU가 동일한 역할을 수행 (마스터/슬레이브 구분 없음)
	 *   - 모든 CPU가 커널 코드 실행 및 인터럽트 처리 가능
	 *   - 공유 메모리 아키텍처 사용
	 *   - 예: 듀얼코어, 쿼드코어 프로세서 등
	 *
	 * - SMP 시스템인 경우: CP15의 MPIDR 레지스터를 읽어 하드웨어 ID 비트만 추출 (비트 23:0)
	 *   각 CPU는 고유한 MPIDR 값을 가지므로, 이를 통해 CPU를 식별할 수 있습니다.
	 * - 단일 CPU 시스템인 경우: 0으로 설정
	 *   UP(Uni-Processor) 시스템에서는 CPU 식별이 불필요하므로 0을 사용합니다.
	 *
	 * MPIDR_HWID_BITMASK (0xFFFFFF)는 하위 24비트만 추출하여
	 * SMP 비트(31:30)와 MT 비트(24)를 제외한 실제 하드웨어 ID만 얻습니다.
	 *
	 * 예시: MPIDR = 0x80000002 (SMP=1, MT=0, HWID=2)인 경우
	 *       mpidr = 0x00000002
	 *
	 * 호출 함수 위치:
	 * - is_smp(): arch/arm/include/asm/smp_plat.h:18
	 * - read_cpuid_mpidr(): arch/arm/include/asm/cputype.h:260
	 * - MPIDR_HWID_BITMASK: arch/arm/include/asm/cputype.h:54
	 */
	u32 mpidr = is_smp() ? read_cpuid_mpidr() & MPIDR_HWID_BITMASK : 0;

	/*
	 * cpu: Affinity Level 0 값 (비트 7:0)
	 * - 멀티스레딩이 활성화된 경우: CPU 코어 내 스레드 ID
	 * - 멀티스레딩이 비활성화된 경우: 코어 ID
	 *
	 * MPIDR_AFFINITY_LEVEL 매크로는 MPIDR의 특정 레벨(0, 1, 2)에서
	 * 8비트씩 추출합니다.
	 *
	 * 예시: mpidr = 0x00000102 (클러스터=1, 코어=0, 스레드=2)인 경우
	 *       cpu = 2 (Level 0, 즉 스레드 ID)
	 *
	 * CPU의 계층 구조 (Affinity Level):
	 *   현대 멀티코어 프로세서는 물리적 계층 구조를 가지며, MPIDR의 Affinity Level은
	 *   이 계층 구조를 나타냅니다. 각 레벨은 CPU의 물리적 그룹핑과 공유 리소스를 의미합니다.
	 *
	 *   Level 2: 소켓/패키지 (Socket/Package)
	 *     - 물리적 CPU 칩 전체를 나타냄 (예: 듀얼 소켓 서버의 각 CPU)
	 *     - 같은 소켓의 CPU들은 메모리 컨트롤러와 L3 캐시를 공유
	 *     - NUMA 노드와 밀접한 관련 (같은 소켓 = 같은 NUMA 노드)
	 *
	 *   Level 1: 클러스터 (Cluster)
	 *     - 소켓 내부의 CPU 그룹을 나타냄 (예: big.LITTLE의 big 클러스터, LITTLE 클러스터)
	 *     - 같은 클러스터의 CPU들은 L2 캐시를 공유
	 *     - 클러스터별로 다른 성능 특성을 가질 수 있음
	 *
	 *   Level 0: 코어/스레드 (Core/Thread)
	 *     - 멀티스레딩 활성화: 코어 내 스레드 ID (같은 코어의 하드웨어 스레드)
	 *     - 멀티스레딩 비활성화: 코어 ID
	 *     - 각 코어는 독립적인 L1 캐시를 가짐
	 *
	 *   예시 구조:
	 *     Socket 0
	 *       ├─ Cluster 0 (big)
	 *       │   ├─ Core 0 (Thread 0, Thread 1)
	 *       │   └─ Core 1 (Thread 0, Thread 1)
	 *       └─ Cluster 1 (LITTLE)
	 *           ├─ Core 0 (Thread 0)
	 *           └─ Core 1 (Thread 0)
	 *
	 *   캐시 계층 구조:
	 *     - L1 캐시: 코어별 (가장 빠름, 가장 작음)
	 *     - L2 캐시: 클러스터별 (중간 속도, 중간 크기)
	 *     - L3 캐시: 소켓별 (느리지만 큼, 모든 코어가 공유)
	 *     - 메모리: 소켓별 (가장 느림, 가장 큼)
	 *
	 * 메모리 Locality와의 관계:
	 *   Affinity Level은 CPU의 물리적 계층 구조를 나타내며, 직접적으로 메모리 할당을
	 *   제어하는 것은 아닙니다. 하지만 같은 Affinity Level을 가진 CPU들은 보통:
	 *   - 같은 캐시 계층 구조를 공유 (Level 1: L2 캐시)
	 *   - 같은 메모리 노드에 가까울 수 있음 (Level 2: NUMA 노드)
	 *   커널의 NUMA 정책이나 스케줄러가 이 정보를 활용하여 메모리 locality를 최적화합니다.
	 *   예를 들어, 같은 클러스터의 CPU들은 같은 메모리 노드의 메모리를 사용하도록
	 *   스케줄링될 수 있습니다.
	 *
	 * 매크로 위치:
	 * - MPIDR_AFFINITY_LEVEL: arch/arm/include/asm/cputype.h:62
	 */
	u32 cpu = MPIDR_AFFINITY_LEVEL(mpidr, 0);

	/*
	 * 논리적 CPU 0번(부팅 CPU)의 물리적 ID 매핑 설정
	 *
	 * cpu_logical_map[0] = cpu 의미:
	 * - 커널 내부에서 논리적 CPU 0번으로 참조하는 CPU의 물리적 ID가 'cpu'임을 설정
	 *
	 * 예시: 물리적 CPU 2가 부팅 CPU인 경우
	 *       cpu_logical_map[0] = 2
	 *       즉, "논리적 CPU 0 = 물리적 CPU 2"
	 *
	 * 매크로/변수 위치:
	 * - cpu_logical_map: arch/arm/include/asm/smp_plat.h:73 (매크로)
	 * - __cpu_logical_map: arch/arm/kernel/setup.c:594 (배열 정의)
	 */
	cpu_logical_map(0) = cpu;

	/*
	 * 나머지 논리적 CPU들의 초기 매핑 설정
	 *
	 * 매핑 규칙:
	 * - 논리적 CPU i의 물리적 ID가 'cpu'와 같으면 → 물리적 ID 0으로 매핑
	 *   (이렇게 하면 물리적 CPU 0번이 다른 논리적 CPU 번호를 가질 수 있음)
	 * - 그 외의 경우 → 논리적 번호와 동일한 물리적 ID로 매핑
	 *
	 * 예시: 물리적 CPU 2가 부팅 CPU인 경우
	 *       cpu_logical_map[0] = 2  (이미 설정됨)
	 *       cpu_logical_map[1] = 1  (1 != 2이므로 1)
	 *       cpu_logical_map[2] = 0  (2 == 2이므로 0으로 매핑)
	 *       cpu_logical_map[3] = 3  (3 != 2이므로 3)
	 *
	 * 이 매핑은 초기값이며, 실제 시스템 토폴로지가 파악되면
	 * Device Tree나 ACPI 정보를 기반으로 재설정될 수 있습니다.
	 */
	for (i = 1; i < nr_cpu_ids; ++i)
		cpu_logical_map(i) = i == cpu ? 0 : i;

	/*
	 * 부팅 CPU의 Per-CPU 변수 오프셋을 0으로 초기화
	 *
	 * CPU Offset (CPU 오프셋)의 역할:
	 *   CPU offset은 SMP 시스템에서 각 CPU가 자신의 Per-CPU 변수에 접근하기 위해
	 *   사용하는 메모리 오프셋 값입니다.
	 *
	 *   Per-CPU 변수란:
	 *     - 각 CPU마다 독립적인 인스턴스를 가지는 변수
	 *     - CPU 간 동기화 없이 빠르게 접근 가능
	 *     - 예: DEFINE_PER_CPU(int, counter)는 각 CPU마다 별도의 counter를 가짐
	 *
	 *   동작 원리:
	 *     1. 메모리에 Per-CPU 변수들이 연속적으로 배치됨
	 *        [CPU0 영역][CPU1 영역][CPU2 영역]...
	 *     2. 각 CPU는 자신의 오프셋을 알고 있음
	 *        CPU0: offset = 0
	 *        CPU1: offset = CPU0 영역 크기
	 *        CPU2: offset = CPU0 영역 크기 + CPU1 영역 크기
	 *     3. Per-CPU 변수 접근 시: base_address + offset + 변수_오프셋
	 *
	 *   예시:
	 *     DEFINE_PER_CPU(int, my_var);
	 *     CPU0에서 접근: my_var = base + 0 + my_var_offset
	 *     CPU1에서 접근: my_var = base + cpu1_offset + my_var_offset
	 *
	 *   ARM 아키텍처에서의 구현:
	 *     - __my_cpu_offset는 각 CPU가 자신의 Per-CPU 변수에 접근하기 위해
	 *       사용하는 오프셋 값입니다.
	 *     - 이 값은 TPIDRPRW (Thread ID, Privileged Read/Write) 레지스터에 저장됩니다.
	 *     - TPIDRPRW는 ARMv6K 이상에서만 사용 가능하며, 각 CPU가 독립적으로
	 *       자신의 값을 유지할 수 있습니다.
	 *
	 * 초기화가 필요한 이유:
	 *   - 부팅 단계에서는 아직 Per-CPU 영역이 완전히 설정되지 않았을 수 있음
	 *   - 초기 부팅 중 Per-CPU 변수 접근 시 잘못된 오프셋으로 인한 hang 방지
	 *   - lockdep 같은 초기화 코드가 Per-CPU 변수에 접근할 수 있음
	 *
	 * set_my_cpu_offset(0)의 의미:
	 *   - 부팅 CPU의 오프셋을 0으로 설정
	 *   - Per-CPU 변수가 아직 설정되지 않은 상태에서도 안전하게 접근 가능
	 *   - 부팅 CPU는 항상 첫 번째 Per-CPU 영역을 사용하므로 offset = 0이 적절함
	 *
	 * 참고:
	 *   - 이후 smp_prepare_boot_cpu() 등에서 실제 Per-CPU 오프셋이 설정됩니다.
	 *   - 다른 CPU들은 부팅 시 각자의 오프셋이 설정됩니다.
	 *
	 * 함수 위치:
	 *   - set_my_cpu_offset(): arch/arm/include/asm/percpu.h:17 (CONFIG_SMP인 경우)
	 *                          arch/arm/include/asm/percpu.h:64 (비SMP인 경우, 빈 매크로)
	 */
	set_my_cpu_offset(0);

	/*
	 * 부팅 정보 출력
	 *
	 * 어떤 물리적 CPU에서 부팅되었는지 로그로 출력합니다.
	 * 이 정보는 디버깅과 시스템 분석에 유용합니다.
	 *
	 * 예시 출력: "Booting Linux on physical CPU 0x2"
	 *
	 * 매크로 위치:
	 * - pr_info(): include/linux/printk.h (로그 출력 매크로)
	 */
	pr_info("Booting Linux on physical CPU 0x%x\n", mpidr);
}

struct mpidr_hash mpidr_hash;
#ifdef CONFIG_SMP
/**
 * smp_build_mpidr_hash - Pre-compute shifts required at each affinity
 *			  level in order to build a linear index from an
 *			  MPIDR value. Resulting algorithm is a collision
 *			  free hash carried out through shifting and ORing
 */
static void __init smp_build_mpidr_hash(void)
{
	u32 i, affinity;
	u32 fs[3], bits[3], ls, mask = 0;
	/*
	 * Pre-scan the list of MPIDRS and filter out bits that do
	 * not contribute to affinity levels, ie they never toggle.
	 */
	for_each_possible_cpu(i)
		mask |= (cpu_logical_map(i) ^ cpu_logical_map(0));
	pr_debug("mask of set bits 0x%x\n", mask);
	/*
	 * Find and stash the last and first bit set at all affinity levels to
	 * check how many bits are required to represent them.
	 */
	for (i = 0; i < 3; i++) {
		affinity = MPIDR_AFFINITY_LEVEL(mask, i);
		/*
		 * Find the MSB bit and LSB bits position
		 * to determine how many bits are required
		 * to express the affinity level.
		 */
		ls = fls(affinity);
		fs[i] = affinity ? ffs(affinity) - 1 : 0;
		bits[i] = ls - fs[i];
	}
	/*
	 * An index can be created from the MPIDR by isolating the
	 * significant bits at each affinity level and by shifting
	 * them in order to compress the 24 bits values space to a
	 * compressed set of values. This is equivalent to hashing
	 * the MPIDR through shifting and ORing. It is a collision free
	 * hash though not minimal since some levels might contain a number
	 * of CPUs that is not an exact power of 2 and their bit
	 * representation might contain holes, eg MPIDR[7:0] = {0x2, 0x80}.
	 */
	mpidr_hash.shift_aff[0] = fs[0];
	mpidr_hash.shift_aff[1] = MPIDR_LEVEL_BITS + fs[1] - bits[0];
	mpidr_hash.shift_aff[2] = 2*MPIDR_LEVEL_BITS + fs[2] -
						(bits[1] + bits[0]);
	mpidr_hash.mask = mask;
	mpidr_hash.bits = bits[2] + bits[1] + bits[0];
	pr_debug("MPIDR hash: aff0[%u] aff1[%u] aff2[%u] mask[0x%x] bits[%u]\n",
				mpidr_hash.shift_aff[0],
				mpidr_hash.shift_aff[1],
				mpidr_hash.shift_aff[2],
				mpidr_hash.mask,
				mpidr_hash.bits);
	/*
	 * 4x is an arbitrary value used to warn on a hash table much bigger
	 * than expected on most systems.
	 */
	if (mpidr_hash_size() > 4 * num_possible_cpus())
		pr_warn("Large number of MPIDR hash buckets detected\n");
	sync_cache_w(&mpidr_hash);
}
#endif

/*
 * locate processor in the list of supported processor types.  The linker
 * builds this table for us from the entries in arch/arm/mm/proc-*.S
 */
struct proc_info_list *lookup_processor(u32 midr)
{
	struct proc_info_list *list = lookup_processor_type(midr);

	if (!list) {
		pr_err("CPU%u: configuration botched (ID %08x), CPU halted\n",
		       smp_processor_id(), midr);
		while (1)
		/* can't use cpu_relax() here as it may require MMU setup */;
	}

	return list;
}

static void __init setup_processor(void)
{
	unsigned int midr = read_cpuid_id();
	struct proc_info_list *list = lookup_processor(midr);

	cpu_name = list->cpu_name;
	__cpu_architecture = __get_cpu_architecture();

	init_proc_vtable(list->proc);
#ifdef MULTI_TLB
	cpu_tlb = *list->tlb;
#endif
#ifdef MULTI_USER
	cpu_user = *list->user;
#endif
#ifdef MULTI_CACHE
	cpu_cache = *list->cache;
#endif

	pr_info("CPU: %s [%08x] revision %d (ARMv%s), cr=%08lx\n",
		list->cpu_name, midr, midr & 15,
		proc_arch[cpu_architecture()], get_cr());

	snprintf(init_utsname()->machine, __NEW_UTS_LEN + 1, "%s%c",
		 list->arch_name, ENDIANNESS);
	snprintf(elf_platform, ELF_PLATFORM_SIZE, "%s%c",
		 list->elf_name, ENDIANNESS);
	elf_hwcap = list->elf_hwcap;

	cpuid_init_hwcaps();
	patch_aeabi_idiv();

#ifndef CONFIG_ARM_THUMB
	elf_hwcap &= ~(HWCAP_THUMB | HWCAP_IDIVT);
#endif
#ifdef CONFIG_MMU
	init_default_cache_policy(list->__cpu_mm_mmu_flags);
#endif
	erratum_a15_798181_init();

	elf_hwcap_fixup();

	cacheid_init();
	cpu_init();
}

void __init dump_machine_table(void)
{
	const struct machine_desc *p;

	early_print("Available machine support:\n\nID (hex)\tNAME\n");
	for_each_machine_desc(p)
		early_print("%08x\t%s\n", p->nr, p->name);

	early_print("\nPlease check your kernel config and/or bootloader.\n");

	while (true)
		/* can't use cpu_relax() here as it may require MMU setup */;
}

int __init arm_add_memory(u64 start, u64 size)
{
	u64 aligned_start;

	/*
	 * Ensure that start/size are aligned to a page boundary.
	 * Size is rounded down, start is rounded up.
	 */
	aligned_start = PAGE_ALIGN(start);
	if (aligned_start > start + size)
		size = 0;
	else
		size -= aligned_start - start;

#ifndef CONFIG_PHYS_ADDR_T_64BIT
	if (aligned_start > ULONG_MAX) {
		pr_crit("Ignoring memory at 0x%08llx outside 32-bit physical address space\n",
			start);
		return -EINVAL;
	}

	if (aligned_start + size > ULONG_MAX) {
		pr_crit("Truncating memory at 0x%08llx to fit in 32-bit physical address space\n",
			(long long)start);
		/*
		 * To ensure bank->start + bank->size is representable in
		 * 32 bits, we use ULONG_MAX as the upper limit rather than 4GB.
		 * This means we lose a page after masking.
		 */
		size = ULONG_MAX - aligned_start;
	}
#endif

	if (aligned_start < PHYS_OFFSET) {
		if (aligned_start + size <= PHYS_OFFSET) {
			pr_info("Ignoring memory below PHYS_OFFSET: 0x%08llx-0x%08llx\n",
				aligned_start, aligned_start + size);
			return -EINVAL;
		}

		pr_info("Ignoring memory below PHYS_OFFSET: 0x%08llx-0x%08llx\n",
			aligned_start, (u64)PHYS_OFFSET);

		size -= PHYS_OFFSET - aligned_start;
		aligned_start = PHYS_OFFSET;
	}

	start = aligned_start;
	size = size & ~(phys_addr_t)(PAGE_SIZE - 1);

	/*
	 * Check whether this memory region has non-zero size or
	 * invalid node number.
	 */
	if (size == 0)
		return -EINVAL;

	memblock_add(start, size);
	return 0;
}

/*
 * Pick out the memory size.  We look for mem=size@start,
 * where start and size are "size[KkMm]"
 */

static int __init early_mem(char *p)
{
	static int usermem __initdata = 0;
	u64 size;
	u64 start;
	char *endp;

	/*
	 * If the user specifies memory size, we
	 * blow away any automatically generated
	 * size.
	 */
	if (usermem == 0) {
		usermem = 1;
		memblock_remove(memblock_start_of_DRAM(),
			memblock_end_of_DRAM() - memblock_start_of_DRAM());
	}

	start = PHYS_OFFSET;
	size  = memparse(p, &endp);
	if (*endp == '@')
		start = memparse(endp + 1, NULL);

	arm_add_memory(start, size);

	return 0;
}
early_param("mem", early_mem);

static void __init request_standard_resources(const struct machine_desc *mdesc)
{
	phys_addr_t start, end, res_end;
	struct resource *res;
	u64 i;

	kernel_code.start   = virt_to_phys(_text);
	kernel_code.end     = virt_to_phys(__init_begin - 1);
	kernel_data.start   = virt_to_phys(_sdata);
	kernel_data.end     = virt_to_phys(_end - 1);

	for_each_mem_range(i, &start, &end) {
		unsigned long boot_alias_start;

		/*
		 * In memblock, end points to the first byte after the
		 * range while in resourses, end points to the last byte in
		 * the range.
		 */
		res_end = end - 1;

		/*
		 * Some systems have a special memory alias which is only
		 * used for booting.  We need to advertise this region to
		 * kexec-tools so they know where bootable RAM is located.
		 */
		boot_alias_start = phys_to_idmap(start);
		if (arm_has_idmap_alias() && boot_alias_start != IDMAP_INVALID_ADDR) {
			res = memblock_alloc_or_panic(sizeof(*res), SMP_CACHE_BYTES);
			res->name = "System RAM (boot alias)";
			res->start = boot_alias_start;
			res->end = phys_to_idmap(res_end);
			res->flags = IORESOURCE_MEM | IORESOURCE_BUSY;
			request_resource(&iomem_resource, res);
		}

		res = memblock_alloc_or_panic(sizeof(*res), SMP_CACHE_BYTES);
		res->name  = "System RAM";
		res->start = start;
		res->end = res_end;
		res->flags = IORESOURCE_SYSTEM_RAM | IORESOURCE_BUSY;

		request_resource(&iomem_resource, res);

		if (kernel_code.start >= res->start &&
		    kernel_code.end <= res->end)
			request_resource(res, &kernel_code);
		if (kernel_data.start >= res->start &&
		    kernel_data.end <= res->end)
			request_resource(res, &kernel_data);
	}

	if (mdesc->video_start) {
		video_ram.start = mdesc->video_start;
		video_ram.end   = mdesc->video_end;
		request_resource(&iomem_resource, &video_ram);
	}

	/*
	 * Some machines don't have the possibility of ever
	 * possessing lp0, lp1 or lp2
	 */
	if (mdesc->reserve_lp0)
		request_resource(&ioport_resource, &lp0);
	if (mdesc->reserve_lp1)
		request_resource(&ioport_resource, &lp1);
	if (mdesc->reserve_lp2)
		request_resource(&ioport_resource, &lp2);
}

#if defined(CONFIG_VGA_CONSOLE)
struct screen_info vgacon_screen_info = {
 .orig_video_lines	= 30,
 .orig_video_cols	= 80,
 .orig_video_mode	= 0,
 .orig_video_ega_bx	= 0,
 .orig_video_isVGA	= 1,
 .orig_video_points	= 8
};
#endif

static int __init customize_machine(void)
{
	/*
	 * customizes platform devices, or adds new ones
	 * On DT based machines, we fall back to populating the
	 * machine from the device tree, if no callback is provided,
	 * otherwise we would always need an init_machine callback.
	 */
	if (machine_desc->init_machine)
		machine_desc->init_machine();

	return 0;
}
arch_initcall(customize_machine);

static int __init init_machine_late(void)
{
	struct device_node *root;
	int ret;

	if (machine_desc->init_late)
		machine_desc->init_late();

	root = of_find_node_by_path("/");
	if (root) {
		ret = of_property_read_string(root, "serial-number",
					      &system_serial);
		if (ret)
			system_serial = NULL;
	}

	if (!system_serial)
		system_serial = kasprintf(GFP_KERNEL, "%08x%08x",
					  system_serial_high,
					  system_serial_low);

	return 0;
}
late_initcall(init_machine_late);

#ifdef CONFIG_CRASH_RESERVE
/*
 * The crash region must be aligned to 128MB to avoid
 * zImage relocating below the reserved region.
 */
#define CRASH_ALIGN	(128 << 20)

static inline unsigned long long get_total_mem(void)
{
	unsigned long total;

	total = max_low_pfn - min_low_pfn;
	return total << PAGE_SHIFT;
}

/**
 * reserve_crashkernel() - reserves memory are for crash kernel
 *
 * This function reserves memory area given in "crashkernel=" kernel command
 * line parameter. The memory reserved is used by a dump capture kernel when
 * primary kernel is crashing.
 */
static void __init reserve_crashkernel(void)
{
	unsigned long long crash_size, crash_base;
	unsigned long long total_mem;
	int ret;

	total_mem = get_total_mem();
	ret = parse_crashkernel(boot_command_line, total_mem,
				&crash_size, &crash_base,
				NULL, NULL, NULL);
	/* invalid value specified or crashkernel=0 */
	if (ret || !crash_size)
		return;

	if (crash_base <= 0) {
		unsigned long long crash_max = idmap_to_phys((u32)~0);
		unsigned long long lowmem_max = __pa(high_memory - 1) + 1;
		if (crash_max > lowmem_max)
			crash_max = lowmem_max;

		crash_base = memblock_phys_alloc_range(crash_size, CRASH_ALIGN,
						       CRASH_ALIGN, crash_max);
		if (!crash_base) {
			pr_err("crashkernel reservation failed - No suitable area found.\n");
			return;
		}
	} else {
		unsigned long long crash_max = crash_base + crash_size;
		unsigned long long start;

		start = memblock_phys_alloc_range(crash_size, SECTION_SIZE,
						  crash_base, crash_max);
		if (!start) {
			pr_err("crashkernel reservation failed - memory is in use.\n");
			return;
		}
	}

	pr_info("Reserving %ldMB of memory at %ldMB for crashkernel (System RAM: %ldMB)\n",
		(unsigned long)(crash_size >> 20),
		(unsigned long)(crash_base >> 20),
		(unsigned long)(total_mem >> 20));

	/* The crashk resource must always be located in normal mem */
	crashk_res.start = crash_base;
	crashk_res.end = crash_base + crash_size - 1;
	insert_resource(&iomem_resource, &crashk_res);

	if (arm_has_idmap_alias()) {
		/*
		 * If we have a special RAM alias for use at boot, we
		 * need to advertise to kexec tools where the alias is.
		 */
		static struct resource crashk_boot_res = {
			.name = "Crash kernel (boot alias)",
			.flags = IORESOURCE_BUSY | IORESOURCE_MEM,
		};

		crashk_boot_res.start = phys_to_idmap(crash_base);
		crashk_boot_res.end = crashk_boot_res.start + crash_size - 1;
		insert_resource(&iomem_resource, &crashk_boot_res);
	}
}
#else
static inline void reserve_crashkernel(void) {}
#endif /* CONFIG_CRASH_RESERVE*/

void __init hyp_mode_check(void)
{
#ifdef CONFIG_ARM_VIRT_EXT
	sync_boot_mode();

	if (is_hyp_mode_available()) {
		pr_info("CPU: All CPU(s) started in HYP mode.\n");
		pr_info("CPU: Virtualization extensions available.\n");
	} else if (is_hyp_mode_mismatched()) {
		pr_warn("CPU: WARNING: CPU(s) started in wrong/inconsistent modes (primary CPU mode 0x%x)\n",
			__boot_cpu_mode & MODE_MASK);
		pr_warn("CPU: This may indicate a broken bootloader or firmware.\n");
	} else
		pr_info("CPU: All CPU(s) started in SVC mode.\n");
#endif
}

static void (*__arm_pm_restart)(enum reboot_mode reboot_mode, const char *cmd);

static int arm_restart(struct notifier_block *nb, unsigned long action,
		       void *data)
{
	__arm_pm_restart(action, data);
	return NOTIFY_DONE;
}

static struct notifier_block arm_restart_nb = {
	.notifier_call = arm_restart,
	.priority = 128,
};

void __init setup_arch(char **cmdline_p)
{
	const struct machine_desc *mdesc = NULL;
	void *atags_vaddr = NULL;

	if (__atags_pointer)
		atags_vaddr = FDT_VIRT_BASE(__atags_pointer);

	setup_processor();
	if (atags_vaddr) {
		mdesc = setup_machine_fdt(atags_vaddr);
		if (mdesc)
			memblock_reserve(__atags_pointer,
					 fdt_totalsize(atags_vaddr));
	}
	if (!mdesc)
		mdesc = setup_machine_tags(atags_vaddr, __machine_arch_type);
	if (!mdesc) {
		early_print("\nError: invalid dtb and unrecognized/unsupported machine ID\n");
		early_print("  r1=0x%08x, r2=0x%08x\n", __machine_arch_type,
			    __atags_pointer);
		if (__atags_pointer)
			early_print("  r2[]=%*ph\n", 16, atags_vaddr);
		dump_machine_table();
	}

	machine_desc = mdesc;
	machine_name = mdesc->name;
	dump_stack_set_arch_desc("%s", mdesc->name);

	if (mdesc->reboot_mode != REBOOT_HARD)
		reboot_mode = mdesc->reboot_mode;

	setup_initial_init_mm(_text, _etext, _edata, _end);

	/* populate cmd_line too for later use, preserving boot_command_line */
	strscpy(cmd_line, boot_command_line, COMMAND_LINE_SIZE);
	*cmdline_p = cmd_line;

	early_fixmap_init();
	early_ioremap_init();

	parse_early_param();

#ifdef CONFIG_MMU
	early_mm_init(mdesc);
#endif
	setup_dma_zone(mdesc);
	xen_early_init();
	arm_efi_init();
	/*
	 * Make sure the calculation for lowmem/highmem is set appropriately
	 * before reserving/allocating any memory
	 */
	adjust_lowmem_bounds();
	arm_memblock_init(mdesc);
	/* Memory may have been removed so recalculate the bounds. */
	adjust_lowmem_bounds();

	early_ioremap_reset();

	paging_init(mdesc);
	kasan_init();
	request_standard_resources(mdesc);

	if (mdesc->restart) {
		__arm_pm_restart = mdesc->restart;
		register_restart_handler(&arm_restart_nb);
	}

	unflatten_device_tree();

	arm_dt_init_cpu_maps();
	psci_dt_init();
#ifdef CONFIG_SMP
	if (is_smp()) {
		if (!mdesc->smp_init || !mdesc->smp_init()) {
			if (psci_smp_available())
				smp_set_ops(&psci_smp_ops);
			else if (mdesc->smp)
				smp_set_ops(mdesc->smp);
		}
		smp_init_cpus();
		smp_build_mpidr_hash();
	}
#endif

	if (!is_smp())
		hyp_mode_check();

	reserve_crashkernel();

#ifdef CONFIG_VT
#if defined(CONFIG_VGA_CONSOLE)
	vgacon_register_screen(&vgacon_screen_info);
#endif
#endif

	if (mdesc->init_early)
		mdesc->init_early();
}

bool arch_cpu_is_hotpluggable(int num)
{
	return platform_can_hotplug_cpu(num);
}

#ifdef CONFIG_HAVE_PROC_CPU
static int __init proc_cpu_init(void)
{
	struct proc_dir_entry *res;

	res = proc_mkdir("cpu", NULL);
	if (!res)
		return -ENOMEM;
	return 0;
}
fs_initcall(proc_cpu_init);
#endif

static const char *hwcap_str[] = {
	"swp",
	"half",
	"thumb",
	"26bit",
	"fastmult",
	"fpa",
	"vfp",
	"edsp",
	"java",
	"iwmmxt",
	"crunch",
	"thumbee",
	"neon",
	"vfpv3",
	"vfpv3d16",
	"tls",
	"vfpv4",
	"idiva",
	"idivt",
	"vfpd32",
	"lpae",
	"evtstrm",
	"fphp",
	"asimdhp",
	"asimddp",
	"asimdfhm",
	"asimdbf16",
	"i8mm",
	NULL
};

static const char *hwcap2_str[] = {
	"aes",
	"pmull",
	"sha1",
	"sha2",
	"crc32",
	"sb",
	"ssbs",
	NULL
};

static int c_show(struct seq_file *m, void *v)
{
	int i, j;
	u32 cpuid;

	for_each_online_cpu(i) {
		/*
		 * glibc reads /proc/cpuinfo to determine the number of
		 * online processors, looking for lines beginning with
		 * "processor".  Give glibc what it expects.
		 */
		seq_printf(m, "processor\t: %d\n", i);
		cpuid = is_smp() ? per_cpu(cpu_data, i).cpuid : read_cpuid_id();
		seq_printf(m, "model name\t: %s rev %d (%s)\n",
			   cpu_name, cpuid & 15, elf_platform);

#if defined(CONFIG_SMP)
		seq_printf(m, "BogoMIPS\t: %lu.%02lu\n",
			   per_cpu(cpu_data, i).loops_per_jiffy / (500000UL/HZ),
			   (per_cpu(cpu_data, i).loops_per_jiffy / (5000UL/HZ)) % 100);
#else
		seq_printf(m, "BogoMIPS\t: %lu.%02lu\n",
			   loops_per_jiffy / (500000/HZ),
			   (loops_per_jiffy / (5000/HZ)) % 100);
#endif
		/* dump out the processor features */
		seq_puts(m, "Features\t: ");

		for (j = 0; hwcap_str[j]; j++)
			if (elf_hwcap & (1 << j))
				seq_printf(m, "%s ", hwcap_str[j]);

		for (j = 0; hwcap2_str[j]; j++)
			if (elf_hwcap2 & (1 << j))
				seq_printf(m, "%s ", hwcap2_str[j]);

		seq_printf(m, "\nCPU implementer\t: 0x%02x\n", cpuid >> 24);
		seq_printf(m, "CPU architecture: %s\n",
			   proc_arch[cpu_architecture()]);

		if ((cpuid & 0x0008f000) == 0x00000000) {
			/* pre-ARM7 */
			seq_printf(m, "CPU part\t: %07x\n", cpuid >> 4);
		} else {
			if ((cpuid & 0x0008f000) == 0x00007000) {
				/* ARM7 */
				seq_printf(m, "CPU variant\t: 0x%02x\n",
					   (cpuid >> 16) & 127);
			} else {
				/* post-ARM7 */
				seq_printf(m, "CPU variant\t: 0x%x\n",
					   (cpuid >> 20) & 15);
			}
			seq_printf(m, "CPU part\t: 0x%03x\n",
				   (cpuid >> 4) & 0xfff);
		}
		seq_printf(m, "CPU revision\t: %d\n\n", cpuid & 15);
	}

	seq_printf(m, "Hardware\t: %s\n", machine_name);
	seq_printf(m, "Revision\t: %04x\n", system_rev);
	seq_printf(m, "Serial\t\t: %s\n", system_serial);

	return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	return *pos < 1 ? (void *)1 : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static void c_stop(struct seq_file *m, void *v)
{
}

const struct seq_operations cpuinfo_op = {
	.start	= c_start,
	.next	= c_next,
	.stop	= c_stop,
	.show	= c_show
};
