/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_ARM_CPUTYPE_H
#define __ASM_ARM_CPUTYPE_H

/* CP15 레지스터 인덱스 정의
 * CP15의 c0 레지스터에서 읽을 수 있는 다양한 CPU 정보 레지스터들의 인덱스
 * MRC p15, 0, <Rd>, c0, c0, <index> 명령어에서 사용됨
 *
 * 사용 방법:
 *   - read_cpuid(CPUID_MPIDR): MPIDR 레지스터 읽기
 *   - read_cpuid(CPUID_ID): CPU ID 레지스터 읽기
 *   - 각 상수는 MRC 명령어의 마지막 인자로 전달됨
 */
#define CPUID_ID	0	/* CPU ID 레지스터 (MIDR - Main ID Register) */
#define CPUID_CACHETYPE	1	/* 캐시 타입 레지스터 */
#define CPUID_TCM	2	/* TCM (Tightly Coupled Memory) 레지스터 */
#define CPUID_TLBTYPE	3	/* TLB 타입 레지스터 */
#define CPUID_MPUIR	4	/* MPU (Memory Protection Unit) ID 레지스터 */
#define CPUID_MPIDR	5	/* MPIDR (Multiprocessor Affinity Register) 레지스터
			    * 값: 5
			    * 용도: read_cpuid(CPUID_MPIDR) 호출 시 사용
			    * 의미: CP15의 c0 레지스터에서 MPIDR을 읽을 때의 인덱스
			    * 예시: read_cpuid(CPUID_MPIDR) -> MRC p15, 0, <Rd>, c0, c0, 5
			    */
#define CPUID_REVIDR	6	/* Revision ID 레지스터 */

#ifdef CONFIG_CPU_V7M
#define CPUID_EXT_PFR0	0x40
#define CPUID_EXT_PFR1	0x44
#define CPUID_EXT_DFR0	0x48
#define CPUID_EXT_AFR0	0x4c
#define CPUID_EXT_MMFR0	0x50
#define CPUID_EXT_MMFR1	0x54
#define CPUID_EXT_MMFR2	0x58
#define CPUID_EXT_MMFR3	0x5c
#define CPUID_EXT_ISAR0	0x60
#define CPUID_EXT_ISAR1	0x64
#define CPUID_EXT_ISAR2	0x68
#define CPUID_EXT_ISAR3	0x6c
#define CPUID_EXT_ISAR4	0x70
#define CPUID_EXT_ISAR5	0x74
#define CPUID_EXT_ISAR6	0x7c
#define CPUID_EXT_PFR2	0x90
#else
#define CPUID_EXT_PFR0	"c1, 0"
#define CPUID_EXT_PFR1	"c1, 1"
#define CPUID_EXT_DFR0	"c1, 2"
#define CPUID_EXT_AFR0	"c1, 3"
#define CPUID_EXT_MMFR0	"c1, 4"
#define CPUID_EXT_MMFR1	"c1, 5"
#define CPUID_EXT_MMFR2	"c1, 6"
#define CPUID_EXT_MMFR3	"c1, 7"
#define CPUID_EXT_ISAR0	"c2, 0"
#define CPUID_EXT_ISAR1	"c2, 1"
#define CPUID_EXT_ISAR2	"c2, 2"
#define CPUID_EXT_ISAR3	"c2, 3"
#define CPUID_EXT_ISAR4	"c2, 4"
#define CPUID_EXT_ISAR5	"c2, 5"
#define CPUID_EXT_ISAR6	"c2, 7"
#define CPUID_EXT_PFR2	"c3, 4"
#endif

#define MPIDR_SMP_BITMASK (0x3 << 30)
#define MPIDR_SMP_VALUE (0x2 << 30)

#define MPIDR_MT_BITMASK (0x1 << 24)

#define MPIDR_HWID_BITMASK 0xFFFFFF

#define MPIDR_INVALID (~MPIDR_HWID_BITMASK)

/* MPIDR 어피니티 레벨 관련 상수
 * MPIDR 레지스터는 여러 어피니티 레벨로 구성되어 있으며,
 * 각 레벨은 8비트(256개 값)를 사용합니다.
 */
#define MPIDR_LEVEL_BITS 8		/* 각 어피니티 레벨의 비트 수 */
#define MPIDR_LEVEL_MASK ((1 << MPIDR_LEVEL_BITS) - 1)	/* 8비트 마스크 (0xFF) */
#define MPIDR_LEVEL_SHIFT(level) (MPIDR_LEVEL_BITS * level)	/* 레벨별 시프트 값 */

/**
 * MPIDR_AFFINITY_LEVEL - MPIDR 레지스터에서 특정 어피니티 레벨 값 추출
 *
 * MPIDR 레지스터는 계층적 어피니티 구조를 가지고 있으며,
 * 각 레벨은 8비트씩 할당되어 있습니다.
 *
 * @mpidr: MPIDR 레지스터 값
 * @level: 추출할 어피니티 레벨 (0, 1, 2)
 *
 * 어피니티 레벨 구조:
 *   - Level 0 (비트 7:0):   CPU 코어 내 스레드 ID 또는 코어 ID
 *   - Level 1 (비트 15:8):  클러스터 ID
 *   - Level 2 (비트 23:16): 소켓/패키지 ID
 *
 * 동작:
 *   1. mpidr을 오른쪽으로 (8 * level) 비트만큼 시프트
 *   2. 하위 8비트를 마스킹하여 추출
 *
 * 예시:
 *   mpidr = 0x00010203 (Level2=1, Level1=2, Level0=3)
 *   MPIDR_AFFINITY_LEVEL(mpidr, 0) = 0x03 (Level 0)
 *   MPIDR_AFFINITY_LEVEL(mpidr, 1) = 0x02 (Level 1)
 *   MPIDR_AFFINITY_LEVEL(mpidr, 2) = 0x01 (Level 2)
 *
 * 사용 예시:
 *   - CPU 토폴로지 파싱: 각 레벨의 ID 추출
 *   - 논리-물리 CPU 매핑: arch/arm/kernel/setup.c에서 사용
 */
#define MPIDR_AFFINITY_LEVEL(mpidr, level) \
	((mpidr >> (MPIDR_LEVEL_BITS * level)) & MPIDR_LEVEL_MASK)

#define ARM_CPU_IMP_ARM			0x41
#define ARM_CPU_IMP_BRCM		0x42
#define ARM_CPU_IMP_DEC			0x44
#define ARM_CPU_IMP_INTEL		0x69

/* ARM implemented processors */
#define ARM_CPU_PART_ARM1136		0x4100b360
#define ARM_CPU_PART_ARM1156		0x4100b560
#define ARM_CPU_PART_ARM1176		0x4100b760
#define ARM_CPU_PART_ARM11MPCORE	0x4100b020
#define ARM_CPU_PART_CORTEX_A8		0x4100c080
#define ARM_CPU_PART_CORTEX_A9		0x4100c090
#define ARM_CPU_PART_CORTEX_A5		0x4100c050
#define ARM_CPU_PART_CORTEX_A7		0x4100c070
#define ARM_CPU_PART_CORTEX_A12		0x4100c0d0
#define ARM_CPU_PART_CORTEX_A17		0x4100c0e0
#define ARM_CPU_PART_CORTEX_A15		0x4100c0f0
#define ARM_CPU_PART_CORTEX_A53		0x4100d030
#define ARM_CPU_PART_CORTEX_A57		0x4100d070
#define ARM_CPU_PART_CORTEX_A72		0x4100d080
#define ARM_CPU_PART_CORTEX_A73		0x4100d090
#define ARM_CPU_PART_CORTEX_A75		0x4100d0a0
#define ARM_CPU_PART_MASK		0xff00fff0

/* Broadcom implemented processors */
#define ARM_CPU_PART_BRAHMA_B15		0x420000f0
#define ARM_CPU_PART_BRAHMA_B53		0x42001000

/* DEC implemented cores */
#define ARM_CPU_PART_SA1100		0x4400a110

/* Intel implemented cores */
#define ARM_CPU_PART_SA1110		0x6900b110
#define ARM_CPU_REV_SA1110_A0		0
#define ARM_CPU_REV_SA1110_B0		4
#define ARM_CPU_REV_SA1110_B1		5
#define ARM_CPU_REV_SA1110_B2		6
#define ARM_CPU_REV_SA1110_B4		8

#define ARM_CPU_XSCALE_ARCH_MASK	0xe000
#define ARM_CPU_XSCALE_ARCH_V1		0x2000
#define ARM_CPU_XSCALE_ARCH_V2		0x4000
#define ARM_CPU_XSCALE_ARCH_V3		0x6000

/* Qualcomm implemented cores */
#define ARM_CPU_PART_SCORPION		0x510002d0

#ifndef __ASSEMBLY__

#include <linux/stringify.h>
#include <linux/kernel.h>

extern unsigned int processor_id;
struct proc_info_list *lookup_processor(u32 midr);

#ifdef CONFIG_CPU_CP15
/**
 * read_cpuid - CP15의 CPU 정보 레지스터 읽기 매크로
 *
 * CP15 (Coprocessor 15)의 c0 레지스터에서 CPU 정보를 읽어 반환하는 매크로입니다.
 *
 * @reg: 읽을 레지스터의 인덱스 (CPUID_ID, CPUID_MPIDR 등)
 *
 * 동작:
 *   - MRC (Move to Register from Coprocessor) 어셈블리 명령어 사용
 *   - 명령어 형식: "mrc p15, 0, <Rd>, c0, c0, <reg>"
 *     * p15: Coprocessor 15 (시스템 제어 코프로세서)
 *     * c0, c0: CP15의 레지스터 번호
 *     * reg: 읽을 레지스터의 인덱스 (CPUID_* 상수)
 *
 * 반환값:
 *   - 읽은 레지스터의 32비트 값
 *
 * 사용 예시:
 *   - read_cpuid(CPUID_MPIDR): MPIDR 레지스터 읽기
 *   - read_cpuid(CPUID_ID): CPU ID 레지스터 읽기
 *
 * 참고:
 *   - CONFIG_CPU_CP15가 활성화된 경우에만 사용 가능
 *   - 인라인 어셈블리로 구현되어 컴파일 타임에 최적화됨
 */
#define read_cpuid(reg)							\
	({								\
		unsigned int __val;					\
		asm("mrc	p15, 0, %0, c0, c0, " __stringify(reg)	\
		    : "=r" (__val)					\
		    :							\
		    : "cc");						\
		__val;							\
	})

/*
 * The memory clobber prevents gcc 4.5 from reordering the mrc before
 * any is_smp() tests, which can cause undefined instruction aborts on
 * ARM1136 r0 due to the missing extended CP15 registers.
 */
#define read_cpuid_ext(ext_reg)						\
	({								\
		unsigned int __val;					\
		asm("mrc	p15, 0, %0, c0, " ext_reg		\
		    : "=r" (__val)					\
		    :							\
		    : "memory");					\
		__val;							\
	})

#elif defined(CONFIG_CPU_V7M)

#include <asm/io.h>
#include <asm/v7m.h>

/* V7M 아키텍처용 fallback 구현
 * V7M (ARMv7-M, Cortex-M 시리즈)는 CP15가 없으므로
 * 이 함수 호출 시 경고를 출력하고 0을 반환합니다.
 */
#define read_cpuid(reg)							\
	({								\
		WARN_ON_ONCE(1);					\
		0;							\
	})

static inline unsigned int __attribute_const__ read_cpuid_ext(unsigned offset)
{
	return readl(BASEADDR_V7M_SCB + offset);
}

#else /* ifdef CONFIG_CPU_CP15 / elif defined (CONFIG_CPU_V7M) */

/*
 * CP15가 없는 시스템용 fallback 구현
 *
 * 이 구현은 CP15 (Coprocessor 15)가 없는 오래된 ARM 프로세서나
 * 특수한 아키텍처에서 사용됩니다.
 *
 * 동작:
 *   - WARN_ON_ONCE(1): 경고 메시지 출력 (한 번만)
 *   - 0 반환: 안전한 기본값
 *
 * 참고:
 *   - CP15가 없는 시스템에서 이 함수가 호출되면 경고가 출력됩니다
 *   - 대부분의 현대 ARM 프로세서는 CONFIG_CPU_CP15가 활성화되어
 *     실제 MRC 명령어를 사용하는 구현(150번 줄)이 사용됩니다
 *   - 이 fallback은 호환성을 위한 것이며, 실제로는 거의 사용되지 않습니다
 */
#define read_cpuid(reg)							\
	({								\
		WARN_ON_ONCE(1);					\
		0;							\
	})

#define read_cpuid_ext(reg) read_cpuid(reg)

#endif /* ifdef CONFIG_CPU_CP15 / else */

#ifdef CONFIG_CPU_CP15
/*
 * The CPU ID never changes at run time, so we might as well tell the
 * compiler that it's constant.  Use this function to read the CPU ID
 * rather than directly reading processor_id or read_cpuid() directly.
 */
static inline unsigned int __attribute_const__ read_cpuid_id(void)
{
	return read_cpuid(CPUID_ID);
}

static inline unsigned int __attribute_const__ read_cpuid_cachetype(void)
{
	return read_cpuid(CPUID_CACHETYPE);
}

static inline unsigned int __attribute_const__ read_cpuid_mputype(void)
{
	return read_cpuid(CPUID_MPUIR);
}

#elif defined(CONFIG_CPU_V7M)

static inline unsigned int __attribute_const__ read_cpuid_id(void)
{
	return readl(BASEADDR_V7M_SCB + V7M_SCB_CPUID);
}

static inline unsigned int __attribute_const__ read_cpuid_cachetype(void)
{
	return readl(BASEADDR_V7M_SCB + V7M_SCB_CTR);
}

static inline unsigned int __attribute_const__ read_cpuid_mputype(void)
{
	return readl(BASEADDR_V7M_SCB + MPU_TYPE);
}

#else /* ifdef CONFIG_CPU_CP15 / elif defined(CONFIG_CPU_V7M) */

static inline unsigned int __attribute_const__ read_cpuid_id(void)
{
	return processor_id;
}

#endif /* ifdef CONFIG_CPU_CP15 / else */

static inline unsigned int __attribute_const__ read_cpuid_implementor(void)
{
	return (read_cpuid_id() & 0xFF000000) >> 24;
}

static inline unsigned int __attribute_const__ read_cpuid_revision(void)
{
	return read_cpuid_id() & 0x0000000f;
}

/*
 * The CPU part number is meaningless without referring to the CPU
 * implementer: implementers are free to define their own part numbers
 * which are permitted to clash with other implementer part numbers.
 */
static inline unsigned int __attribute_const__ read_cpuid_part(void)
{
	return read_cpuid_id() & ARM_CPU_PART_MASK;
}

static inline unsigned int __attribute_const__ __deprecated read_cpuid_part_number(void)
{
	return read_cpuid_id() & 0xFFF0;
}

static inline unsigned int __attribute_const__ xscale_cpu_arch_version(void)
{
	return read_cpuid_id() & ARM_CPU_XSCALE_ARCH_MASK;
}

static inline unsigned int __attribute_const__ read_cpuid_tcmstatus(void)
{
	return read_cpuid(CPUID_TCM);
}

/**
 * read_cpuid_mpidr - MPIDR 레지스터 읽기
 *
 * CP15의 MPIDR (Multiprocessor Affinity Register) 레지스터 값을 읽어 반환합니다.
 *
 * 반환값:
 *   - MPIDR 레지스터의 전체 32비트 값
 *   - 각 CPU 코어마다 고유한 값 (하드웨어에서 부팅 시 자동 설정)
 *   - 어피니티 레벨 정보 포함:
 *     * 비트 7:0:   Affinity Level 0 (스레드/코어 ID)
 *     * 비트 15:8:  Affinity Level 1 (클러스터 ID)
 *     * 비트 23:16: Affinity Level 2 (소켓/패키지 ID)
 *     * 비트 24:    MT (Multithreading) 비트
 *     * 비트 31:30: SMP 모드 비트
 *
 * 사용 예시:
 *   - CPU 식별: 각 CPU가 자신의 고유 ID를 읽어서 구분
 *   - 토폴로지 파싱: 어피니티 레벨로 CPU 계층 구조 파악
 *   - 논리-물리 CPU 매핑: smp_setup_processor_id()에서 사용
 *
 * 참고:
 *   - 읽기 전용 레지스터 (하드웨어가 자동으로 설정)
 *   - 내부적으로 MRC p15, 0, <Rd>, c0, c0, 5 어셈블리 명령어 사용
 *   - SMP 시스템에서만 의미가 있으며, UP 시스템에서는 0 반환 가능
 *   - 실제 하드웨어 ID만 필요하면 MPIDR_HWID_BITMASK로 마스킹 필요
 *
 * 동작 과정:
 *   1. read_cpuid(CPUID_MPIDR) 호출
 *   2. CPUID_MPIDR은 14번 줄에 정의된 상수로 값은 5
 *   3. read_cpuid 매크로(150번 줄)가 확장되어 인라인 어셈블리로 변환:
 *      asm("mrc p15, 0, %0, c0, c0, 5" : "=r" (__val) : : "cc")
 *   4. MRC 명령어 실행:
 *      - mrc: Move to Register from Coprocessor
 *      - p15: Coprocessor 15 (시스템 제어 코프로세서)
 *      - c0, c0: CP15의 레지스터 번호
 *      - 5: 읽을 레지스터 인덱스 (CPUID_MPIDR)
 *   5. MPIDR 레지스터의 32비트 값이 반환됨
 */
/**
 * __attribute_const__ - 컴파일러 최적화 힌트 속성
 *
 * __attribute_const__는 GCC의 __attribute__((__const__))를 래핑한 매크로로,
 * 함수가 인자에만 의존하고 전역 변수나 포인터를 통한 메모리 접근을 하지 않는다는 것을
 * 컴파일러에 알려주는 최적화 힌트입니다.
 *
 * 역할:
 *   1. 순수 함수 표시:
 *      - 함수가 인자 값에만 의존하여 결과를 결정
 *      - 같은 인자로 호출하면 항상 같은 결과 반환
 *      - 전역 변수, 정적 변수, 포인터를 통한 메모리 읽기 없음
 *
 *   2. 컴파일러 최적화:
 *      - 공통 서브표현식 제거 (CSE: Common Subexpression Elimination)
 *        예: 같은 인자로 여러 번 호출 시 한 번만 계산하고 재사용
 *      - 루프 불변 코드 이동 (LICM: Loop Invariant Code Motion)
 *        예: 루프 내에서 같은 인자로 호출 시 루프 밖으로 이동
 *      - 데드 코드 제거 (Dead Code Elimination)
 *        예: 사용되지 않는 호출 제거
 *
 *   3. __attribute__((pure))와의 차이:
 *      - pure: 전역 변수나 포인터를 통한 메모리 읽기는 가능하지만 쓰기는 없음
 *      - const: 전역 변수나 포인터를 통한 메모리 읽기도 없음 (더 엄격)
 *
 * 사용 예시:
 *   // 최적화 전:
 *   for (int i = 0; i < 1000; i++) {
 *       unsigned int mpidr = read_cpuid_mpidr();  // 매번 호출
 *       // ... mpidr 사용
 *   }
 *
 *   // 최적화 후 (컴파일러가 자동으로):
 *   unsigned int mpidr = read_cpuid_mpidr();  // 한 번만 호출
 *   for (int i = 0; i < 1000; i++) {
 *       // ... mpidr 사용
 *   }
 *
 * 주의사항:
 *   - 함수가 실제로 순수 함수여야 함 (전역 변수 읽기, 메모리 접근 없음)
 *   - 잘못 사용하면 잘못된 최적화로 인한 버그 발생 가능
 *   - CPU 레지스터 읽기 같은 하드웨어 접근은 런타임에 값이 변할 수 있지만,
 *     같은 CPU에서 같은 레지스터를 읽으면 항상 같은 값이므로 const로 표시 가능
 */
static inline unsigned int __attribute_const__ read_cpuid_mpidr(void)
{
	return read_cpuid(CPUID_MPIDR);
}

/* StrongARM-11x0 CPUs */
#define cpu_is_sa1100() (read_cpuid_part() == ARM_CPU_PART_SA1100)
#define cpu_is_sa1110() (read_cpuid_part() == ARM_CPU_PART_SA1110)

/*
 * Intel's XScale3 core supports some v6 features (supersections, L2)
 * but advertises itself as v5 as it does not support the v6 ISA.  For
 * this reason, we need a way to explicitly test for this type of CPU.
 */
#ifndef CONFIG_CPU_XSC3
#define cpu_is_xsc3()	0
#else
static inline int cpu_is_xsc3(void)
{
	unsigned int id;
	id = read_cpuid_id() & 0xffffe000;
	/* It covers both Intel ID and Marvell ID */
	if ((id == 0x69056000) || (id == 0x56056000))
		return 1;

	return 0;
}
#endif

#if !defined(CONFIG_CPU_XSCALE) && !defined(CONFIG_CPU_XSC3) && \
    !defined(CONFIG_CPU_MOHAWK)
#define	cpu_is_xscale_family() 0
#else
static inline int cpu_is_xscale_family(void)
{
	unsigned int id;
	id = read_cpuid_id() & 0xffffe000;

	switch (id) {
	case 0x69052000: /* Intel XScale 1 */
	case 0x69054000: /* Intel XScale 2 */
	case 0x69056000: /* Intel XScale 3 */
	case 0x56056000: /* Marvell XScale 3 */
	case 0x56158000: /* Marvell Mohawk */
		return 1;
	}

	return 0;
}
#endif

/*
 * Marvell's PJ4 and PJ4B cores are based on V7 version,
 * but require a specical sequence for enabling coprocessors.
 * For this reason, we need a way to distinguish them.
 */
#if defined(CONFIG_CPU_PJ4) || defined(CONFIG_CPU_PJ4B)
static inline int cpu_is_pj4(void)
{
	unsigned int id;

	id = read_cpuid_id();
	if ((id & 0xff0fff00) == 0x560f5800)
		return 1;

	return 0;
}
#else
#define cpu_is_pj4()	0
#endif

static inline int __attribute_const__ cpuid_feature_extract_field(u32 features,
								  int field)
{
	int feature = (features >> field) & 15;

	/* feature registers are signed values */
	if (feature > 7)
		feature -= 16;

	return feature;
}

#define cpuid_feature_extract(reg, field) \
	cpuid_feature_extract_field(read_cpuid_ext(reg), field)

#endif /* __ASSEMBLY__ */

#endif
