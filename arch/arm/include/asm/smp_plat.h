/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ARM specific SMP header, this contains our implementation
 * details.
 */
#ifndef __ASMARM_SMP_PLAT_H
#define __ASMARM_SMP_PLAT_H

#include <linux/cpumask.h>
#include <linux/err.h>

#include <asm/cpu.h>
#include <asm/cputype.h>

/*
 * is_smp - 현재 실행 중인 플랫폼이 SMP 시스템인지 확인
 *
 * 이 함수는 빌드 타임 설정과 런타임 하드웨어 상태를 모두 고려하여
 * 실제로 SMP 시스템에서 실행 중인지 판단합니다.
 *
 * 반환값:
 *   true  - SMP 시스템에서 실행 중
 *   false - 단일 CPU 시스템에서 실행 중
 *
 * 전처리기 스타일 (#ifndef) 사용 이유:
 *   - #ifndef는 C 언어의 전통적인 관례로, 1970년대부터 사용됨
 *   - 헤더 가드(header guard)에서 표준적으로 사용되는 패턴
 *   - 컴파일 타임에 조건에 맞지 않는 코드를 완전히 제거하여
 *     바이너리 크기와 성능 최적화
 *   - 플랫폼 독립적인 코드 작성 가능 (ARM, x86, SMP, UP 등)
 *   - #if !defined()보다 짧고 간결함
 *
 *   참고: Linux 커널은 최근 IS_ENABLED() 매크로를 권장하지만,
 *         이 경우처럼 조건부 컴파일이 필수적이고 존재하지 않는
 *         심볼을 참조할 수 있는 경우에는 #ifndef가 적절합니다.
 *
 * 조건별 동작:
 *
 * 케이스 1: #ifndef CONFIG_SMP
 *   - 의미: CONFIG_SMP가 정의되지 않았음 (단일 CPU 커널로 빌드됨)
 *   - 반환: false
 *   - 설명: UP(Uni-Processor) 커널은 SMP를 지원하지 않으므로 항상 false
 *   - 읽기 팁: #ifndef는 "if not defined"의 의미로,
 *             "CONFIG_SMP가 정의되지 않았으면"을 의미합니다
 *
 * 케이스 2: #elif defined(CONFIG_SMP_ON_UP)
 *   - 의미: SMP 커널이지만 단일 CPU 시스템에서도 실행 가능하도록 빌드됨
 *   - 반환: 런타임에 smp_on_up 변수 값에 따라 결정
 *   - 설명: 부팅 시 실제 하드웨어를 확인하여 smp_on_up 변수를 설정
 *           - 실제 SMP 하드웨어: smp_on_up = 1 → true 반환
 *           - 실제 UP 하드웨어: smp_on_up = 0 → false 반환
 *   - 목적: 하나의 커널 이미지로 다양한 하드웨어에서 실행 가능
 *   - 참고: smp_on_up 변수는 arch/arm/kernel/head.S에서 초기화됨
 *
 * 케이스 3: #else
 *   - 의미: SMP 커널로 빌드되었고, UP 호환 모드가 아님
 *   - 반환: true
 *   - 설명: SMP 전용 커널이므로 항상 SMP로 간주
 *
 * 예시:
 *   - UP 커널 빌드: is_smp() → false
 *   - SMP 커널 + UP 호환 + 실제 SMP 하드웨어: is_smp() → true
 *   - SMP 커널 + UP 호환 + 실제 UP 하드웨어: is_smp() → false
 *   - SMP 커널 + UP 호환 없음: is_smp() → true
 */
static inline bool is_smp(void)
{
#ifndef CONFIG_SMP
	/* 케이스 1: UP 커널로 빌드됨 - SMP 지원 없음 */
	return false;
#elif defined(CONFIG_SMP_ON_UP)
	/* 케이스 2: SMP 커널이지만 UP 호환 모드 - 런타임에 하드웨어 확인 */
	extern unsigned int smp_on_up;
	return !!smp_on_up;
#else
	/* 케이스 3: SMP 전용 커널 - 항상 SMP로 간주 */
	return true;
#endif
}

/**
 * smp_cpuid_part() - return part id for a given cpu
 * @cpu:	logical cpu id.
 *
 * Return: part id of logical cpu passed as argument.
 */
static inline unsigned int smp_cpuid_part(int cpu)
{
	struct cpuinfo_arm *cpu_info = &per_cpu(cpu_data, cpu);

	return is_smp() ? cpu_info->cpuid & ARM_CPU_PART_MASK :
			  read_cpuid_part();
}

/* all SMP configurations have the extended CPUID registers */
#ifndef CONFIG_MMU
#define tlb_ops_need_broadcast()	0
#else
static inline int tlb_ops_need_broadcast(void)
{
	if (!is_smp())
		return 0;

	return ((read_cpuid_ext(CPUID_EXT_MMFR3) >> 12) & 0xf) < 2;
}
#endif

#if !defined(CONFIG_SMP) || __LINUX_ARM_ARCH__ >= 7
#define cache_ops_need_broadcast()	0
#else
static inline int cache_ops_need_broadcast(void)
{
	if (!is_smp())
		return 0;

	return ((read_cpuid_ext(CPUID_EXT_MMFR3) >> 12) & 0xf) < 1;
}
#endif

/*
 * Logical CPU mapping.
 */
extern u32 __cpu_logical_map[];
#define cpu_logical_map(cpu)	__cpu_logical_map[cpu]
/*
 * Retrieve logical cpu index corresponding to a given MPIDR[23:0]
 *  - mpidr: MPIDR[23:0] to be used for the look-up
 *
 * Returns the cpu logical index or -EINVAL on look-up error
 */
static inline int get_logical_index(u32 mpidr)
{
	int cpu;
	for (cpu = 0; cpu < nr_cpu_ids; cpu++)
		if (cpu_logical_map(cpu) == mpidr)
			return cpu;
	return -EINVAL;
}

/*
 * NOTE ! Assembly code relies on the following
 * structure memory layout in order to carry out load
 * multiple from its base address. For more
 * information check arch/arm/kernel/sleep.S
 */
struct mpidr_hash {
	u32	mask; /* used by sleep.S */
	u32	shift_aff[3]; /* used by sleep.S */
	u32	bits;
};

extern struct mpidr_hash mpidr_hash;

static inline u32 mpidr_hash_size(void)
{
	return 1 << mpidr_hash.bits;
}

extern int platform_can_secondary_boot(void);
extern int platform_can_cpu_hotplug(void);

#ifdef CONFIG_HOTPLUG_CPU
extern int platform_can_hotplug_cpu(unsigned int cpu);
#else
static inline int platform_can_hotplug_cpu(unsigned int cpu)
{
	return 0;
}
#endif

#endif
