#ifndef __LINUX_SPINLOCK_TYPES_RAW_H
#define __LINUX_SPINLOCK_TYPES_RAW_H

#include <linux/types.h>

#if defined(CONFIG_SMP)
# include <asm/spinlock_types.h>
#else
# include <linux/spinlock_types_up.h>
#endif

#include <linux/lockdep_types.h>

typedef struct raw_spinlock {
	arch_spinlock_t raw_lock;
#ifdef CONFIG_DEBUG_SPINLOCK
	unsigned int magic, owner_cpu;
	void *owner;
#endif
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map dep_map;
#endif
} raw_spinlock_t;

#define SPINLOCK_MAGIC		0xdead4ead

#define SPINLOCK_OWNER_INIT	((void *)-1L)

#ifdef CONFIG_DEBUG_LOCK_ALLOC
# define RAW_SPIN_DEP_MAP_INIT(lockname)		\
	.dep_map = {					\
		.name = #lockname,			\
		.wait_type_inner = LD_WAIT_SPIN,	\
	}
# define SPIN_DEP_MAP_INIT(lockname)			\
	.dep_map = {					\
		.name = #lockname,			\
		.wait_type_inner = LD_WAIT_CONFIG,	\
	}

# define LOCAL_SPIN_DEP_MAP_INIT(lockname)		\
	.dep_map = {					\
		.name = #lockname,			\
		.wait_type_inner = LD_WAIT_CONFIG,	\
		.lock_type = LD_LOCK_PERCPU,		\
	}
#else
# define RAW_SPIN_DEP_MAP_INIT(lockname)
# define SPIN_DEP_MAP_INIT(lockname)
# define LOCAL_SPIN_DEP_MAP_INIT(lockname)
#endif

#ifdef CONFIG_DEBUG_SPINLOCK
# define SPIN_DEBUG_INIT(lockname)		\
	.magic = SPINLOCK_MAGIC,		\
	.owner_cpu = -1,			\
	.owner = SPINLOCK_OWNER_INIT,
#else
# define SPIN_DEBUG_INIT(lockname)
#endif

/**
 * __RAW_SPIN_LOCK_INITIALIZER - raw_spinlock 구조체 초기화 리스트 생성 매크로
 *
 * @lockname: 락의 이름 (디버깅 및 lockdep 추적용)
 *
 * 기능:
 *   - raw_spinlock_t 구조체를 초기화하기 위한 구조체 초기화 리스트를 생성
 *   - C99 designated initializer 문법 사용 (.field = value)
 *
 * 초기화되는 필드:
 *   1. .raw_lock: 아키텍처별 스핀락을 "잠금 해제됨" 상태로 초기화
 *      - __ARCH_SPIN_LOCK_UNLOCKED: 아키텍처별로 정의된 잠금 해제 상태 값
 *      - 예: ARM에서는 0, x86에서는 특정 비트 패턴
 *
 *   2. SPIN_DEBUG_INIT(lockname): 디버그 빌드에서만 초기화
 *      - .magic = SPINLOCK_MAGIC (0xdead4ead): 락이 유효한지 검증용
 *      - .owner_cpu = -1: 현재 소유 CPU 없음
 *      - .owner = SPINLOCK_OWNER_INIT: 소유자 없음
 *
 *   3. RAW_SPIN_DEP_MAP_INIT(lockname): lockdep 활성화 시 초기화
 *      - .dep_map.name: 락의 이름 (디버깅용)
 *      - .dep_map.wait_type_inner: LD_WAIT_SPIN (스핀락 대기 타입)
 *
 * 확장 예시 (CONFIG_DEBUG_SPINLOCK=y, CONFIG_DEBUG_LOCK_ALLOC=y):
 *   __RAW_SPIN_LOCK_INITIALIZER(my_lock)
 *   →
 *   {
 *       .raw_lock = __ARCH_SPIN_LOCK_UNLOCKED,
 *       .magic = 0xdead4ead,
 *       .owner_cpu = -1,
 *       .owner = (void *)-1L,
 *       .dep_map = {
 *           .name = "my_lock",
 *           .wait_type_inner = LD_WAIT_SPIN,
 *       }
 *   }
 */
#define __RAW_SPIN_LOCK_INITIALIZER(lockname)	\
{						\
	.raw_lock = __ARCH_SPIN_LOCK_UNLOCKED,	\
	SPIN_DEBUG_INIT(lockname)		\
	RAW_SPIN_DEP_MAP_INIT(lockname) }

/**
 * __RAW_SPIN_LOCK_UNLOCKED - 잠금 해제 상태의 raw_spinlock_t 타입 값 생성
 *
 * @lockname: 락의 이름
 *
 * 기능:
 *   - __RAW_SPIN_LOCK_INITIALIZER로 만든 초기화 리스트를
 *     raw_spinlock_t 타입으로 캐스팅하여 반환
 *   - 구조체 초기화 리스트를 타입이 지정된 값으로 변환
 *
 * 사용 목적:
 *   - 변수 선언 시 초기화 값으로 사용
 *   - 함수 파라미터로 전달할 수 있는 타입이 지정된 값 생성
 *
 * 예시:
 *   raw_spinlock_t lock = __RAW_SPIN_LOCK_UNLOCKED(lock);
 *   → lock 변수를 잠금 해제 상태로 초기화
 */
#define __RAW_SPIN_LOCK_UNLOCKED(lockname)	\
	(raw_spinlock_t) __RAW_SPIN_LOCK_INITIALIZER(lockname)

/**
 * DEFINE_RAW_SPINLOCK - raw_spinlock 변수 선언 및 초기화 매크로
 *
 * @x: 선언할 변수 이름
 *
 * 기능:
 *   - raw_spinlock_t 타입의 변수를 선언하고 잠금 해제 상태로 초기화
 *   - 변수 선언과 초기화를 한 번에 수행
 *
 * 사용 예시:
 *   DEFINE_RAW_SPINLOCK(my_lock);
 *   →
 *   raw_spinlock_t my_lock = __RAW_SPIN_LOCK_UNLOCKED(my_lock);
 *   →
 *   raw_spinlock_t my_lock = (raw_spinlock_t) {
 *       .raw_lock = __ARCH_SPIN_LOCK_UNLOCKED,
 *       SPIN_DEBUG_INIT(my_lock)
 *       RAW_SPIN_DEP_MAP_INIT(my_lock)
 *   };
 *
 * 실제 사용 예시:
 *   - lib/debugobjects.c:90
 *     DEFINE_RAW_SPINLOCK(pool_lock);
 *     → pool_lock이라는 이름의 raw_spinlock 변수 선언 및 초기화
 *
 *   - lib/debugobjects.c:450
 *     static DEFINE_RAW_SPINLOCK(avg_lock);
 *     → 정적 변수로 선언
 *
 * 주의사항:
 *   - 이 매크로는 변수 선언이므로 함수 내부나 전역 스코프에서만 사용 가능
 *   - 이미 선언된 변수를 초기화하려면 raw_spin_lock_init() 함수 사용
 *   - 초기화된 락은 "잠금 해제됨" 상태이므로 바로 사용 가능
 */
#define DEFINE_RAW_SPINLOCK(x)  raw_spinlock_t x = __RAW_SPIN_LOCK_UNLOCKED(x)

#endif /* __LINUX_SPINLOCK_TYPES_RAW_H */
