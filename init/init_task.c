// SPDX-License-Identifier: GPL-2.0
#include <linux/init_task.h>
#include <linux/export.h>
#include <linux/mqueue.h>
#include <linux/sched.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/rt.h>
#include <linux/sched/task.h>
#include <linux/sched/ext.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/audit.h>
#include <linux/numa.h>
#include <linux/scs.h>
#include <linux/plist.h>

#include <linux/uaccess.h>

static struct signal_struct init_signals = {
	.nr_threads	= 1,
	.thread_head	= LIST_HEAD_INIT(init_task.thread_node),
	.wait_chldexit	= __WAIT_QUEUE_HEAD_INITIALIZER(init_signals.wait_chldexit),
	.shared_pending	= {
		.list = LIST_HEAD_INIT(init_signals.shared_pending.list),
		.signal =  {{0}}
	},
	.multiprocess	= HLIST_HEAD_INIT,
	.rlim		= INIT_RLIMITS,
#ifdef CONFIG_CGROUPS
	.cgroup_threadgroup_rwsem	= __RWSEM_INITIALIZER(init_signals.cgroup_threadgroup_rwsem),
#endif
	.cred_guard_mutex = __MUTEX_INITIALIZER(init_signals.cred_guard_mutex),
	.exec_update_lock = __RWSEM_INITIALIZER(init_signals.exec_update_lock),
#ifdef CONFIG_POSIX_TIMERS
	.posix_timers		= HLIST_HEAD_INIT,
	.ignored_posix_timers	= HLIST_HEAD_INIT,
	.cputimer		= {
		.cputime_atomic	= INIT_CPUTIME_ATOMIC,
	},
#endif
	INIT_CPU_TIMERS(init_signals)
	.pids = {
		[PIDTYPE_PID]	= &init_struct_pid,
		[PIDTYPE_TGID]	= &init_struct_pid,
		[PIDTYPE_PGID]	= &init_struct_pid,
		[PIDTYPE_SID]	= &init_struct_pid,
	},
	INIT_PREV_CPUTIME(init_signals)
};

static struct sighand_struct init_sighand = {
	.count		= REFCOUNT_INIT(1),
	.action		= { { { .sa_handler = SIG_DFL, } }, },
	.siglock	= __SPIN_LOCK_UNLOCKED(init_sighand.siglock),
	.signalfd_wqh	= __WAIT_QUEUE_HEAD_INITIALIZER(init_sighand.signalfd_wqh),
};

#ifdef CONFIG_SHADOW_CALL_STACK
unsigned long init_shadow_call_stack[SCS_SIZE / sizeof(long)] = {
	[(SCS_SIZE / sizeof(long)) - 1] = SCS_END_MAGIC
};
#endif

/* init to 2 - one for init_task, one to ensure it is never freed */
static struct group_info init_groups = { .usage = REFCOUNT_INIT(2) };

/*
 * The initial credentials for the initial task
 */
static struct cred init_cred = {
	.usage			= ATOMIC_INIT(4),
	.uid			= GLOBAL_ROOT_UID,
	.gid			= GLOBAL_ROOT_GID,
	.suid			= GLOBAL_ROOT_UID,
	.sgid			= GLOBAL_ROOT_GID,
	.euid			= GLOBAL_ROOT_UID,
	.egid			= GLOBAL_ROOT_GID,
	.fsuid			= GLOBAL_ROOT_UID,
	.fsgid			= GLOBAL_ROOT_GID,
	.securebits		= SECUREBITS_DEFAULT,
	.cap_inheritable	= CAP_EMPTY_SET,
	.cap_permitted		= CAP_FULL_SET,
	.cap_effective		= CAP_FULL_SET,
	.cap_bset		= CAP_FULL_SET,
	.user			= INIT_USER,
	.user_ns		= &init_user_ns,
	.group_info		= &init_groups,
	.ucounts		= &init_ucounts,
};

/*
 * Set up the first task table, touch at your own risk!. Base=0,
 * limit=0x1fffff (=2MB)
 */
/*
 * init_task: 커널의 첫 번째 태스크 (PID 0, "swapper")
 * - 부팅 직후 가장 먼저 생기는 태스크 (최초의 커널 스레드)
 * - 커널 이미지 안에 미리 할당된 정적 배열로 존재
 * - 동적 할당 없이 시작하자마자 바로 사용 가능
 * - L1_CACHE_BYTES로 정렬: CPU 캐시 라인에 맞춰 성능 최적화
 */
struct task_struct init_task __aligned(L1_CACHE_BYTES) = {
#ifdef CONFIG_THREAD_INFO_IN_TASK
	/* 스레드 정보가 task_struct 안에 포함된 경우 */
	.thread_info	= INIT_THREAD_INFO(init_task), /* 스레드 정보 초기화 */
	.stack_refcount	= REFCOUNT_INIT(1), /* 스택 참조 카운트: 자기 자신만 참조 */
#endif
	/* 태스크 상태 (__state): 태스크의 현재 실행 상태
	 * 가능한 값들:
	 * - TASK_RUNNING (0): 실행 가능한 상태, CPU에서 실행 중이거나 실행 대기 중
	 * - TASK_INTERRUPTIBLE (1): 인터럽트 가능한 대기 상태, 시그널로 깨울 수 있음
	 * - TASK_UNINTERRUPTIBLE (2): 인터럽트 불가능한 대기 상태, 시그널로도 깨울 수 없음 (I/O 대기 등)
	 * - __TASK_STOPPED (4): 정지된 상태 (디버거에 의해)
	 * - __TASK_TRACED (8): 추적 중인 상태 (ptrace 등)
	 * - TASK_PARKED (0x40): 주차된 상태 (kthread 등)
	 * - TASK_DEAD (0x80): 종료된 상태
	 * - TASK_FROZEN (0x8000): 동결된 상태 (suspend 등)
	 *
	 * init_task는 TASK_RUNNING으로 시작: 부팅 후 바로 실행 가능해야 함
	 */
	.__state	= 0, /* TASK_RUNNING */
	.stack		= init_stack, /* 커널 스택 포인터 (정적으로 할당된 스택) */
	.usage		= REFCOUNT_INIT(2), /* 참조 카운트 2: 자기 자신 + 시스템이 항상 참조 (절대 해제되지 않음) */
	/* 태스크 플래그 (flags): 태스크의 특성을 나타내는 비트 플래그들 (여러 개 OR 가능)
	 * 가능한 플래그들:
	 * - PF_KTHREAD (0x00200000): 커널 스레드, 사용자 공간이 없는 커널 태스크
	 * - PF_IDLE (0x00000002): IDLE 스레드 (CPU가 할 일이 없을 때 실행)
	 * - PF_EXITING (0x00000004): 종료 중인 태스크
	 * - PF_USER_WORKER (0x00004000): 사용자 공간 스레드에서 클론된 커널 스레드
	 * - PF_IO_WORKER (0x00000010): I/O 워커 태스크
	 * - PF_WQ_WORKER (0x00000020): 워크큐 워커 태스크
	 * - PF_NOFREEZE (0x00008000): 동결되지 않아야 하는 태스크
	 * - PF_MEMALLOC (0x00000800): 메모리 할당 중인 태스크 (메모리 해제를 위해)
	 * - PF_KSWAPD (0x00020000): kswapd (메모리 스왑 데몬)
	 * - PF_KCOMPACTD (0x00010000): kcompactd (메모리 압축 데몬)
	 *
	 * init_task는 PF_KTHREAD: 커널 태스크이므로 사용자 공간이 없음
	 */
	.flags		= PF_KTHREAD,
	/* 우선순위 (prio): 동적 우선순위, 스케줄러가 실제로 사용하는 우선순위
	 * 범위: 0 (최고) ~ MAX_PRIO-1 (최저)
	 * - 실시간 태스크: 0 ~ MAX_RT_PRIO-1 (1~99, 높을수록 우선순위 높음)
	 * - 일반 태스크: MAX_RT_PRIO ~ MAX_PRIO-1 (100~139, 낮을수록 우선순위 높음)
	 * - MAX_PRIO는 보통 140 (MAX_RT_PRIO=100 + NICE_WIDTH=40)
	 *
	 * init_task는 MAX_PRIO - 20 = 120: 낮은 우선순위 (idle 태스크이므로)
	 * 다른 태스크가 없을 때만 실행되도록 설정
	 */
	.prio		= MAX_PRIO - 20,
	/* 정적 우선순위 (static_prio): nice 값에 의해 결정되는 기본 우선순위
	 * 범위: MAX_RT_PRIO ~ MAX_PRIO-1 (100~139)
	 * - nice 값: -20 (최고) ~ +19 (최저)
	 * - static_prio = MAX_RT_PRIO + nice + 20
	 * - 예: nice=0 → static_prio=120, nice=-20 → static_prio=100
	 *
	 * init_task는 MAX_PRIO - 20 = 120: nice=0에 해당하는 우선순위
	 */
	.static_prio	= MAX_PRIO - 20,
	/* 정규 우선순위 (normal_prio): 스케줄링 정책을 고려한 실제 우선순위
	 * - SCHED_NORMAL/BATCH/IDLE: static_prio와 동일
	 * - SCHED_FIFO/RR: rt_priority에 따라 결정 (1~99)
	 * - SCHED_DEADLINE: -1 (특별 처리)
	 *
	 * init_task는 MAX_PRIO - 20 = 120: SCHED_NORMAL이므로 static_prio와 동일
	 */
	.normal_prio	= MAX_PRIO - 20,
	/* 스케줄링 정책 (policy): 태스크를 어떻게 스케줄링할지 결정
	 *
	 * 가능한 정책들과 상세 설명:
	 *
	 * 1. SCHED_NORMAL (0) - 일반 스케줄링 정책
	 *    - CFS (Completely Fair Scheduler) 사용
	 *    - 대부분의 일반 프로세스가 사용하는 기본 정책
	 *    - nice 값(-20 ~ +19)으로 우선순위 조절 가능
	 *    - 공정성과 응답성을 균형있게 제공
	 *    - 예: 웹 브라우저, 텍스트 에디터, 일반 애플리케이션
	 *
	 * 2. SCHED_FIFO (1) - 실시간 FIFO 정책
	 *    - First In First Out, 선입선출 방식
	 *    - 우선순위: 1 ~ 99 (높을수록 우선순위 높음)
	 *    - 같은 우선순위면 먼저 실행된 태스크가 계속 실행 (타임 슬라이스 없음)
	 *    - 높은 우선순위 태스크가 낮은 우선순위 태스크를 즉시 선점 가능
	 *    - 자발적으로 양보하거나 블록되기 전까지 계속 실행
	 *    - 주의: 잘못 사용하면 시스템이 멈출 수 있음 (root 권한 필요)
	 *    - 예: 실시간 오디오/비디오 처리, 하드웨어 제어, 실시간 데이터 수집
	 *
	 * 3. SCHED_RR (2) - 실시간 Round-Robin 정책
	 *    - FIFO와 비슷하지만 타임 슬라이스(time slice)가 있음
	 *    - 우선순위: 1 ~ 99 (높을수록 우선순위 높음)
	 *    - 같은 우선순위 태스크들이 시간을 나눠서 실행 (공정성 제공)
	 *    - 타임 슬라이스가 끝나면 같은 우선순위의 다음 태스크로 전환
	 *    - FIFO보다 공정하지만 여전히 실시간 보장
	 *    - 예: 여러 실시간 태스크를 공정하게 실행해야 하는 경우
	 *
	 * 4. SCHED_BATCH (3) - 배치 스케줄링
	 *    - 대화형 태스크보다 낮은 우선순위
	 *    - CPU 집약적 작업에 적합
	 *    - 인터랙티브 성능에 영향을 주지 않음
	 *    - nice 값으로 우선순위 조절 가능
	 *    - 예: 컴파일 작업, 과학 계산, 데이터 분석, 백업 작업
	 *
	 * 5. SCHED_IDLE (5) - IDLE 스케줄링
	 *    - 가장 낮은 우선순위 (SCHED_NORMAL보다도 낮음)
	 *    - 시스템이 거의 유휴 상태일 때만 실행
	 *    - 다른 모든 태스크가 실행 가능할 때는 실행되지 않음
	 *    - 예: 백그라운드 유지보수 작업, 로그 정리, 주기적 체크
	 *
	 * 6. SCHED_DEADLINE (6) - 데드라인 스케줄링
	 *    - EDF (Earliest Deadline First) + CBS (Constant Bandwidth Server)
	 *    - 특정 시간 내에 완료되어야 하는 작업용
	 *    - 주기(period), 실행 시간(runtime), 데드라인(deadline)을 지정
	 *    - 주기적으로 실행되는 태스크에 적합
	 *    - 데드라인을 놓치지 않도록 보장
	 *    - 예: 주기적인 센서 읽기, 주기적인 제어 루프, 미디어 스트리밍
	 *
	 * 7. SCHED_EXT (7) - 확장 가능한 스케줄러
	 *    - BPF (Berkeley Packet Filter)를 통한 커스텀 스케줄러
	 *    - 사용자가 자신만의 스케줄링 알고리즘을 구현 가능
	 *    - 실험적 기능, 커널 재컴파일 없이 스케줄러 교체 가능
	 *    - 예: 특수한 워크로드에 최적화된 커스텀 스케줄러
	 *
	 * init_task는 SCHED_NORMAL: 일반적인 스케줄링이면 충분 (idle 태스크이므로)
	 */
	.policy		= SCHED_NORMAL,
	/* CPU 관련 필드들: 태스크가 어떤 CPU에서 실행될 수 있는지 제어
	 * - cpus_ptr: CPU 마스크 포인터, 자신의 cpus_mask를 가리킴
	 * - user_cpus_ptr: 사용자 공간에서 설정한 CPU 마스크 (cpuset 등)
	 *   * 커널 스레드는 NULL (사용자 공간이 없으므로)
	 *   * 사용자 프로세스는 cpuset을 통해 특정 CPU에 제한 가능
	 * - cpus_mask: 실제로 사용되는 CPU 마스크 (비트마스크)
	 *   * CPU_MASK_ALL: 모든 CPU에서 실행 가능 (모든 비트가 1)
	 *   * 예: 4코어 시스템에서 0b1111 = CPU 0,1,2,3 모두 사용 가능
	 * - max_allowed_capacity: 최대 허용 CPU 용량 (정규화된 값, 1024 = 100%)
	 *   * 비대칭 CPU (big.LITTLE 등)에서 사용
	 *   * SCHED_CAPACITY_SCALE (1024) = 최대 용량
	 * - nr_cpus_allowed: 허용된 CPU 개수 (cpus_mask에서 1인 비트 개수)
	 *   * NR_CPUS = 시스템의 최대 CPU 개수
	 */
	.cpus_ptr	= &init_task.cpus_mask,
	.user_cpus_ptr	= NULL, /* 사용자 공간 CPU 마스크: 커널 스레드는 NULL */
	.cpus_mask	= CPU_MASK_ALL, /* 모든 CPU에서 실행 가능: 모든 비트가 1 */
	.max_allowed_capacity	= SCHED_CAPACITY_SCALE, /* 최대 허용 용량: 1024 (정규화된 값) */
	.nr_cpus_allowed= NR_CPUS, /* 허용된 CPU 개수: 시스템의 모든 CPU 개수 */
	/* 메모리 관리 관련 필드들
	 * - mm: 프로세스의 메모리 관리자 (mm_struct)
	 *   * 사용자 공간의 가상 메모리 주소 공간을 관리
	 *   * 커널 스레드는 사용자 공간이 없으므로 NULL
	 *   * 사용자 프로세스는 자신만의 mm을 가짐
	 * - active_mm: 활성 메모리 관리자
	 *   * 커널 스레드는 NULL이지만 active_mm은 필요 (페이지 테이블 접근용)
	 *   * 이전에 실행된 프로세스의 mm을 참조 (lazy TLB flush)
	 *   * init_mm: 커널의 초기 메모리 관리 구조체
	 * - faults_disabled_mapping: 페이지 폴트 비활성화 매핑
	 *   * 특정 메모리 영역에서 페이지 폴트를 비활성화할 때 사용
	 *   * 초기에는 NULL
	 */
	.mm		= NULL, /* 메모리 관리자: 커널 스레드는 사용자 공간이 없으므로 NULL */
	.active_mm	= &init_mm, /* 활성 메모리 관리자: 커널 공간 메모리 관리 구조체 */
	.faults_disabled_mapping = NULL, /* 페이지 폴트 비활성화 매핑: 초기에는 NULL */
	/* 시스템 콜 재시작 블록 (restart_block)
	 * - 일부 시스템 콜은 인터럽트 가능하며, 시그널로 중단될 수 있음
	 * - 중단된 시스템 콜을 재시작하기 위한 정보를 저장
	 * - fn: 재시작 함수 포인터
	 *   * do_no_restart_syscall: 재시작하지 않음 (에러 반환)
	 *   * 다른 함수들: 특정 시스템 콜의 재시작 로직
	 * - init_task는 idle 태스크이므로 시스템 콜 재시작이 필요 없음
	 */
	.restart_block	= {
		.fn = do_no_restart_syscall, /* 시스템 콜 재시작 함수: 재시작하지 않음 */
	},
	/* CFS 스케줄러 엔티티 (se): 완전 공정 스케줄러 관련 정보
	 * - CFS (Completely Fair Scheduler): SCHED_NORMAL, SCHED_BATCH, SCHED_IDLE에서 사용
	 * - 가상 런타임(vruntime)을 사용하여 공정성 보장
	 * - 태스크가 실행될수록 vruntime이 증가, 낮은 vruntime을 가진 태스크가 우선 실행
	 * - 스케줄 그룹을 통해 CPU 시간을 그룹 단위로 할당 가능 (cgroups)
	 * - group_node: 이 태스크가 속한 스케줄 그룹의 리스트 노드
	 * - init_task는 루트 그룹에 속함
	 */
	.se		= {
		.group_node 	= LIST_HEAD_INIT(init_task.se.group_node), /* 스케줄 그룹 리스트 노드 초기화 */
	},
	/* 실시간 스케줄러 엔티티 (rt): RT 스케줄링 관련 정보
	 * - RT (Real-Time) 스케줄러: SCHED_FIFO, SCHED_RR에서 사용
	 * - 우선순위 기반 스케줄링 (1~99, 높을수록 우선순위 높음)
	 * - run_list: 같은 우선순위의 RT 태스크들이 연결된 리스트
	 * - time_slice: Round-Robin을 위한 타임 슬라이스 (SCHED_RR에서만 사용)
	 *   * SCHED_FIFO: 타임 슬라이스 없음, 자발적으로 양보하거나 블록될 때까지 실행
	 *   * SCHED_RR: 타임 슬라이스가 끝나면 같은 우선순위의 다음 태스크로 전환
	 * - init_task는 SCHED_NORMAL이므로 RT 엔티티는 사용되지 않지만 초기화는 필요
	 */
	.rt		= {
		.run_list	= LIST_HEAD_INIT(init_task.rt.run_list), /* 실행 리스트 초기화 */
		.time_slice	= RR_TIMESLICE, /* 라운드 로빈 타임 슬라이스: RT 태스크용 (일반 태스크는 사용 안 함) */
	},
	.tasks		= LIST_HEAD_INIT(init_task.tasks), /* 모든 태스크 리스트: 전역 태스크 리스트에 연결 */
#ifdef CONFIG_SMP
	/* SMP(다중 프로세서) 환경에서 푸시 가능한 태스크 리스트 */
	.pushable_tasks	= PLIST_NODE_INIT(init_task.pushable_tasks, MAX_PRIO), /* 우선순위 기반 리스트, 최대 우선순위 */
#endif
#ifdef CONFIG_CGROUP_SCHED
	.sched_task_group = &root_task_group, /* 스케줄 그룹: 루트 그룹 (최상위 그룹) */
#endif
#ifdef CONFIG_SCHED_CLASS_EXT
	/* 확장 가능한 스케줄러 클래스 (BPF 기반 커스텀 스케줄러) */
	.scx		= {
		.dsq_list.node	= LIST_HEAD_INIT(init_task.scx.dsq_list.node), /* 디스패치 큐 리스트 */
		.sticky_cpu	= -1, /* 특정 CPU에 고정되지 않음 */
		.holding_cpu	= -1, /* CPU를 점유하지 않음 */
		.runnable_node	= LIST_HEAD_INIT(init_task.scx.runnable_node), /* 실행 가능 노드 */
		.runnable_at	= INITIAL_JIFFIES, /* 실행 가능 시점: 부팅 시점 */
		.ddsp_dsq_id	= SCX_DSQ_INVALID, /* 디스패치 큐 ID: 유효하지 않음 */
		.slice		= SCX_SLICE_DFL, /* 타임 슬라이스: 기본값 */
	},
#endif
	/* ptrace 관련 필드들: 프로세스 추적 및 디버깅
	 * - ptraced: 이 태스크를 추적하는 프로세스들의 리스트
	 *   * ptrace() 시스템 콜로 이 태스크를 추적하는 디버거/트레이서 목록
	 *   * 예: gdb가 프로세스를 attach하면 이 리스트에 추가됨
	 * - ptrace_entry: 이 태스크가 다른 태스크를 추적할 때 사용하는 엔트리
	 *   * 이 태스크가 추적하는 자식 프로세스들의 리스트
	 * - 초기에는 비어있음 (추적 관계 없음)
	 */
	.ptraced	= LIST_HEAD_INIT(init_task.ptraced), /* ptrace로 추적 중인 리스트: 초기에는 비어있음 */
	.ptrace_entry	= LIST_HEAD_INIT(init_task.ptrace_entry), /* ptrace 엔트리: 초기에는 비어있음 */
	/* 프로세스 관계 필드들: 프로세스 트리 구조
	 * - real_parent: 실제 부모 프로세스 (fork를 호출한 프로세스)
	 *   * init_task는 최상위이므로 자기 자신을 부모로 가리킴
	 *   * 모든 프로세스의 조상이 됨
	 * - parent: 현재 부모 프로세스 (ptrace 등으로 변경될 수 있음)
	 *   * 일반적으로 real_parent와 같지만, ptrace로 추적되면 추적자가 parent가 됨
	 *   * init_task는 자기 자신
	 * - children: 자식 프로세스들의 리스트
	 *   * fork()로 생성된 직접 자식들
	 *   * 초기에는 비어있음, 나중에 init 프로세스 등이 추가됨
	 * - sibling: 형제 프로세스들의 리스트
	 *   * 같은 부모를 가진 다른 프로세스들
	 *   * 부모의 children 리스트에 함께 연결됨
	 *   * 초기에는 비어있음
	 * - group_leader: 프로세스 그룹의 리더
	 *   * 멀티스레드 프로세스에서 모든 스레드가 같은 group_leader를 가리킴
	 *   * init_task는 단일 스레드이므로 자기 자신
	 */
	.real_parent	= &init_task, /* 실제 부모: 자기 자신 (최상위 태스크이므로) */
	.parent		= &init_task, /* 부모: 자기 자신 (모든 프로세스의 조상) */
	.children	= LIST_HEAD_INIT(init_task.children), /* 자식 프로세스 리스트: 초기에는 비어있음 */
	.sibling	= LIST_HEAD_INIT(init_task.sibling), /* 형제 프로세스 리스트: 초기에는 비어있음 */
	.group_leader	= &init_task, /* 프로세스 그룹 리더: 자기 자신 (단일 스레드) */
	/* 자격 증명 (Credentials) 필드들: 보안 및 권한 관리
	 * - real_cred: 실제 자격 증명 (변경 불가능한 원본)
	 *   * execve() 등으로 변경되기 전의 원본 자격 증명
	 *   * 보안 감사(audit) 등에서 사용
	 * - cred: 현재 자격 증명 (실제로 사용되는 것)
	 *   * setuid, setgid 등으로 변경 가능
	 *   * 현재 실행 중인 권한을 나타냄
	 * - init_cred: 초기 자격 증명 구조체
	 *   * UID/GID: 0 (root)
	 *   * 모든 권한(CAP_FULL_SET)을 가짐
	 *   * init_task는 시스템 최초 태스크이므로 root 권한 필요
	 * - RCU_POINTER_INITIALIZER: RCU (Read-Copy-Update) 포인터 초기화
	 *   * 멀티스레드 환경에서 안전하게 포인터를 읽기 위한 메커니즘
	 */
	RCU_POINTER_INITIALIZER(real_cred, &init_cred), /* 실제 자격 증명: 초기 자격 증명 (root 권한) */
	RCU_POINTER_INITIALIZER(cred, &init_cred), /* 현재 자격 증명: 초기 자격 증명 (root 권한) */
	.comm		= INIT_TASK_COMM, /* 태스크 이름: "swapper" (idle 태스크) */
	.thread		= INIT_THREAD, /* 아키텍처별 스레드 정보 초기화 */
	.fs		= &init_fs, /* 파일 시스템 정보: 초기 파일 시스템 구조체 */
	.files		= &init_files, /* 열린 파일 테이블: 초기 파일 테이블 구조체 */
#ifdef CONFIG_IO_URING
	.io_uring	= NULL, /* io_uring 컨텍스트: 초기에는 없음 */
#endif
	/* 시그널 관련 필드들: 프로세스 간 통신 및 제어
	 * - signal: 시그널 정보 구조체 (signal_struct)
	 *   * 프로세스 그룹의 시그널 정보 공유
	 *   * 시그널 핸들러, 시그널 마스크, 리소스 제한 등 관리
	 *   * init_signals: 초기 시그널 구조체
	 * - sighand: 시그널 핸들러 구조체 (sighand_struct)
	 *   * 각 시그널(SIGTERM, SIGINT 등)에 대한 핸들러 함수
	 *   * init_sighand: 초기 시그널 핸들러 (모두 SIG_DFL)
	 * - pending: 대기 중인 시그널
	 *   * 프로세스에게 전달되었지만 아직 처리되지 않은 시그널
	 *   * list: 대기 중인 시그널 리스트
	 *   * signal: 시그널 비트마스크 (각 비트가 하나의 시그널)
	 *   * 초기에는 없음
	 * - blocked: 차단된 시그널 마스크
	 *   * sigprocmask()로 차단된 시그널들
	 *   * 차단된 시그널은 전달되지 않음 (대기만 함)
	 *   * 초기에는 모든 시그널 허용 (차단 없음)
	 */
	.signal		= &init_signals, /* 시그널 정보: 초기 시그널 구조체 */
	.sighand	= &init_sighand, /* 시그널 핸들러: 초기 시그널 핸들러 구조체 */
	/* 네임스페이스 프록시 (nsproxy): 프로세스 격리 및 가상화
	 * - 네임스페이스: 프로세스가 보는 시스템 리소스의 격리된 뷰
	 * - PID 네임스페이스: 프로세스 ID 공간 격리 (컨테이너에서 독립적인 PID)
	 * - 네트워크 네임스페이스: 네트워크 인터페이스, 라우팅 테이블 등 격리
	 * - 마운트 네임스페이스: 파일 시스템 마운트 포인트 격리
	 * - UTS 네임스페이스: 호스트명, 도메인명 격리
	 * - IPC 네임스페이스: System V IPC, POSIX 메시지 큐 등 격리
	 * - init_nsproxy: 초기 네임스페이스 (호스트 네임스페이스)
	 *   * 모든 네임스페이스의 루트
	 */
	.nsproxy	= &init_nsproxy, /* 네임스페이스 프록시: 초기 네임스페이스 (PID, 네트워크, 마운트 등) */
	.pending	= {
		.list = LIST_HEAD_INIT(init_task.pending.list), /* 대기 중인 시그널 리스트 */
		.signal = {{0}} /* 대기 중인 시그널: 초기에는 없음 */
	},
	.blocked	= {{0}}, /* 차단된 시그널 마스크: 초기에는 모든 시그널 허용 */
	.alloc_lock	= __SPIN_LOCK_UNLOCKED(init_task.alloc_lock), /* 할당 락: 초기화 (락 해제 상태) */
	.journal_info	= NULL, /* 저널 정보: 파일 시스템 저널링 관련 (초기에는 없음) */
	INIT_CPU_TIMERS(init_task) /* CPU 타이머 초기화: 프로세스별 CPU 시간 추적 */
	.pi_lock	= __RAW_SPIN_LOCK_UNLOCKED(init_task.pi_lock), /* 우선순위 상속 락: 초기화 (락 해제 상태) */
	.timer_slack_ns = 50000, /* 50 usec default slack: 타이머 슬랙 (타이머 정확도 여유 시간) */
	.thread_pid	= &init_struct_pid, /* 스레드 PID: 초기 PID 구조체 (PID 0) */
	.thread_node	= LIST_HEAD_INIT(init_signals.thread_head), /* 시그널 스레드 리스트 노드 */
#ifdef CONFIG_AUDIT
	/* 감사(Audit) 시스템: 보안 감사 로깅 */
	.loginuid	= INVALID_UID, /* 로그인 사용자 ID: 유효하지 않음 (커널 태스크) */
	.sessionid	= AUDIT_SID_UNSET, /* 세션 ID: 설정되지 않음 */
#endif
#ifdef CONFIG_PERF_EVENTS
	/* 성능 이벤트: perf 도구를 통한 성능 분석 */
	.perf_event_mutex = __MUTEX_INITIALIZER(init_task.perf_event_mutex), /* perf 이벤트 뮤텍스 */
	.perf_event_list = LIST_HEAD_INIT(init_task.perf_event_list), /* perf 이벤트 리스트 */
#endif
#ifdef CONFIG_PREEMPT_RCU
	/* 선점 가능한 RCU (Read-Copy-Update): 동기화 메커니즘 */
	.rcu_read_lock_nesting = 0, /* RCU 읽기 락 중첩 레벨: 락을 잡지 않음 */
	.rcu_read_unlock_special.s = 0, /* RCU 언락 특수 플래그: 없음 */
	.rcu_node_entry = LIST_HEAD_INIT(init_task.rcu_node_entry), /* RCU 노드 엔트리 */
	.rcu_blocked_node = NULL, /* RCU로 차단된 노드: 없음 */
#endif
#ifdef CONFIG_TASKS_RCU
	/* 태스크 RCU: 태스크별 RCU 동기화 */
	.rcu_tasks_holdout = false, /* RCU 태스크 홀드아웃: 차단되지 않음 */
	.rcu_tasks_holdout_list = LIST_HEAD_INIT(init_task.rcu_tasks_holdout_list), /* 홀드아웃 리스트 */
	.rcu_tasks_idle_cpu = -1, /* RCU 태스크 idle CPU: 설정되지 않음 */
	.rcu_tasks_exit_list = LIST_HEAD_INIT(init_task.rcu_tasks_exit_list), /* 종료 리스트 */
#endif
#ifdef CONFIG_TASKS_TRACE_RCU
	/* 태스크 추적 RCU: RCU 추적 기능 */
	.trc_reader_nesting = 0, /* 추적 리더 중첩: 없음 */
	.trc_reader_special.s = 0, /* 추적 리더 특수 플래그: 없음 */
	.trc_holdout_list = LIST_HEAD_INIT(init_task.trc_holdout_list), /* 홀드아웃 리스트 */
	.trc_blkd_node = LIST_HEAD_INIT(init_task.trc_blkd_node), /* 차단된 노드 */
#endif
#ifdef CONFIG_CPUSETS
	/* CPU 세트: CPU 및 메모리 노드 제약 */
	.mems_allowed_seq = SEQCNT_SPINLOCK_ZERO(init_task.mems_allowed_seq,
						 &init_task.alloc_lock), /* 허용된 메모리 노드 시퀀스 카운터 */
#endif
#ifdef CONFIG_RT_MUTEXES
	/* 실시간 뮤텍스: 우선순위 상속 뮤텍스 */
	.pi_waiters	= RB_ROOT_CACHED, /* 우선순위 상속 대기자: 빈 레드-블랙 트리 */
	.pi_top_task	= NULL, /* 최상위 우선순위 태스크: 없음 */
#endif
	INIT_PREV_CPUTIME(init_task) /* 이전 CPU 시간 초기화 */
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
	/* 가상 CPU 회계: CPU 시간 추적 */
	.vtime.seqcount	= SEQCNT_ZERO(init_task.vtime_seqcount), /* 가상 시간 시퀀스 카운터 */
	.vtime.starttime = 0, /* 시작 시간: 0 */
	.vtime.state	= VTIME_SYS, /* 가상 시간 상태: 시스템 모드 */
#endif
#ifdef CONFIG_NUMA_BALANCING
	/* NUMA 밸런싱: Non-Uniform Memory Access 밸런싱 */
	.numa_preferred_nid = NUMA_NO_NODE, /* 선호 NUMA 노드: 없음 */
	.numa_group	= NULL, /* NUMA 그룹: 없음 */
	.numa_faults	= NULL, /* NUMA 페이지 폴트 통계: 없음 */
#endif
#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
	/* KASAN: 커널 주소 샌타이저 (메모리 오류 감지) */
	.kasan_depth	= 1, /* KASAN 깊이: 1 (초기 깊이) */
#endif
#ifdef CONFIG_KCSAN
	/* KCSAN: 커널 동시성 샌타이저 (데이터 레이스 감지) */
	.kcsan_ctx = {
		.scoped_accesses	= {LIST_POISON1, NULL}, /* 범위 접근 리스트: 초기화 */
	},
#endif
#ifdef CONFIG_TRACE_IRQFLAGS
	/* IRQ 플래그 추적: 인터럽트 플래그 추적 */
	.softirqs_enabled = 1, /* 소프트 IRQ 활성화: 활성화됨 */
#endif
#ifdef CONFIG_LOCKDEP
	/* 락 의존성 추적: 데드락 감지 */
	.lockdep_depth = 0, /* 락 깊이: 0 (아직 락을 잡지 않음) */
	.curr_chain_key = INITIAL_CHAIN_KEY, /* 현재 체인 키: 초기 키 */
	.lockdep_recursion = 0, /* 락 의존성 재귀: 없음 */
#endif
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	/* 함수 그래프 추적기: 함수 호출 그래프 추적 */
	.ret_stack		= NULL, /* 반환 스택: 없음 */
	.tracing_graph_pause	= ATOMIC_INIT(0), /* 추적 일시 정지: 일시 정지 안 함 */
#endif
#if defined(CONFIG_TRACING) && defined(CONFIG_PREEMPTION)
	/* 추적 재귀: 추적 중 재귀 방지 */
	.trace_recursion = 0, /* 추적 재귀 레벨: 없음 */
#endif
#ifdef CONFIG_LIVEPATCH
	/* 라이브 패치: 런타임 커널 패치 */
	.patch_state	= KLP_TRANSITION_IDLE, /* 패치 상태: 유휴 (전환 없음) */
#endif
#ifdef CONFIG_SECURITY
	/* 보안 모듈: LSM (Linux Security Module) */
	.security	= NULL, /* 보안 컨텍스트: 초기에는 없음 */
#endif
#ifdef CONFIG_SECCOMP_FILTER
	/* seccomp 필터: 시스템 콜 필터링 */
	.seccomp	= { .filter_count = ATOMIC_INIT(0) }, /* 필터 개수: 0 (필터 없음) */
#endif
#ifdef CONFIG_SCHED_MM_CID
	/* 스케줄러 메모리 컨텍스트 ID: CPU 캐시 최적화 */
	.mm_cid		= { .cid = MM_CID_UNSET, }, /* 컨텍스트 ID: 설정되지 않음 */
#endif
};
EXPORT_SYMBOL(init_task);

/*
 * Initial thread structure. Alignment of this is handled by a special
 * linker map entry.
 */
#ifndef CONFIG_THREAD_INFO_IN_TASK
struct thread_info init_thread_info __init_thread_info = INIT_THREAD_INFO(init_task);
#endif
