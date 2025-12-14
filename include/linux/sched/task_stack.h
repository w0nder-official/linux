/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_TASK_STACK_H
#define _LINUX_SCHED_TASK_STACK_H

/*
 * task->stack (kernel stack) handling interfaces:
 */

#include <linux/sched.h>
#include <linux/magic.h>
#include <linux/refcount.h>
#include <linux/kasan.h>

#ifdef CONFIG_THREAD_INFO_IN_TASK

/*
 * When accessing the stack of a non-current task that might exit, use
 * try_get_task_stack() instead.  task_stack_page will return a pointer
 * that could get freed out from under you.
 */
static __always_inline void *task_stack_page(const struct task_struct *task)
{
	return task->stack;
}

#define setup_thread_stack(new,old)	do { } while(0)

static __always_inline unsigned long *end_of_stack(const struct task_struct *task)
{
#ifdef CONFIG_STACK_GROWSUP
	return (unsigned long *)((unsigned long)task->stack + THREAD_SIZE) - 1;
#else
	return task->stack;
#endif
}

#else

#define task_stack_page(task)	((void *)(task)->stack)

static inline void setup_thread_stack(struct task_struct *p, struct task_struct *org)
{
	*task_thread_info(p) = *task_thread_info(org);
	task_thread_info(p)->task = p;
}

/*
 * Return the address of the last usable long on the stack.
 *
 * When the stack grows down, this is just above the thread
 * info struct. Going any lower will corrupt the threadinfo.
 *
 * When the stack grows up, this is the highest address.
 * Beyond that position, we corrupt data on the next page.
 */
/*
 * 스택의 마지막 부분(끝 부분) 주소를 반환합니다.
 * 스택 오버플로우 감지를 위해 스택 끝에 매직 넘버를 저장할 때 사용됩니다.
 *
 * 스택이 아래로 자라나는 경우 (일반적인 경우):
 * - thread_info 구조체 바로 위 위치(스택의 끝)를 반환합니다.
 * - 이보다 더 낮은 위치로 가면 thread_info 구조체가 손상됩니다.
 *
 * 스택이 위로 자라나는 경우 (CONFIG_STACK_GROWSUP):
 * - 스택의 가장 높은 주소(스택의 끝)를 반환합니다.
 * - 이 위치를 넘어가면 다음 페이지의 데이터가 손상됩니다.
 */
static inline unsigned long *end_of_stack(const struct task_struct *p) // end_of_stack 여기
{
#ifdef CONFIG_STACK_GROWSUP
	/* 스택이 위로 자라나는 경우: thread_info + THREAD_SIZE - 1 */
	return (unsigned long *)((unsigned long)task_thread_info(p) + THREAD_SIZE) - 1;
#else
	/* 스택이 아래로 자라나는 경우: thread_info 바로 위 */
	return (unsigned long *)(task_thread_info(p) + 1);
#endif
}

#endif

#ifdef CONFIG_THREAD_INFO_IN_TASK
static inline void *try_get_task_stack(struct task_struct *tsk)
{
	return refcount_inc_not_zero(&tsk->stack_refcount) ?
		task_stack_page(tsk) : NULL;
}

extern void put_task_stack(struct task_struct *tsk);
#else
static inline void *try_get_task_stack(struct task_struct *tsk)
{
	return task_stack_page(tsk);
}

static inline void put_task_stack(struct task_struct *tsk) {}
#endif

void exit_task_stack_account(struct task_struct *tsk);

/*
 * task_stack_end_corrupted: 스택 오버플로우 감지 매크로
 *
 * 동작 원리:
 * - end_of_stack(task)로 태스크의 스택 끝 주소를 가져옴
 * - 스택 끝에 저장된 값(*(end_of_stack(task)))이 STACK_END_MAGIC과 다른지 확인
 * - STACK_END_MAGIC 정의: include/uapi/linux/magic.h:75 (값: 0x57AC6E9D)
 * - 다르면 true 반환 (스택이 손상되었거나 오버플로우 발생)
 * - 같으면 false 반환 (스택이 정상)
 *
 * 매크로 확장:
 *   task_stack_end_corrupted(task)
 *   -> (*(end_of_stack(task)) != STACK_END_MAGIC)
 *
 * 설정 위치:
 * - set_task_stack_end_magic()에서 스택 끝에 STACK_END_MAGIC 값 설정
 * - 함수 정의: kernel/fork.c:871
 * - 호출 위치: init/main.c:1026 (init_task 초기화 시)
 *              kernel/fork.c:928 (새 태스크 생성 시)
 *
 * 체크 시점 및 위치:
 *
 * 1. 스케줄러에서 태스크 스위칭 시 (CONFIG_SCHED_STACK_END_CHECK 옵션 필요)
 *    - 위치: kernel/sched/core.c:5815
 *    - 함수: schedule_debug() -> __schedule() 내부
 *    - 시점: 태스크가 CPU에서 나가기 전(prev 태스크 체크)
 *    - 동작: 스택 손상 감지 시 panic() 호출
 *    - 호출 경로: schedule() -> __schedule() -> schedule_debug()
 *
 * 2. 잘못된 컨텍스트에서 sleep 함수 호출 시
 *    - 위치: kernel/sched/core.c:8820
 *    - 함수: __might_sleep() -> might_sleep()
 *    - 시점: atomic context나 interrupt context에서 sleep 함수 호출 시
 *    - 동작: 스택 손상 감지 시 경고 메시지 출력
 *    - 예: spinlock 보유 중, 인터럽트 핸들러에서 sleep 함수 호출 시
 *
 * 3. 페이지 폴트 핸들러에서 (x86)
 *    - 위치: arch/x86/mm/fault.c:705
 *    - 함수: __do_page_fault() -> oops 경로
 *    - 시점: 커널 모드에서 페이지 폴트 발생 시
 *    - 동작: 스택 손상 감지 시 "Thread overran stack, or stack corrupted" 메시지 출력
 *    - 호출 경로: page_fault_handler() -> __do_page_fault() -> oops:
 *
 * 4. 페이지 폴트 핸들러에서 (PowerPC)
 *    - 위치: arch/powerpc/mm/fault.c:651
 *    - 함수: __do_page_fault() -> oops 경로
 *    - 시점: 커널 모드에서 페이지 폴트 발생 시
 *    - 동작: x86과 동일하게 스택 손상 감지 시 메시지 출력
 *
 * 5. 스택 트레이스 수집 시
 *    - 위치: kernel/trace/trace_stack.c:276
 *    - 함수: check_stack()
 *    - 시점: 최대 스택 사용량 추적 중 스택 트레이스 수집 시
 *    - 동작: 스택 손상 감지 시 print_max_stack() 후 BUG() 호출
 *    - 용도: 스택 사용량 프로파일링 중 오버플로우 감지
 *
 * 참고사항:
 * - 이 체크는 스택 오버플로우를 사후에 감지하는 것 (예방이 아님)
 * - 스택이 이미 손상된 후에야 감지되므로, 데이터 손상이 이미 발생했을 수 있음
 * - CONFIG_SCHED_STACK_END_CHECK 옵션이 활성화되어야 스케줄러에서 체크됨
 * - STACK_END_MAGIC 값은 set_task_stack_end_magic()에서 설정됨 (kernel/fork.c:871)
 */
#define task_stack_end_corrupted(task) \
		(*(end_of_stack(task)) != STACK_END_MAGIC)

static inline int object_is_on_stack(const void *obj)
{
	void *stack = task_stack_page(current);

	obj = kasan_reset_tag(obj);
	return (obj >= stack) && (obj < (stack + THREAD_SIZE));
}

extern void thread_stack_cache_init(void);

#ifdef CONFIG_DEBUG_STACK_USAGE
unsigned long stack_not_used(struct task_struct *p);
#else
static inline unsigned long stack_not_used(struct task_struct *p)
{
	return 0;
}
#endif
extern void set_task_stack_end_magic(struct task_struct *tsk);

static inline int kstack_end(void *addr)
{
	/* Reliable end of stack detection:
	 * Some APM bios versions misalign the stack
	 */
	return !(((unsigned long)addr+sizeof(void*)-1) & (THREAD_SIZE-sizeof(void*)));
}

#endif /* _LINUX_SCHED_TASK_STACK_H */
