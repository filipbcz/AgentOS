#ifndef AGENTOS_ABI_H
#define AGENTOS_ABI_H

#define SYS_GETPID   0x10001
#define SYS_WRITE    0x10002
#define SYS_EXIT     0x10003
#define SYS_SPAWN    0x10004
#define SYS_TRY_WAIT 0x10005
#define SYS_YIELD    0x10006
#define SYS_OPEN     0x10007
#define SYS_READ     0x10008
#define SYS_CLOSE    0x10009
#define SYS_PIPE     0x1000a
#define SYS_DUP2     0x1000b
#define SYS_IPC_PAIR 0x1000c
#define SYS_IPC_SEND 0x1000d
#define SYS_IPC_RECV 0x1000e
#define SYS_KILL     0x1000f
#define SYS_MONOTONIC_MS 0x10010
#define SYS_WAIT_CHILD_UNTIL 0x10011
#define SYS_SLEEP_UNTIL      0x10012
#define SYS_CHILD_AFTER      0x10013
#define SYS_FORK             0x10014
#define SYS_IPC_TRY_RECV     0x10015
#define SYS_BOOT_PAUSE       0x10016
#define SYS_WAIT_EVENTS_UNTIL 0x10017
#define SYS_TIMER_STATS       0x10018
#define SYS_IPC_TRY_SEND      0x10019
#define SYS_VM_STATS          0x1001a

/* SYS_VM_STATS(buffer, 64, 0): eight little-endian u64 fields:
 * version=1, reserved virtual pages, resident user data pages, private user
 * page-table pages (including the root), region metadata pages, cumulative
 * demand-page allocations, COW copies and last-owner COW promotions.
 * Counters start at zero for each newly created address space, including fork;
 * resident mappings and reservations are inherited by fork. Shared data is
 * counted once per mapping, so this is not a system-wide physical-RAM total.
 * The destination is made writable before taking the snapshot and is included
 * in the result. Reading the counters never resets them. Returns 0, -14 for an
 * invalid destination, -12 for allocation failure, -22 for size/flags.
 */
/* User-buffer operations may materialize valid reserved pages, including
 * kernel copy-in as well as copy-out. An invalid range returns -14; allocation
 * failure while materializing demand/COW pages returns -12. No bytes or I/O
 * state are committed by a failed preflight; pages materialized earlier in
 * that preflight may remain resident. A fatal user page fault (including OOM)
 * terminates only that process with status 270 (256 + vector 14).
 */

/* SYS_TIMER_STATS(buffer, 32, 0): copy version 1, CPU-local monotonic
 * milliseconds, cumulative scheduler timer IRQs and idle scheduler IRQs,
 * as four little-endian u64 values. Counters never reset on read. Returns
 * 0, -14 for an invalid buffer, -12 on allocation failure, -22 for invalid
 * size/flags, -5 without a clock.
 * An idle IRQ interrupts an active scheduler with no runnable process.
 */
/* SYS_IPC_TRY_SEND(fd, address, length): same authenticated, atomic message
 * operation as IPC_SEND; a full peer inbox returns -11 instead of sleeping.
 * Peer closure returns -32. No message is consumed/committed on failure.
 */

/* SYS_BOOT_PAUSE(): only the original BSP PID 1, after collecting all
 * boot-test descendants, may park for the trusted-terminal handoff.
 * Resumption returns to the SAME process, with no PID reuse. */
/* SYS_WAIT_EVENTS_UNTIL(fd_mask, cpu_local_deadline_ms, 0): atomically
 * validates watched IPC descriptors, sleeps without userspace polling and
 * wakes on queued messages, endpoint EOF, any direct child exit or deadline.
 * Returns bits 0..31 for readable descriptors, bit 32 for child exit, zero
 * at deadline; -9/-88 bad descriptor/type, -5 stalled clock, -22 arguments.
 * Like all IPC/wait operations, it is CPU-local; no cross-CPU callbacks.
 */
/* SYS_MONOTONIC_MS: nonnegative milliseconds since owning CPU's epoch.
 * Per-CPU only; a process is currently pinned to its CPU. Not UTC and not
 * synchronized between CPUs. Returns -5 if the calibrated source is absent.
 */
/* SYS_WAIT_CHILD_UNTIL(child_pid, absolute_cpu_local_deadline_ms):
 * Return and reap child's nonnegative exit status (0..255 for normal exit,
 * 256+fault_vector for a trapped fault) if it has exited;
 * otherwise block until child exits or monotonic deadline is reached.
 * Returns -110 on deadline, -10 if child absent/not owned, -5 if clock stalls,
 * -22 if deadline exceeds signed syscall range. Does not reap on timeout.
 * SYS_SLEEP_UNTIL(absolute_cpu_local_deadline_ms): blocks until the deadline,
 * returns 0 on success, -5 on clock stall, -22 on invalid deadline.
 * Timer-backed waits are local to the current CPU. With no runnable work,
 * LAPIC is armed once for the earliest deadline, with at most a one-second
 * watchdog interval. Five seconds of calibrated LAPIC countdown without
 * monotonic progress reports a clock failure, never a fabricated timeout.
 * Neither syscall busy-polls or sleeps while holding allocator locks.
 */
/* SYS_CHILD_AFTER(last_pid): return the lowest direct child's PID
 * greater than last_pid, or -10 if no such child exists. Includes adopted
 * orphaned children and zombies, but never exposes another process's children.
 * In each CPU-local process session, the first root userspace process owns
 * the reaper role. Descendants are adopted at their parent's exit or kill.
 * If that reaper itself dies, unattended children are stopped and their
 * resources are reclaimed during kernel shutdown. -22 for invalid cursor.
 */
/* SYS_FORK(): create a CPU-local child at the instruction following the
 * syscall. Parent receives a new nonzero PID; child receives zero. Physical
 * resident user pages are shared read-only with explicit COW until the first
 * write; unmaterialized reservations remain lazy in both address spaces.
 * Kernel->user writes from read()/IPC also resolve COW; immutable text
 * stays read-only and executable, and both inherit open descriptors.
 * -11 if the CPU task table is full, -12 on frame allocation failure.
 * The parent remains unchanged on clone allocation failure.
 */
/* SYS_IPC_TRY_RECV(fd, address, capacity): identical to SYS_IPC_RECV
 * except that an empty, still-open inbox returns -11 (EAGAIN) immediately.
 * A closed and drained peer returns 0. This enables one PID-root supervisor
 * to check independent service readiness, commands and timed exits without
 * becoming blocked on any one endpoint. Caller buffer includes 16-byte
 * authenticated peer prefix; no data or message is consumed on -11.
 */
/* SYS_KILL(pid): a process may terminate only its direct child.
 * The child becomes a reapable zombie with exit status 137.
 * Returns 0 when newly terminated and 1 if already a zombie; unknown PID -3,
 * unrelated PID -1, zero/self -22. This is not a general signal ABI. */
#define IPC_MAX_MESSAGE 1024

#ifdef __ASSEMBLER__
/* Exactly one entry object per native ELF supplies this ABI discriminator.
 * PT_NOTE name="AgentOS\0", type=1, descriptor={u32 version=1,u32 flags=0}.
 * Every field and record is little-endian with four-byte ELF note alignment.
 * Unmarked ELF is reserved for the future Linux ABI and is not native code.
 */
.pushsection .note.agentos,"a",@note
.balign 4
.long 8, 8, 1
.asciz "AgentOS"
.long 1, 0
.popsection
#endif

#ifndef __ASSEMBLER__
/* IPC_PAIR stores two 32-bit descriptors. Each endpoint can send and receive.
 * IPC_SEND accepts 1..IPC_MAX_MESSAGE payload bytes and returns their count.
 * IPC_RECV's capacity and return value count only payload bytes. Its destination
 * must reserve sizeof(struct ipc_peer) + capacity bytes: kernel-derived identity
 * first, then one complete payload. A short capacity (-90) or invalid destination
 * (-14), or allocation failure (-12), leaves the message queued. A drained,
 * closed peer returns 0; send returns
 * -32 after the peer's last descriptor closes. dup2/spawn retain endpoint refs.
 */
struct ipc_peer { unsigned long pid; unsigned uid, gid; };
_Static_assert(sizeof(struct ipc_peer) == 16, "IPC peer layout");
static inline long os_call(long op, long a, long b, long c) {
    __asm__ volatile ("syscall" : "+a"(op) : "D"(a), "S"(b), "d"(c) : "rcx","r11","cc","memory");
    return op;
}
static inline void format_hex(char *out, unsigned long value, unsigned digits) {
    while (digits) {
        out[--digits] = "0123456789abcdef"[value & 15];
        value >>= 4;
    }
}
#endif
#endif
