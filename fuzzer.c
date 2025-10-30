/*
 * Copyright (C) 2025 Ivan Gaydardzhiev
 * Licensed under the GPL-2.0-only
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/ioctl.h>
#include <linux/percpu.h>
#include <linux/notifier.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/timekeeping.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/sched/signal.h>
#include <linux/preempt.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <asm/ptrace.h>
#include <asm/traps.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/cacheflush.h>
#include <asm/fpu/api.h>
#include <asm/pgtable.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ivan Gaydardzhiev");
MODULE_DESCRIPTION("x86_64 CPU instruction fuzzer");
MODULE_VERSION("1.0");

#define DEVICE_NAME "cpu_fuzzer"
#define CLASS_NAME "fuzzer"

#define FUZZ_IOCTL_START _IO('f', 1)
#define FUZZ_IOCTL_STOP _IO('f', 2)
#define FUZZ_IOCTL_STATUS _IOR('f', 3, int)

#define MAX_INST_LEN 15
#define LOG_CAPACITY 4096
#define EXEC_SLEEP_MS 5

static unsigned long max_iterations = 0;
module_param(max_iterations, ulong, 0644);
MODULE_PARM_DESC(max_iterations, "maximum fuzz iterations before stopping (0 = unlimited)");

static unsigned int fuzz_timeout_ms = 256;
module_param(fuzz_timeout_ms, uint, 0644);
MODULE_PARM_DESC(fuzz_timeout_ms, "timeout (ms) for single instruction execution");

static bool fuzz_random = true;
module_param(fuzz_random, bool, 0644);
MODULE_PARM_DESC(fuzz_random, "enable randomized instruction generation");

enum exec_status {
	EXEC_SUCCESS = 0,
	EXEC_INVALID_OPCODE,
	EXEC_GP_FAULT,
	EXEC_PAGE_FAULT,
	EXEC_MSR_FAULT,
	EXEC_TIMEOUT,
	EXEC_UNKNOWN_FAULT,
};

struct cpu_state_gp {
	u64 rax, rbx, rcx, rdx;
	u64 rsi, rdi, rbp, rsp;
	u64 r8, r9, r10, r11, r12, r13, r14, r15;
	u64 rip;
	u64 rflags;
};

struct exec_result {
	u64 timestamp_ns;
	enum exec_status status;
	u8 inst_len;
	u8 fault_vector;
	bool regs_valid;
	u8 reserved;
	u8 inst_bytes[MAX_INST_LEN];
	struct cpu_state_gp regs;
};

struct msr_snapshot {
	u32 msr;
	u64 value;
	bool valid;
};

struct inst_generator {
	bool randomize;
	u64 counter;
	struct rnd_state prng;
	u8 fixed_len;
};

struct exec_context {
	struct exec_result *res;
	unsigned long fixup_ip;
	bool active;
	bool fault_seen;
};

static const u32 tracked_msrs[] = {
	MSR_IA32_DEBUGCTLMSR,
	0x79,
	MSR_IA32_FEAT_CTL,
	MSR_CORE_PERF_GLOBAL_CTRL,
};

#define MSR_TRACKED_COUNT ARRAY_SIZE(tracked_msrs)

static const u8 exec_stub_prologue[] = {
	0x9c,                         /* pushfq */
	0x50,                         /* push rax */
	0x51,                         /* push rcx */
	0x52,                         /* push rdx */
	0x53,                         /* push rbx */
	0x55,                         /* push rbp */
	0x56,                         /* push rsi */
	0x57,                         /* push rdi */
	0x41, 0x50,                   /* push r8  */
	0x41, 0x51,                   /* push r9  */
	0x41, 0x52,                   /* push r10 */
	0x41, 0x53,                   /* push r11 */
	0x41, 0x54,                   /* push r12 */
	0x41, 0x55,                   /* push r13 */
	0x41, 0x56,                   /* push r14 */
	0x41, 0x57,                   /* push r15 */
};

static const u8 exec_stub_epilogue[] = {
	0x41, 0x5f,                   /* pop r15 */
	0x41, 0x5e,                   /* pop r14 */
	0x41, 0x5d,                   /* pop r13 */
	0x41, 0x5c,                   /* pop r12 */
	0x41, 0x5b,                   /* pop r11 */
	0x41, 0x5a,                   /* pop r10 */
	0x41, 0x59,                   /* pop r9  */
	0x41, 0x58,                   /* pop r8  */
	0x5f,                         /* pop rdi */
	0x5e,                         /* pop rsi */
	0x5d,                         /* pop rbp */
	0x5b,                         /* pop rbx */
	0x5a,                         /* pop rdx */
	0x59,                         /* pop rcx */
	0x58,                         /* pop rax */
	0x9d,                         /* popfq   */
	0xc3,                         /* ret     */
};

static struct task_struct *fuzz_thread;
static bool fuzz_running;
static DEFINE_MUTEX(fuzz_lock);
static unsigned long iter_count;

static dev_t fuzzer_dev;
static struct class *fuzzer_class;
static struct cdev fuzzer_cdev;
static struct device *fuzzer_device;

static struct exec_result *log_buffer;
static size_t log_head;
static size_t log_tail;
static DEFINE_MUTEX(log_mutex);

struct exec_mapping {
	void *addr;
	struct page *page;
};

static DEFINE_PER_CPU(struct exec_context, exec_contexts);
static DEFINE_PER_CPU(struct exec_mapping, exec_mappings);

static struct hrtimer fuzz_timer;
static atomic_t fuzz_timeout_flag = ATOMIC_INIT(0);

static int fuzz_thread_fn(void *data);

static void capture_regs_from_ptregs(struct cpu_state_gp *dst, const struct pt_regs *regs) {
	dst->rax = regs->ax;
	dst->rbx = regs->bx;
	dst->rcx = regs->cx;
	dst->rdx = regs->dx;
	dst->rsi = regs->si;
	dst->rdi = regs->di;
	dst->rbp = regs->bp;
	dst->rsp = regs->sp;
	dst->r8 = regs->r8;
	dst->r9 = regs->r9;
	dst->r10 = regs->r10;
	dst->r11 = regs->r11;
	dst->r12 = regs->r12;
	dst->r13 = regs->r13;
	dst->r14 = regs->r14;
	dst->r15 = regs->r15;
	dst->rip = regs->ip;
	dst->rflags = regs->flags;
}

static void msr_snapshot_save(struct msr_snapshot *snaps, size_t count) {
	size_t i;
	for (i = 0; i < count; ++i) {
		u64 val;

		snaps[i].msr = tracked_msrs[i];
		snaps[i].valid = !rdmsrl_safe(tracked_msrs[i], &val);
		snaps[i].value = val;
	}
}

static bool msr_snapshot_restore(const struct msr_snapshot *snaps, size_t count) {
	size_t i;
	bool ok = true;
	for (i = 0; i < count; ++i) {
		if (!snaps[i].valid)
			continue;
		if (wrmsrl_safe(snaps[i].msr, snaps[i].value)) {
			ok = false;
			pr_warn_ratelimited("fuzzer: failed to restore MSR 0x%x\n",
					    snaps[i].msr);
		}
	}
	return ok;
}

static int generate_instruction(struct inst_generator *gen, u8 *out, size_t *out_len) {
	u8 len;
	size_t i;
	if (!gen || !out || !out_len)
		return -EINVAL;
	if (gen->randomize) {
		len = 1 + (prandom_u32_state(&gen->prng) % MAX_INST_LEN);
		for (i = 0; i < len; ++i)
			out[i] = (u8)prandom_u32_state(&gen->prng);
	} else {
		len = gen->fixed_len ? gen->fixed_len : 1;
		for (i = 0; i < len; ++i)
			out[i] = (gen->counter >> (i * 8)) & 0xff;
		gen->counter++;
	}
	*out_len = len;
	return 0;
}

static void log_add(const struct exec_result *res) {
	mutex_lock(&log_mutex);
	log_buffer[log_tail] = *res;
	log_tail = (log_tail + 1) % LOG_CAPACITY;
	if (log_tail == log_head)
		log_head = (log_head + 1) % LOG_CAPACITY;
	mutex_unlock(&log_mutex);
}

static ssize_t log_read(char __user *buf, size_t count) {
	size_t copied = 0;
	mutex_lock(&log_mutex);
	while (log_head != log_tail &&
	       copied + sizeof(struct exec_result) <= count) {
		if (copy_to_user(buf + copied, &log_buffer[log_head],
				 sizeof(struct exec_result))) {
			mutex_unlock(&log_mutex);
			return -EFAULT;
		}
		copied += sizeof(struct exec_result);
		log_head = (log_head + 1) % LOG_CAPACITY;
	}
	mutex_unlock(&log_mutex);
	return copied;
}

static enum hrtimer_restart fuzz_timeout_callback(struct hrtimer *timer) {
	atomic_set(&fuzz_timeout_flag, 1);
	if (fuzz_thread)
		wake_up_process(fuzz_thread);
	return HRTIMER_NORESTART;
}

static void fuzz_start_timeout(void) {
	ktime_t kt;

	atomic_set(&fuzz_timeout_flag, 0);
	kt = ktime_set(0, (u64)fuzz_timeout_ms * NSEC_PER_MSEC);
	hrtimer_start(&fuzz_timer, kt, HRTIMER_MODE_REL_PINNED);
}

static void fuzz_cancel_timeout(void) {
	hrtimer_cancel(&fuzz_timer);
	atomic_set(&fuzz_timeout_flag, 0);
}

static int execute_instruction_safe(const u8 *code, size_t len, struct exec_result *res) {
	unsigned long flags;
	void (*entry)(void);
	struct exec_mapping *mapping;
	u8 *exec_area;
	size_t total_len;
	struct exec_context *ctx;
	bool fault_seen = false;
	if (!code || !res || !len || len > MAX_INST_LEN)
		return -EINVAL;
	preempt_disable();
	local_irq_save(flags);
	ctx = this_cpu_ptr(&exec_contexts);
	mapping = this_cpu_ptr(&exec_mappings);
	exec_area = mapping->addr;
	if (!exec_area) {
		local_irq_restore(flags);
		preempt_enable();
		return -ENOMEM;
	}
	ctx->res = res;
	ctx->fault_seen = false;
	ctx->active = true;
	ctx->fixup_ip = (unsigned long)&&fault_fixup;
	memcpy(exec_area, exec_stub_prologue, sizeof(exec_stub_prologue));
	memcpy(exec_area + sizeof(exec_stub_prologue), code, len);
	memcpy(exec_area + sizeof(exec_stub_prologue) + len,
	       exec_stub_epilogue, sizeof(exec_stub_epilogue));
	total_len = sizeof(exec_stub_prologue) + len + sizeof(exec_stub_epilogue);
	flush_icache_range((unsigned long)exec_area,
			   (unsigned long)exec_area + total_len);
	entry = (void (*)(void))exec_area;
	kernel_fpu_begin();
	entry();
	kernel_fpu_end();
	goto out;
fault_fixup:
	kernel_fpu_end();
	ctx->fault_seen = true;
out:
	fault_seen = ctx->fault_seen;
	ctx->active = false;
	ctx->res = NULL;
	local_irq_restore(flags);
	preempt_enable();
	return fault_seen ? -EFAULT : 0;
}

static int fault_die_notifier(struct notifier_block *self, unsigned long val, void *data) {
	struct die_args *args = data;
	struct exec_context *ctx;
	if (!args || (val != DIE_TRAP && val != DIE_OOPS))
		return NOTIFY_DONE;
	if (current != fuzz_thread)
		return NOTIFY_DONE;
	ctx = this_cpu_ptr(&exec_contexts);
	if (!ctx->active || !ctx->res)
		return NOTIFY_DONE;
	ctx->fault_seen = true;
	ctx->res->regs_valid = true;
	ctx->res->fault_vector = args->trapnr;
	if (args->regs)
		capture_regs_from_ptregs(&ctx->res->regs, args->regs);
	switch (args->trapnr) {
	case X86_TRAP_UD:
		ctx->res->status = EXEC_INVALID_OPCODE;
		break;
	case X86_TRAP_GP:
		ctx->res->status = EXEC_GP_FAULT;
		break;
	case X86_TRAP_PF:
		ctx->res->status = EXEC_PAGE_FAULT;
		break;
	default:
		ctx->res->status = EXEC_UNKNOWN_FAULT;
		break;
	}
	if (args->regs)
		args->regs->ip = ctx->fixup_ip;
	return NOTIFY_STOP;
}

static struct notifier_block die_nb = {
	.notifier_call = fault_die_notifier,
	.priority = INT_MAX,
};

static ssize_t fuzzer_read(struct file *file, char __user *buf, size_t len, loff_t *ppos) {
	ssize_t copied;
	copied = log_read(buf, len);
	if (copied > 0)
		*ppos += copied;

	return copied;
}

static long fuzzer_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
	long ret = 0;
	switch (cmd) {
	case FUZZ_IOCTL_START:
		mutex_lock(&fuzz_lock);
		if (fuzz_running) {
			ret = -EBUSY;
		} else {
			iter_count = 0;
			fuzz_thread = kthread_run(fuzz_thread_fn, NULL, "cpu_fuzzer");
			if (IS_ERR(fuzz_thread)) {
				ret = PTR_ERR(fuzz_thread);
				fuzz_thread = NULL;
			} else {
				fuzz_running = true;
			}
		}
		mutex_unlock(&fuzz_lock);
		break;
	case FUZZ_IOCTL_STOP:
		mutex_lock(&fuzz_lock);
		if (!fuzz_running) {
			ret = -EINVAL;
		} else {
			kthread_stop(fuzz_thread);
			fuzz_thread = NULL;
			fuzz_running = false;
		}
		mutex_unlock(&fuzz_lock);
		break;
	case FUZZ_IOCTL_STATUS:
		ret = put_user(fuzz_running ? 1 : 0, (int __user *)arg);
		break;
	default:
		ret = -ENOTTY;
		break;
	}
	return ret;
}

static const struct file_operations fuzzer_fops = {
	.owner = THIS_MODULE,
	.read = fuzzer_read,
	.unlocked_ioctl = fuzzer_ioctl,
	.llseek = noop_llseek,
};

static int fuzz_thread_fn(void *data) {
	struct inst_generator gen;
	struct exec_result result;
	struct msr_snapshot msr_snap[MSR_TRACKED_COUNT];
	u8 inst[MAX_INST_LEN];
	size_t inst_len;
	int ret;
	memset(&gen, 0, sizeof(gen));
	gen.randomize = fuzz_random;
	gen.fixed_len = 1;
	prandom_seed_state(&gen.prng, get_random_u32());
	pr_info("fuzzer: fuzz thread started (random=%d, timeout=%ums)\n",
		gen.randomize, fuzz_timeout_ms);
	while (!kthread_should_stop()) {
		if (max_iterations && iter_count >= max_iterations)
			break;
		memset(&result, 0, sizeof(result));
		ret = generate_instruction(&gen, inst, &inst_len);
		if (ret) {
			pr_warn_ratelimited("fuzzer: generator error %d\n", ret);
			continue;
		}
		result.inst_len = inst_len;
		memcpy(result.inst_bytes, inst, inst_len);
		result.status = EXEC_SUCCESS;
		msr_snapshot_save(msr_snap, MSR_TRACKED_COUNT);
		fuzz_start_timeout();
		ret = execute_instruction_safe(inst, inst_len, &result);
		fuzz_cancel_timeout();
		if (atomic_read(&fuzz_timeout_flag)) {
			result.status = EXEC_TIMEOUT;
		} else if (ret && result.status == EXEC_SUCCESS) {
			result.status = EXEC_UNKNOWN_FAULT;
		}
		if (!msr_snapshot_restore(msr_snap, MSR_TRACKED_COUNT) &&
		    result.status == EXEC_SUCCESS)
			result.status = EXEC_MSR_FAULT;
		result.timestamp_ns = ktime_get_ns();
		log_add(&result);
		iter_count++;
		if (msleep_interruptible(EXEC_SLEEP_MS))
			break;
	}
	mutex_lock(&fuzz_lock);
	fuzz_running = false;
	mutex_unlock(&fuzz_lock);
	pr_info("fuzzer: fuzz thread exiting after %lu iterations\n",
		iter_count);
	return 0;
}

static int init_exec_buffers(void) {
	int cpu;
	for_each_possible_cpu(cpu) {
		struct exec_mapping *mapping = per_cpu_ptr(&exec_mappings, cpu);
		struct page *page;
		void *addr;
		page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!page)
			goto err;
		addr = vmap(&page, 1, VM_MAP, PAGE_KERNEL_EXEC);
		if (!addr) {
			__free_page(page);
			goto err;
		}
		mapping->page = page;
		mapping->addr = addr;
	}
	return 0;
err:
	for_each_possible_cpu(cpu) {
		struct exec_mapping *mapping = per_cpu_ptr(&exec_mappings, cpu);
		if (mapping->addr)
			vunmap(mapping->addr);
		if (mapping->page)
			__free_page(mapping->page);
		mapping->addr = NULL;
		mapping->page = NULL;
	}
	return -ENOMEM;
}

static void free_exec_buffers(void) {
	int cpu;
	for_each_possible_cpu(cpu) {
		struct exec_mapping *mapping = per_cpu_ptr(&exec_mappings, cpu);
		if (mapping->addr)
			vunmap(mapping->addr);
		if (mapping->page)
			__free_page(mapping->page);
		mapping->addr = NULL;
		mapping->page = NULL;
	}
}

static int __init fuzzer_module_init(void) {
	int ret;
	pr_info("fuzzer: initializing module\n");
	log_buffer = kcalloc(LOG_CAPACITY, sizeof(*log_buffer), GFP_KERNEL);
	if (!log_buffer)
		return -ENOMEM;
	ret = init_exec_buffers();
	if (ret)
		goto free_log;
	ret = register_die_notifier(&die_nb);
	if (ret) {
		pr_err("fuzzer: failed to register die notifier\n");
		goto free_exec;
	}
	hrtimer_init(&fuzz_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_PINNED);
	fuzz_timer.function = fuzz_timeout_callback;
	ret = alloc_chrdev_region(&fuzzer_dev, 0, 1, DEVICE_NAME);
	if (ret) {
		pr_err("fuzzer: alloc_chrdev_region failed\n");
		goto unregister_die;
	}
	fuzzer_class = class_create(CLASS_NAME);
	if (IS_ERR(fuzzer_class)) {
		ret = PTR_ERR(fuzzer_class);
		pr_err("fuzzer: class_create failed\n");
		goto unregister_chrdev;
	}
	cdev_init(&fuzzer_cdev, &fuzzer_fops);
	ret = cdev_add(&fuzzer_cdev, fuzzer_dev, 1);
	if (ret) {
		pr_err("fuzzer: cdev_add failed\n");
		goto destroy_class;
	}
	fuzzer_device = device_create(fuzzer_class, NULL, fuzzer_dev, NULL, DEVICE_NAME);
	if (IS_ERR(fuzzer_device)) {
		ret = PTR_ERR(fuzzer_device);
		pr_err("fuzzer: device_create failed\n");
		goto del_cdev;
	}
	pr_info("fuzzer: module loaded /dev/%s\n", DEVICE_NAME);
	return 0;
del_cdev:
	cdev_del(&fuzzer_cdev);
destroy_class:
	class_destroy(fuzzer_class);
unregister_chrdev:
	unregister_chrdev_region(fuzzer_dev, 1);
unregister_die:
	unregister_die_notifier(&die_nb);
free_exec:
	free_exec_buffers();
free_log:
	kfree(log_buffer);
	return ret;
}

static void __exit fuzzer_module_exit(void) {
	pr_info("fuzzer: module exit\n");
	mutex_lock(&fuzz_lock);
	if (fuzz_running && fuzz_thread) {
		kthread_stop(fuzz_thread);
		fuzz_thread = NULL;
		fuzz_running = false;
	}
	mutex_unlock(&fuzz_lock);
	hrtimer_cancel(&fuzz_timer);
	unregister_die_notifier(&die_nb);
	if (fuzzer_device)
		device_destroy(fuzzer_class, fuzzer_dev);
	cdev_del(&fuzzer_cdev);
	class_destroy(fuzzer_class);
	unregister_chrdev_region(fuzzer_dev, 1);
	free_exec_buffers();
	kfree(log_buffer);
	pr_info("fuzzer: module unloaded\n");
}

module_init(fuzzer_module_init);
module_exit(fuzzer_module_exit);
