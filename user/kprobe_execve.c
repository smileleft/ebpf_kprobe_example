#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>

#include "../bpf/kprobe_execve.bpf.skel.h" // bpftool gen skeleton으로 생성될 헤더

// 이벤트 데이터 구조체 (BPF 프로그램의 event 구조체와 동일해야 함)
struct event {
    __u32 pid;
    char comm[16]; // TASK_COMM_LEN은 16
    char filename[256];
};

static struct kprobe_execve_bpf *skel;

//static int handle_event(void *ctx, void *data, size_t data_len)
static void handle_event(void *ctx, int cpu, void *data, unsigned int data_len)
{
    const struct event *e = (const struct event *)data;

    // check length of data
    if (data_len < sizeof(*e)) {
    	fprintf(stderr, "Received truncated event data (expected %zu, got %u)\n", sizeof(*e), data_len);
	return;
    }
    printf("PID: %d, COMM: %s, FILENAME: %s\n", e->pid, e->comm, e->filename);
    //return 0;
}

static void sig_handler(int sig)
{
    printf("Exiting...\n");
    if (skel) {
        kprobe_execve_bpf__destroy(skel);
    }
    exit(0);
}

int main(int argc, char **argv)
{
    int err;
    struct perf_buffer *pb = NULL;
    

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // eBPF 스켈레톤 로드
    skel = kprobe_execve_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // eBPF 프로그램 로드
    err = kprobe_execve_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %s\n", strerror(errno));
        kprobe_execve_bpf__destroy(skel);
        return 1;
    }

    // eBPF 프로그램 검증 및 어태치 (kprobe)
    err = kprobe_execve_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        kprobe_execve_bpf__destroy(skel);
        return 1;
    }

    // Perf buffer를 사용하여 이벤트 수신 설정
    // ringbuf 사용 시:
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64, handle_event, NULL, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer: %s\n", strerror(errno));
        kprobe_execve_bpf__destroy(skel);
        return 1;
    }

    printf("Successfully started! Tracing execve system calls. Press Ctrl+C to stop.\n");

    while (true) {
        err = perf_buffer__poll(pb, 100); // 100ms 타임아웃
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %s\n", strerror(errno));
            break;
        }
    }

    perf_buffer__free(pb);
    kprobe_execve_bpf__destroy(skel);
    return 0;
}
