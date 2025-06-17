# Find clang's built-in include path for standard headers like stddef.h
CLANG_BUILTIN_INCLUDE := /usr/lib/llvm-18/lib/clang/18/include

# Get target architecture for BPF programs
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    ARCH_HDR_DEFINE = -D__TARGET_ARCH_x86
else ifeq ($(ARCH),aarch64)
    ARCH_HDR_DEFINE = -D__TARGET_ARCH_arm64
else
    $(error Unsupported architecture $(ARCH) for BPF compilation. Please add __TARGET_ARCH_xxx manually to BPF_CFLAGS.)
endif

# LLVM/Clang 경로 (시스템에 따라 조정 필요)
CLANG ?= /usr/bin/clang
LLC ?= /usr/bin/llc
BPFTOOL ?= /usr/sbin/bpftool

# --- libbpf 및 커널 헤더 경로 설정 ---
# libbpf 헤더 경로: `libbpf-dev` 패키지 설치 시 `/usr/include/bpf` 에 위치.
# 정확한 경로 확인: `dpkg -L libbpf-dev | grep bpf.h`
LIBBPF_SYSTEM_INCLUDE ?= /usr/include/bpf

# 커널 헤더 경로: 현재 실행 중인 커널 버전에 맞는 헤더 경로
# `uname -r`은 "6.8.0-60-generic"과 같은 커널 릴리즈를 반환합니다.
LINUX_KERNEL_INCLUDE ?= /usr/src/linux-headers-$(shell uname -r)/include

# 일반적인 Linux 시스템 헤더 (필요시 추가)
COMMON_LINUX_INCLUDE ?= /usr/include/linux

BPF_SOURCES = bpf/kprobe_execve.bpf.c
USER_SOURCES = user/kprobe_execve.c

BPF_OBJ = $(BPF_SOURCES:.c=.o)
BPF_SKEL_HDR = $(BPF_SOURCES:.c=.skel.h)
USER_BIN = user/kprobe_execve

VMLINUX_HDR = vmlinux.h

# BPF_CFLAGS for the eBPF program (uses BPF-specific target and defines)
# -I$(CURDIR)는 vmlinux.h를 찾기 위함
BPF_CFLAGS = -g -target bpf -D__KERNEL__ $(ARCH_HDR_DEFINE) \
	     -I$(CLANG_BUILTIN_INCLUDE) \
             -I$(LIBBPF_SYSTEM_INCLUDE) \
	     -I$(LINUX_KERNEL_INCLUDE) \
             -I$(CURDIR) \
             -Wall

# USER_CFLAGS for the user-space program (standard C flags)
# user/kprobe_execve.c가 bpf/kprobe_execve.bpf.skel.h를 include 할 것이므로,
# 해당 스켈레톤 헤더에 필요한 libbpf 관련 헤더 경로와 커널 헤더 경로를 명시
USER_CFLAGS = -g \
	      -std=gnu11 \
	      -D__need_size_t \
	      -D_FILE_OFFSET_BITS=64 \
	      -I$(CLANG_BUILTIN_INCLUDE) \
              -I$(LIBBPF_SYSTEM_INCLUDE) \
              -Wall \
	      -Wno-unused-variable

# USER_LDFLAGS for linking the user-space program with installed libbpf
# libbpf.a는 일반적으로 /usr/lib/x86_64-linux-gnu/ 에 설치됩니다.
# 이 경로를 명시적으로 -L로 추가합니다.
# `find /usr/lib -name "libbpf.a"` 명령으로 정확한 경로를 확인하여 필요시 수정하세요.
USER_LDFLAGS = -L/usr/lib/x86_64-linux-gnu -lbpf -lelf -lz


.PHONY: all clean

all: $(USER_BIN) # USER_BIN을 최종 목표로 설정. make가 의존성 체인을 따라 빌드할 것임.

# vmlinux.h 생성 규칙
$(VMLINUX_HDR):
	@echo "Generating $(VMLINUX_HDR)..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# BPF 오브젝트 파일 컴파일 규칙
# 종속성: BPF 소스 파일, vmlinux.h (vmlinux.h가 먼저 생성되어야 함)
$(BPF_OBJ): $(BPF_SOURCES) $(VMLINUX_HDR)
	@echo "Compiling BPF object: $<"
	@echo "  Full clang command for BPF obj: $(CLANG) $(BPF_CFLAGS) -c $< -o $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# BPF 스켈레톤 헤더 생성 규칙
# 종속성: BPF 오브젝트 파일 (BPF 오브젝트가 먼저 컴파일되어야 함)
$(BPF_SKEL_HDR): $(BPF_OBJ)
	@echo "Generating BPF skeleton header: $@"
	$(BPFTOOL) gen skeleton $< > $@
	@sed -i '1i #include <stddef.h>' $@

# 사용자 공간 프로그램 컴파일 및 링크 규칙
# 종속성: 사용자 소스 파일, BPF 스켈레톤 헤더 (스켈레톤 헤더가 생성되어야 include 가능)
# $(BPF_OBJ)는 $(BPF_SKEL_HDR)의 종속성이므로 여기서는 직접 명시하지 않음.
$(USER_BIN): $(USER_SOURCES) $(BPF_SKEL_HDR)
	@echo "Compiling and linking user space program: $<"
	@echo "  Full clang command for user bin: $(CLANG) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)"
	$(CLANG) $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

clean:
	@echo "Cleaning up build artifacts..."
	rm -f $(BPF_OBJ) $(BPF_SKEL_HDR) $(USER_BIN) $(VMLINUX_HDR)
