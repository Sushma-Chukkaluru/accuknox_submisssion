Accuknox Take-Home Challenge - Submission by Chukkaluru Sushma
Candidate ID: Naukri1025
Email: sushmareddychukkaluru@gmail.com

Short personal note:
I am new to eBPF but keen to learn low-level Linux networking. I implemented these sample programs
to demonstrate understanding of packet filtering using XDP and cgroup-based eBPF programs. The code
is intended for native Linux testing (Ubuntu/Debian). Please run in a safe test environment (VM).

Files included:
- Problem_1_Drop_TCP_Packets.c    : XDP program to drop TCP packets on a configured port (default 4040)
- Problem1_userspace.py           : small helper message (optional)
- Problem_2_Drop_Process_Packets.c: cgroup_skb program to restrict a process to a single port (4040)
- Problem_3_Explanation.txt       : Go code explanation and corrected version
- README.txt                      : this file

Prerequisites (Ubuntu/Debian):
    sudo apt update
    sudo apt install clang llvm bpftool libbpf-dev linux-headers-$(uname -r) -y

Problem 1 - Quick steps (native Linux):
    # Compile
    clang -O2 -target bpf -c Problem_1_Drop_TCP_Packets.c -o drop_tcp.o
    # Attach to interface (replace eth0 with your interface)
    sudo ip link set dev eth0 xdp obj drop_tcp.o sec xdp
    # Verify
    sudo bpftool net show
    # View logs (requires permissions)
    sudo cat /sys/kernel/debug/tracing/trace_pipe
    # Detach when done
    sudo ip link set dev eth0 xdp off

Problem 2 - Quick steps (native Linux, cgroup v2 recommended):
    # Compile
    clang -O2 -target bpf -c Problem_2_Drop_Process_Packets.c -o drop_process.o
    # Load program (pin to bpffs)
    sudo bpftool prog load drop_process.o /sys/fs/bpf/drop_process type cgroup_skb
    # Attach to a cgroup (example uses unified cgroup path)
    sudo bpftool cgroup attach /sys/fs/cgroup/unified/ egress pinned /sys/fs/bpf/drop_process
    # Run your target process in that cgroup (e.g., cgexec/cgcreate or systemd-run --scope)
    # Note: Target process name to match is 'myprocess' by default. Change TARGET_PROC in source if needed.

Notes & safety:
    - Run these programs in a VM or test environment. XDP can drop packets and affect network connectivity.
    - Modify interface names and paths according to your environment.
    - For production-grade usage, consider libbpf skeletons, maps for configuration, and thorough error handling.
