---
title: "Containers from Scratch: Linux Isolation Primitives in Action!"
classes: wide
header:  
  teaser: /assets/images/posts/container/container-teaser2.jpg
  overlay_image: assets/images/posts/container/container-header1.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "A deep dive into creating a secure sandbox using Namespaces, Cgroups, Capabilities, and Seccomp-BPF filters in Go and C."
description: "A deep dive into creating a secure sandbox using Namespaces, Cgroups, Capabilities, and Seccomp-BPF filters in Go and C."
categories:
  - notes
  - container
tags:
  - container 
  - linux
toc: true
---


# Introduction

In this project we went deeper into the mechanics of Linux isolation by building a container manually, without Docker or other orchestration tools. Instead of relying on abstractions, we configured the raw primitives ourselves:

- **Namespaces (NS):** set the flags to isolate process IDs, mounts, networking, UTS, IPC, and user IDs.    
- **Capabilities:** dropped privileged capabilities to enforce least privilege.    
- **cgroups:** applied resource limits to CPU, memory, and I/O to prevent runaway workloads.    
- **seccomp:** defined syscall filters to restrict what the process can invoke, reducing attack surface.    

we recreated the essential building blocks of container isolation to get a clearer view of how containers achieve security and resource control “behind the curtains.”

---

# Initial design

We are gonna build our own mini‑runtime using Go and C, trying to remove abstraction when possible to really understand the process of isolation that the primitives offer. 

The goal of this post is not explain each namespaces, or what a capability is, cause I already did in another post. Here i'm gonna show how we apply the isolation manually, without tools.

So our design will be this one for now:

```go
parent
 └─ child        ← namespaces, caps, cgroups
     └─ grandchild ← filesystem, seccomp, exec
```


- **Parent**: the supervisor process. It sets up communication channels and forks children.    
- **Child**: the process where we apply isolation primitives, new namespaces, capability drops, and resource limits via cgroups.    
- **Grandchild**: the actual container workload. Here we finalize the filesystem view, apply seccomp filters, and finally `exec` into the target program, that we can call "workload".

## Pipes and Forks

To create the above design we used two classic Unix primitives for this first phase:

- `pipe2` : creates a pair of file descriptors for parent ↔ child communication. We used two pipes: one for parent‑to‑child (P2C) and one for child‑to‑parent (C2P). Adding the `O_CLOEXEC` flag ensures the descriptors don’t leak into the final container process after `exec`.    
- `fork`: The fork call basically makes a duplicate of the current process. The new process (child) gets a different process ID (PID) and has the PID of the old process (parent) as its parent PID (PPID). Because the two processes are now running exactly the same code, they can tell which is which by the return code of fork - the child gets 0, the parent gets the PID of the child.

> [NOTE] The child gets 0 and the parent (the one that used fork) gets the PID of the child. 

This is very important cause we used that in the code to separate the action of each "layer".

Created the NewFork func cause it will be used in more than one place as mentioned:

```go
func NewFork() (uintptr, error) {
	pid, _, err := unix.RawSyscall(unix.SYS_FORK, 0, 0, 0)
	if err != 0 {
		return 0, err
	}
	return pid, nil
}
```

We did as the doc said, if PID is 0 = child, if its not 0 then its the parent.

The call is exactly like that, example:
```go
childPID, _ = lib.NewFork()

if childPID == 0 {
	// THIS IS THE CHILD PROCESS
} else {
	// THIS IS THE PARENT	
}
```

What now?

The CHILD will start to apply the isolation and the PARENT will just WAIT, when the CHILD finishes its job, then the PARENT can end too.

CHILD: 
```go
// APPLY NAMESPACES TO THE CURRENT PROCESS
// APPLY CGROUPS
// START THE MOUNT PROCESS
```

PARENT: 
```go
// func unix.Wait4(pid int, wstatus *unix.WaitStatus, options int, rusage *unix.Rusage) (wpid int, err error)

var status unix.WaitStatus
PID, err := unix.Wait4(childPID, &status, 0, nil)
```

Another question is, Why to do a double fork and create another process (grand-child) ?

Because some isolations only happens in a CHILD PROCESS, we will talk more about namespaces and other primitives applied during this "isolation process"

references: 

[https://stackoverflow.com/questions/4856255/the-difference-between-fork-vfork-exec-and-clone](https://stackoverflow.com/questions/4856255/the-difference-between-fork-vfork-exec-and-clone)

[https://man7.org/linux/man-pages/man2/pipe.2.html](https://man7.org/linux/man-pages/man2/pipe.2.html)

[https://man7.org/linux/man-pages/man2/fork.2.html](https://man7.org/linux/man-pages/man2/fork.2.html)

[https://man7.org/linux/man-pages/man2/waitpid.2.html](https://man7.org/linux/man-pages/man2/waitpid.2.html)


---

# Namespaces


Linux namespaces are the foundation of container isolation: they wrap global kernel resources so each process sees its own “private” instance. In order to understand this we have to take a look on the flags, syscalls, and what each namespace isolates.

The main entry points for namespace manipulation:

- `clone(2)`: create a new process with `CLONE_NEW*` flags to enter new namespaces
- `unshare(2)`: move the current process into a new namespace without forking.    
- `setns(2)`: join an existing namespace via a file descriptor (`/proc/<pid>/ns/*`).

> You can check what each namespaces does in my "container security in layers" post, link in the references below. 

So Ill skip this part and tell that Namespaces are kernel abstractions controlled by flags (`CLONE_NEW*`)

## Flags

So what I did was to create a struct with all the namespaces that can applied to the process (all except TIME actually).

```go
type NamespaceConfig struct {
	UTS    bool
	MOUNT  bool
	PID    bool
	NET    bool
	USER   bool
	IPC    bool
	CGROUP bool
}
```

This give us more control, and we can choose which one we want to apply to the process and also test them individually.

Simple if its enabled we apply the flag and then UNSHARE.

> I have to change to switch-case, ignore that amount of IFs please lol

```go
func ApplyNamespaces(cfg NamespaceConfig) error {
	var flags int

	if cfg.USER {		
		if err := unix.Unshare(unix.CLONE_NEWUSER); err != nil {
			return err
		}
	}

	if cfg.UTS {
		flags |= unix.CLONE_NEWUTS
	}
	
	if cfg.MOUNT {
		flags |= unix.CLONE_NEWNS
	}
	
	if cfg.PID {
		flags |= unix.CLONE_NEWPID
	}
	
	if cfg.NET {
		flags |= unix.CLONE_NEWNET
	}
	
	if cfg.IPC {
		flags |= unix.CLONE_NEWIPC
	}

	if flags == 0 {
		return nil
	}

	err := unix.Unshare(flags)
	if err != nil {
		return fmt.Errorf("unshare failed: %v", err)
	}	

	return nil
}
```

> I had to set the USER NAMESPACES with another UNSHARE cause different from others it can be created unprivileged


Some 'good to know' informations:

- Most namespaces need `CAP_SYS_ADMIN` to create, except **user namespaces** (since Linux 3.8) which can be created unprivileged
- PID and user namespaces are hierarchical, child namespaces depend on parent ones.
- Each process has `/proc/<pid>/ns/` symlinks for its namespaces. Opening these keeps the namespace alive even if all processes exit.

## Unshare

Unshare description from kernel docs:

"
`unshare()` allows a process to disassociate parts of its execution context that are currently being shared with other processes. Part of execution context, such as the namespace, is shared by default when a new process is created using fork(2), while other parts, such as the virtual memory, open file descriptors, etc, may be shared by explicit request to share them when creating a process using clone(2). 
"

> "disassociate parts of its execution context"... That is what happens when we apply the CLONE_NEW* flags, basically



## Practical examples

Speaking in simple words, after applying the namespaces, the child process doesnt have access to the parent process in the same way. 

So each one has its own importance, if disabled can open possibilities to containers escape.

### NET Namespace test

I set a netcat inside the container and Ill try to access it from the HOST.

without net namespace:

```bash
[johnermac] ❯ echo "Hello" | nc -v localhost 4445
Connection to localhost (127.0.0.1) 4445 port [tcp/*] succeeded!
```

with net namespace:

```bash
[johnermac] ❯ echo "Hello" | nc -v localhost 4445
nc: connect to localhost (127.0.0.1) port 4445 (tcp) failed: Connection refused
```

> We cant access when the net namespace is enabled. Cause the network interface of the container is isolated. So we get connection refused!


> More info about each one can be checked in the reference links below.


references: 

* [johnermac container defense in layers - namespaces](https://johnermac.github.io/notes/container/defenseinlayers/#namespaces)
* [Datadog container security fundamentals part 2](https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-2/)
* [Linux namespaces man page](https://man7.org/linux/man-pages/man7/namespaces.7.html)
* [unshare(2) man page](https://man7.org/linux/man-pages/man2/unshare.2.html)
* [Linux kernel userspace unshare documentation](https://docs.kernel.org/userspace-api/unshare.html)
* [util-linux unshare source code](https://github.com/util-linux/util-linux/blob/master/sys-utils/unshare.c)
* [setns(2) man page](https://man7.org/linux/man-pages/man2/setns.2.html)
* [clone(2) man page](https://man7.org/linux/man-pages/man2/clone.2.html)



---

# Control Groups

Control groups (cgroups) are the Linux kernel feature that lets you organize processes into hierarchies and apply resource limits, accounting, and isolation. They are the BACKBONE of container resource management, with it we can control how much CPU, memory, and I/O a process can consume.

In other words, cgroups isolate _how much_ the process can consume.
We can set a limit for resources, for example:

```go
type CGroupsConfig struct {
	CPUMax    string // "100000 1000000" it means 10%
	MemoryMax string // "256M"
	PIDsMax   string // "10"
	IOMax     string // "8:0 rbps=1048576 wbps=1048576"
	Path      string // "/sys/fs/cgroup/<name of the project>"
}
```

Cgroups are exposed through `/sys/fs/cgroup`, the kernel’s virtual filesystem interface for resource control. Inside of it:

- each directory you create represents a group (“container”).   
- each file inside defines a limit or reports usage.    
- hierarchy it's important cause the limits are applied down the tree, so we configure them in the child so they take effect in the grandchild

## Mechanics of V2

mechanics in **cgroup v2** (the version I used):
- `cgroup.controllers` tells you which resource controllers (“powers”) the kernel makes available.    
- `cgroup.subtree_control` the gate where you enable those controllers for your children.    
- Once enabled, you can set limits (e.g. memory, CPU) and add processes by writing their PID into `cgroup.procs`    

## Important things that I learned

- There are many more details (like `cgroup.events`, `cgroup.freeze`) that tools like Docker use, I’ll explore those in the next project.    
- By default, `/sys/fs/cgroup` belongs to root, so you need root privileges to configure it.    
- Apparently with **systemd delegation** (`systemd-run`), we can hand off a sub‑hierarchy to an unprivileged user, avoiding the need to run as root (but I honestly used only root for cgroup)
- also don’t forget to set the **cgroup namespace** (`CLONE_NEWCGROUP`) _after_ applying your configs, so the process sees only its delegated slice.


> Again, please ignore the imperfection of my code haha This will be refactored later. The goal is to understand the process

Set the limit of the resources the way you want:

```go
groups = CGroupsConfig{
	Path:      "/sys/fs/cgroup/bctor",
	CPUMax:    "50000 100000", // 50% CPU
	MemoryMax: "12M",
	PIDsMax:   "5",
}
```

The function created was this one:

1. Create the cgroup directory first if doesnt exist already
2. Write the limits
3. Move the process ID to cgroup.procs

```go
func ApplyCgroups(cfg CGroupsConfig) error {
	// Create the cgroup dir
	if err := os.MkdirAll(cfg.Path, 0755); err != nil {
		return fmt.Errorf("failed to create cgroup: %w", err)
	}

	// write limits
	if cfg.CPUMax != "" {
		os.WriteFile(filepath.Join(cfg.Path, "cpu.max"), []byte(cfg.CPUMax), 0644)
	}
	if cfg.MemoryMax != "" {
		os.WriteFile(filepath.Join(cfg.Path, "memory.max"), []byte(cfg.MemoryMax), 0644)
	}
	if cfg.PIDsMax != "" {
		os.WriteFile(filepath.Join(cfg.Path, "pids.max"), []byte(cfg.PIDsMax), 0644)
	}
	if cfg.IOMax != "" {
		os.WriteFile(filepath.Join(cfg.Path, "io.max"), []byte(cfg.IOMax), 0644)
	}

	// move current PID into the new cgroup
	pid := strconv.Itoa(os.Getpid())
	return os.WriteFile(filepath.Join(cfg.Path, "cgroup.procs"), []byte(pid), 0644)
}
```

And the enable controllers which add to subtree_control what we want to limit (memory, cpu, processes, etc):

```go
func EnableControllers(root string, ctrls []string) error {
	data := "+" + strings.Join(ctrls, " +")
	return os.WriteFile(
		filepath.Join(root, "cgroup.subtree_control"),
		[]byte(data),
		0644,
	)
}
```


references:

[https://johnermac.github.io/notes/container/defenseinlayers/#cgroups](https://johnermac.github.io/notes/container/defenseinlayers/#cgroups)

[https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-4/](https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-4/)

[https://man7.org/training/cgroups/](https://man7.org/training/cgroups/)



--- 

# Isolated File System

To created an Isolated file sytem, first of all we need the MOUNT NAMESPACE enabled. ALSO very important, we need the second FORK, which will create the GRAND-CHILD with inherited **Namespaces** and **Cgroups** configured before from its parent and grandparent.


> A critical detail in this implementation is the order of security controls. I intentionally apply **Capabilities** and **Seccomp** as the very last steps before the `execve` call

Operations like `mount`, `pivot_root`, and `umount` (used to jail the filesystem) require high privileges, specifically `CAP_SYS_ADMIN`. If you drop capabilities or restrict syscalls via Seccomp _before_ these operations, the kernel will deny the setup of the isolated environment.

Another important detail that Ive learned:

>the parent must `deny setgroups` and write the UID/GIDs to `/proc/[pid]/{uid,gid}_map`. This provides the "Fake Root" power needed to manipulate the filesystem inside the namespace.

## Preparing the Root

To fully isolate the system, we must transform a simple directory into a "Mount Point":

- We performed a **Bind Mount** of the root directory onto itself. This is a kernel requirement for the next step; without it, `pivot_root` will fail because it only works on actual mount points.
- then (optionally) we mount essential virtual filesystems like `/proc`, `/sys`, and `/dev` to provide the container with its own view of processes and devices.

A part of the prepare function that bind mount rootfs onto itself

```go
	if err := os.MkdirAll(cfg.Rootfs, 0755); err != nil {
		return fmt.Errorf("failed to create rootfs dir: %w", err)
	}

	_, err := os.Stat(cfg.Rootfs)
	if err != nil {
		return fmt.Errorf("rootfs stat: %w", err)
	}

	if err := unix.Mount(
		cfg.Rootfs,
		cfg.Rootfs,
		"",
		unix.MS_BIND|unix.MS_REC,
		"",
	); err != nil {
		return fmt.Errorf("bind rootfs: %w", err)
	}
```

> In this phase I also set busybox as a minimal shell to test in the future.

## pivot_root vs chroot

We chose **`pivot_root`** over the traditional `chroot` for superior security:

- **`chroot`**: Only changes the "view" of the root. The old root still exists in the background, and a process can "break out" by opening a file descriptor to the old root.
- `pivot_root` physically swaps the current root with the new root. The old host root is moved to a temporary subdirectory (e.g., `/.old_root`).
- then we do an immediately call `umount` with the **`MNT_DETACH`** flag on the old root. This removes the host’s filesystem from the container's reach, making a "jailbreak" practically impossible.

part of pivot_root function:

```go
func PivotRoot(newRoot string) error {
	putOld := filepath.Join(newRoot, ".pivot_old")

	// change to new root
	if err := unix.Chdir(newRoot); err != nil {
		return fmt.Errorf("chdir new root: %w", err)
	}

	// pivot_root(newRoot, newRoot/.pivot_old)
	if err := unix.PivotRoot(newRoot, putOld); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
```

> As mentioned, after that we unmount and remove the old root directory



references:

[mount(2)](https://man7.org/linux/man-pages/man2/mount.2.html)

[pivot_root(2)](https://man7.org/linux/man-pages/man2/pivot_root.2.html)

[umount(2)](https://man7.org/linux/man-pages/man2/umount.2.html)


---

# Capabilities

Linux Capabilities break down the "all-powerful" root privilege into small, specific units. You can verify this by reading `/proc/<PID>/status` and comparing the bitmasks before and after namespace isolation. This helps map exactly which powers were added or restricted within the new User Namespace.

What I did to understand the cap process and its impact on the process is to remove and test each capability individually. For example, if a process gains root inside the container, it is still strictly limited by the bounding set of capabilities. 

> This ensures that even a compromised root user cannot perform dangerous actions on the host.

So I did a Cap Spec struct:

```go
type CapSpec struct {
	Set    CapSet
	Cap    Capability
	Enable bool
}
```


## Thread capability sets

The way these privileges are managed is through several specific sets. These sets determine which privileges are inherited, kept, or dropped during process transitions like the fork and exec calls used in this project.

You can think of these capability sets like the infinity stones of Thanos:

- Permitted (CapPrm): The absolute ceiling of what a process can do. It acts as a limiting pool for the other sets.
- Effective (CapEff): The actual power currently being used. The kernel checks this set when a process attempts a privileged action.
- Inheritable (CapInh): This set determines which capabilities can be preserved when executing a new program.
- Bounding (CapBnd): The ultimate safety net. Once a capability is removed from here, it can never be regained by the process or its children.
- Ambient (CapAmb): The modern solution for inheritance. It allows unprivileged processes to pass capabilities to their children across an exec call.

Cap State struct, so that we can manage which one is/was applied:

```go
type CapState struct {
	PID int

	Bounding    uint64
	Permitted   uint64
	Effective   uint64
	Inheritable uint64
	Ambient     uint64
}
```


The first function we need is be able to READ the caps. We only need the PID to read, then we build the path mentioned before and read from that path, easy right?

> path = "/proc/(pid)/status"
> you can run **cat** in this path for a process, you are gonna see a lot of info about that process


```go
func ReadCaps(pid int) (*CapState, error) {
	path := "/proc/" + strconv.Itoa(pid) + "/status"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cs := &CapState{PID: pid}

	lines := strings.Split(string(data), "\n")
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "CapInh:":
			cs.Inheritable = parseCapHex(fields[1])
		case "CapPrm:":
			cs.Permitted = parseCapHex(fields[1])
		case "CapEff:":
			cs.Effective = parseCapHex(fields[1])
		case "CapBnd:":
			cs.Bounding = parseCapHex(fields[1])
		case "CapAmb:":
			cs.Ambient = parseCapHex(fields[1])
		}
	}

	return cs, nil
}
```

With this READ function created we can read before and after setting or dropping caps, and DIFF the results for debug

Next we need a function to SET and to DROP. However, we must split this by the capabilities sets, and that can be differente from one cap set to another.

For the SET we gonna do this sequence:
1. capget call will first read its current capability state from the kernel. This is necessary because Linux organizes capabilities into two 32-bit "pages" (data[0] and data[1])
2. Then we wipe the **Effective** (active power) and **Permitted** (allowed power) sets. This ensures a strict **Whitelist** policy
3. calculate the correct page and bit position, then bitwise OR operation to flip the switch for only the chosen capabilities
4. finally the final `Capset` call sends the new bitmask back to the kernel. After that the cap will be indeed activated

bitwise operation and capset example:
```go
for _, c := range caps {
		idx := c / 32
		bit := uint(c % 32)

		data[idx].Effective |= (1 << bit)
		data[idx].Permitted |= (1 << bit)
	}

	// then apply to the process
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
```

We also need a function to DROP capabilities, I realize its better to DROP ALL EXCEPT... cause we can use only one array of APPROVED caps for both SET and DROP_EXCEPT.

basically: If the capability is not on your "Keep" list, it uses the `prctl` system call with the `PR_CAPBSET_DROP` flag. This removes that privilege from the **Bounding Set** of the current thread.

```go
func DropAllExcept(keep []Capability) {
	for c := Capability(0); c <= 40; c++ {
		shouldKeep := false
		for _, k := range keep {
			if c == k {
				shouldKeep = true
				break
			}
		}

		if !shouldKeep {
			unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0)
		}
	}
}

```

ofc I did a function for every cap set individually to experiment, but thats the only 3 functions necessary for operation. We can include Inheritable and Ambient if we want that the child process is born with the same caps as the fater.

## Practical examples

### Removing CAP_SYS_ADMIN:
```go
_ = lib.DropCapability(lib.CAP_SYS_ADMIN)
capStateAfter, _ := lib.ReadCaps(os.Getpid())

err = unix.Mount("tmpfs", "/mnt", "tmpfs", 0, "")
if err != nil {
	os.Stdout.WriteString("Error: " + err.Error() + "\n")
}
```

This will return not permitted cause when we remove the CAP_SYS_ADMIN, we cant mount anymore:

```bash
Error: operation not permitted
```


### testing cap set Ambient for child processes

Without Ambient:

```go
--- CAPS after EXEC ---
CapInh: 0000000000000400 // CAP_NET_BIND_SERVICE
CapPrm: 0000000000000000 // empty
CapEff: 0000000000000000 
CapBnd: 0000000000000400
CapAmb: 0000000000000000
```

> In this case the process has the permission in the Inheritable and Bounding sets but the Effective and Permitted sets are totally empty. This means the process technically has the right to use the power but it is not active.

With Ambient:

```go
--- CAPS after EXEC ---
CapInh: 0000000000000400
CapPrm: 0000000000000400
CapEff: 0000000000000400
CapBnd: 0000000000000400
CapAmb: 0000000000000400
```

> Now the process starts with the power already turned on. This is exactly how a non root container workload can inherit specific privileges like binding to low ports

### With CAP_SETPCAP in Bounding
```go
--- CAPS after EXEC ---
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 000001fffffffeff // CAP_SETPCAP
CapAmb: 0000000000000000
```

> This is a weak setup because while the process has no power now it still has the potential to regain or manipulate capabilities if it finds a way to escalate

In Docker for example, you can activate capabilities **individually** (e.g., `--cap-add=NET_ADMIN`), but you cannot choose which **specific set** (Bounding, Ambient, etc.) to affect via the command line. 

## Quick summary

- **Bounding** = maximum possible.
- **Permitted** = what you _may_ use.
- **Effective** = what you _are_ using.
- **Inheritable** = what you can pass on.
- **Ambient** = what survives `exec`.


references:

[https://johnermac.github.io/notes/container/defenseinlayers/#capabilities](https://johnermac.github.io/notes/container/defenseinlayers/#capabilities)

[https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-3/](https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-3/)

[https://man7.org/linux/man-pages/man7/capabilities.7.html](https://man7.org/linux/man-pages/man7/capabilities.7.html)

[https://man7.org/linux/man-pages/man2/prctl.2.html](https://man7.org/linux/man-pages/man2/prctl.2.html)

[https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)

---

# Seccomp

Seccomp acts as a system call firewall by defining exactly what a process is allowed to say to the kernel. You create filters using BPF macros (Berkeley Packet Filter) to permit only the minimum set of syscalls required for a specific profile. 

> I had to do seccomp code in C, I didnt want to use the libseccomp for that. But it was a great reference nonetheless . Ill add link in the references

## Building a filter for a simple Hello message
For example if we want to just print a hello message, and using seccomp we can block every other syscall that the "print hello" won't need:

```go
syscall.Write(1, []byte("Hello Seccomp!\n"))
```

Lets define the ALLO_SYSCALL func:
```go
#define ALLOW_SYSCALL(name) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned int)SYS_##name, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
```

> This macro creates two instructions that are part of the array sent to the kernel. **BPF_JUMP** is the comparison engine that checks the syscall number, and **BPF_STMT** is the return command that tells the kernel to proceed


Example of filter for the hello workload:

```c
struct sock_filter filter_hello[] = {
    VALIDATE_ARCH,
    ALLOW_SYSCALL(write),        // Write data to stdout/stderr
    ALLOW_SYSCALL(exit),         // Terminate current thread
    ALLOW_SYSCALL(exit_group),   // Terminate process and all threads
    ALLOW_SYSCALL(rt_sigreturn), // Return from signal handler
    KILL_PROCESS
};
```


Any system call not explicitly included in the allowlist results in the process being killed via the KILL_PROCESS action. Thats the power of seccomp!

## Applying the filter

>Before applying the filters we must set PR_SET_NO_NEW_PRIVS. This flag prevents the process and its children from gaining new privileges such as through setuid binaries like sudo. Crucially this also allows non root users to apply seccomp filters.
>

```go
int install_filter(struct sock_filter *filter, size_t count) {
    struct sock_fprog prog = {
        .len = (unsigned short)count,
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return -1;

    return syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
}
```

> by using the *SECCOMP_SET_MODE_FILTER* flag we are telling the kernel to treat the provided BPF instructions as the new mandatory rules for the current thread.

Once a filter is applied it cannot be removed and stays active even after an exec call. For every subsequent syscall the kernel pauses execution to check the syscall number against the filter. If the call is not allowed the kernel sends a SIGSYS signal which terminates the process and typically generates a core dump.

> [DEBUG] we can change SECCOMP_RET_KILL_PROCESS to SECCOMP_RET_LOG. This allows the process to continue while logging blocked calls to the system audit log. 


> [ NOTE] You can monitor these in real time by running dmesg -w and filtering for syscall numbers. To translate these numbers back into human readable names use the ausyscall tool provided by the auditd package.

And in the Go side I can create Profile for everything that will be executed. For example netcat, hello message, shell, etc and just call the C functions:

```go
func ApplySeccomp(p Profile) error {
	var rc C.int

	switch p {
	case ProfileDebugShell:
		rc = C.install_debug_shell()
	case ProfileWorkload:
		rc = C.install_workload()
	case ProfileHello:
		rc = C.install_hello()
	default:
		return fmt.Errorf("unknown seccomp profile")
	}

	if rc != 0 {
		return fmt.Errorf("seccomp install failed: rc=%d", rc)
	}
	return nil
}
```

> Im using CGO to call the C functions. Ill let the link in the references

## Practical examples

### Netcat

Here I tried to access the netcat inside the container. Even if we have direct access (cause net namespaces is disabled), but we are not allowing the READ syscall to happen. 

When the host try to open the netcat communication, it gets blocked and it generates a log message in dmesg:

seccomp block (read syscall example):
```bash
sudo dmesg -w 

[269365.298765] audit: type=1326 audit(1770140032.922:127): auid=4294967295 uid=1000 gid=1000 ses=4294967295 subj=kernel pid=844575 comm="nc" exe="/bin/busybox" sig=31 arch=c000003e syscall=0 compat=0 ip=0x484042 code=0x80000000
```

here is a grep with sed to get only the number:

```bash
sudo dmesg -w | grep --line-buffered "syscall=" | sed -u 's/.*syscall=\([0-9]\+\).*/\1/'

0
```

> the process is killed because the syscall (0 = read) was used and its not allowed from filter.c implementation in seccomp

Get the name of the syscall with ausyscall (apt install auditd)
```bash
ausyscall 0
read
```


> BTW we can block netcat even before that READ syscall. It was just an example.

### ID

Here we are inside the container with root access. We are just running the command **id** normally:

```bash
/ # id
uid=0 gid=0 groups=65534,65534,65534,65534,65534,65534,65534,65534,65534,65534,65534,65534,0
```

For example if we dont allow the GETGUI syscall in the seccomp filter implementation:

```c
/* Identity & Caps */
    ALLOW_SYSCALL(getuid),       // Get real user ID
    ALLOW_SYSCALL(geteuid),      // Get effective user ID
    //ALLOW_SYSCALL(getgid),       // Get real group ID
    ALLOW_SYSCALL(getegid),      // Get effective group ID
```

The ID command will not work anymore, cause this command also uses the GETGID syscall to get the group IDs:

```bash
/ # id
Bad system call (core dumped)
```

And with **dmesg -w** or **strace** (for example), We can inspect why the command ID was blocked.

```bash
[449783.942481] audit: type=1326 audit(1770410676.459:128): auid=4294967295 uid=1000 gid=1000 ses=4294967295 subj=kernel pid=1368396 comm="id" exe="/bin/busybox" sig=31 arch=c000003e syscall=104 compat=0 ip=0x466a4b code=0x80000000
```

Lets find the NAME for the syscall=104 using ausyscall:

```bash
❯ ausyscall 104
getgid
```


references:

[https://johnermac.github.io/notes/container/defenseinlayers/#seccomp](https://johnermac.github.io/notes/container/defenseinlayers/#seccomp)

[https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-6/](https://securitylabs.datadoghq.com/articles/container-security-fundamentals-part-6/)

[https://man7.org/linux/man-pages/man2/seccomp.2.html](https://man7.org/linux/man-pages/man2/seccomp.2.html)

[https://www.kernel.org/doc/html/v5.0/userspace-api/seccomp_filter.html](https://www.kernel.org/doc/html/v5.0/userspace-api/seccomp_filter.html)

[https://docs.kernel.org/networking/filter.html](https://docs.kernel.org/networking/filter.html)

[https://github.com/seccomp/libseccomp-golang](https://github.com/seccomp/libseccomp-golang)

[https://man7.org/linux/man-pages/man2/PR_SET_NO_NEW_PRIVS.2const.html](https://man7.org/linux/man-pages/man2/PR_SET_NO_NEW_PRIVS.2const.html)

[https://man7.org/linux/man-pages/man2/pr_set_seccomp.2const.html](https://man7.org/linux/man-pages/man2/pr_set_seccomp.2const.html)

[https://go.dev/wiki/cgo](https://go.dev/wiki/cgo)



---

# Conclusion

Lets conclude with a netcat scenario, and thinking of ways to apply the primitives displayed in the post.

## Scenario

When running a workload like `nc -lp 4445`, we are essentially opening a gateway into our container. While the application might need this to function, an attacker could abuse it. 

profile netcat workload example:
```go
ProfileWorkload: {
	Path: "/bin/nc",
	Args: []string{"nc", "-lp", "4445"},
	Env:  os.Environ(),
}
```

exec example:
```go
unix.Exec(spec.Path, spec.Args, spec.Env)
```

## Blocking / Limiting Access

Here is how we can use each Linux Isolation Primitives of our container engine to block or limit this:

**1. Network Namespaces (NET NS)** 

In the example we explored, we saw that without a private Network Namespace, the container shares the host's stack. By enabling **CLONE_NEWNET** flag, we completely isolate the container's network. 

Even if `nc` opens a port, it is only visible inside the container’s private network. To make it reach the outside world, we would have to manually create a virtual ethernet bridge (veth), giving us total control over the traffic flow.

**2. Linux Capabilities**

> Just a couple of examples, a lot can be done here

We could drop :

- **CAP_NET_BIND_SERVICE** capability, so the user cannot bind to a privileged port (0-1023)
- **CAP_NET_RAW** : an attacker could use RAW sockets to perform **ARP Spoofing** or sniff traffic from other containers sharing the same network.
- **CAP_SYS_ADMIN**: if the attacker gain shell, they could try to mount the host's hard drive (`/dev/sda1`) or sensitive virtual filesystems (like the host's `/sys`) inside the container.

**3. Seccomp (The Syscall Firewall)**

Seccomp provides the most granular control over the `nc` execution lifecycle:

- We could block the `execve` syscall for the `/bin/nc` path entirely, preventing the program from even starting.
- We could block the `socket` syscall. The program would start, but it would crash immediately when trying to create a network endpoint.
- In our specific example, we allowed the port to open but could have blocked `accept4`. This allows `nc` to listen, but it would be unable to actually establish a connection with the host, effectively "ghosting" any incoming traffic.

Remember the filter.c is a whitelisting, so we just dont add these syscalls there and it will be blocked completely:

```c
// ALLOW_SYSCALL(execve),  // Initialization
// ALLOW_SYSCALL(socket),  // Network
// ALLOW_SYSCALL(accept4), // Network (accept with flags)
```

**4. Cgroups (Resource Control)**

If an attacker uses `nc` to launch a Reverse Shell or a Fork Bomb, **Cgroups** are the final wall. By limiting the number of processes (pids.max) or the amount of memory, we ensure that a compromised `nc` cannot spawn a thousand sub-processes to crash the host or eat up all the CPU while scanning the network.


references:

[https://man7.org/linux/man-pages/man3/exec.3.html](https://man7.org/linux/man-pages/man3/exec.3.html)


> I added references per chapter for this post


---

# What's Next?

Until now, we have been focused on isolating and controlling a single process. In my next post, we are going to step up and look at how to build an **Orchestrator**. We will dive into managing the lifecycle of multiple containers, coordinating their resources, and handling inter-container communication.

I'm still building, but you can check my repo meanwhile if u want:

[https://github.com/Johnermac/bctor](https://github.com/Johnermac/bctor)


> I hope you liked it !  :)
