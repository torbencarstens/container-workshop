# Let's build a container runtime

## general TODOs

- talk about nsenter earlier
- add mount example with usb stick
- add more sub-headlines
- add more spoiler (\<details>) for long outputs and create an appropriate \<summary> for it
- add disclaimer for correctness about PID vs TID in some parts of this (there is a TODO for this in the cgroups section due to the `tasks` file)

## conventions

commands in different namespaces will be shown with the following notation:

```
${id/name}> {command}
{output}
```

if we're simply using 2 shells ids (0/1) will be used, otherwise names might be used

I'm using zsh as a default shell, this makes identifying our test namespaces easier since we'll be using bash in these.

## Linux namespaces

Namespaces allow us to separate certain resources for a process from all other processes.

> A  namespace  wraps a global system resource in an abstraction that makes it appear to the processes within the namespace that they have their own isolated instance of the global resource.
>
> Changes to the global resource are visible to other processes that are members of the namespace, but are invisible to other processes.
> 
> One use of namespaces is to implement containers.

\- man page

Since the man-page mentions that processes are bound to namespaces, we'll simply believe this and carry on. 

### where is my namespace

Well, let's assume that information about the namespace our process is using is probably stored somewhere, we want to have a look at this ourselves.

On linux, we have our own filesystem (`fs` from here on out) for this, it's called `procfs` and is usually handily pre-mounted for us at `/proc`.

You can also manually mount it at `/proc` by doing `mount -t proc proc /proc` but usually `systemd` does this for you.

#### **catch you're it**

(`$$` is our current process id (`pid` in the rest of the tutorial))

```bash
$ ls /proc/$$/ns
lrwxrwxrwx 0 torben 10 Mai 15:18 cgroup -> cgroup:[4026531835]
lrwxrwxrwx 0 torben 10 Mai 15:18 ipc -> ipc:[4026531839]
lrwxrwxrwx 0 torben 10 Mai 15:18 mnt -> mnt:[4026531841]
lrwxrwxrwx 0 torben 10 Mai 15:18 net -> net:[4026531840]
lrwxrwxrwx 0 torben 10 Mai 15:18 pid -> pid:[4026531836]
lrwxrwxrwx 0 torben 10 Mai 15:18 pid_for_children -> pid:[4026531836]
lrwxrwxrwx 0 torben 10 Mai 15:18 time -> time:[4026531834]
lrwxrwxrwx 0 torben 10 Mai 15:18 time_for_children -> time:[4026531834]
lrwxrwxrwx 0 torben 10 Mai 15:18 user -> user:[4026531837]
lrwxrwxrwx 0 torben 10 Mai 15:18 uts -> uts:[4026531838]
```

there is also `/proc/self/` which is simply a link to our `/proc/{pid}` directory:

```bash
$ ls -l /proc/ | grep "self ->"
lrwxrwxrwx    0 root             10 Mai 16:46 self -> 13929
```

### uts namespace

The `uts` namespace is probably the least intersting one but is a good entrypoing for showing a bit about namespaces capabilities.

Let's have a look at our hostname

```bash
$0> hostname
torben-xps9320
```

#### **creating a namespace**
--
we can create one or multiple namespace with `unshare`

```bash
$ unshare --help
Usage:
 unshare [options] [<program> [<argument>...]]`
[...]
 -m, --mount[=<file>]      unshare mounts namespace
 -u, --uts[=<file>]        unshare UTS namespace (hostname etc)
 -i, --ipc[=<file>]        unshare System V IPC namespace
 -n, --net[=<file>]        unshare network namespace
 -p, --pid[=<file>]        unshare pid namespace
 -U, --user[=<file>]       unshare user namespace
 -C, --cgroup[=<file>]     unshare cgroup namespace
 -T, --time[=<file>]       unshare time namespace
[...]
```

by executing `unshare {command}` our command will be run in a new namespace.

#### **back to uts**

Following from this we can create a new uts namespace and running bash inside it

```bash
$0> unshare --uts bash
# I'm in
$1> hostname
torben-xps9320
```

Our hostname inside our new uts namespace is still the same because by default we're inheriting all values from our callee's namespace (i.e. our root namespace in this case).

Let's try changing our hostname inside of our container and see whether we have different hostnames inside and outside:

```bash
$1> hostname container
$1> hostname
container

$0> hostname
torben-xps9320
```

Our shell inside the new uts namespace now has `container` as a hostname while our root namespace still has `torben-xps9320`.

_Much success_

#### **entering a namespace**

Whilst `unshare` creates a new namespace for us, we can also attach to an existing namespace, this is especially useful for debugging purposes.

```bash
$0> unshare --uts bash
$1> hostname container
$0> ps -C bash
    PID TTY          TIME CMD
   8374 pts/0    00:00:00 bash
$0> hostname
torben-xps9320
$0> nsenter --target 8374 --uts hostname
container
```

Instead of specifying a PID we can also specify a path, we'll simply take the path to the bash namespace from the `/proc` direcotry.

```bash
sudo nsenter --uts=/proc/8374/ns/uts hostname
container
```

Similar to unshare we can selectivly enter one or multiple namespaces.

### pid namespace

1337 h4x052 that we're we simply substitute `--uts` with `--pid` and we're _in_ once again:

```bash
$0> sudo unshare --pid bash
bash: fork: Cannot allocate memory
$1> bash-5.1# ls -la
bash: fork: Cannot allocate memory
bash: wait_for: No record of process 19508
# note: on executing more commands the `19508` PID is printed as a source everytime
```

Or not, what is going on here?

Let's have a look at the relevant processes and their namespaces, we already know that we can do this via the `/proc` files.

We'll start with the only pid we have so far:

```bash
$0> stat /proc/19508
stat: cannot statx '/proc/19508': No such file or directory
```
ok, since we don't know anything so far let's have a look at the processes which we know are running (`$1` is still our bash shell in it's own namespace)

```bash
$1> echo $PPID # parent process of our shell in the namespace
19498
$1> echo $$ # our bash process inside the namespace
19499
```

Note that our `bash` process isn't pid 1 despite us executing `bash` in a new pid namespace.

To confirm that these are indeed our processes, let's have a look at what these processes are.

If you check the `/proc/pid/cmdline` file you'll see the command and arguments for the pid.

```bash
$0> cat /proc/19498/cmdline 
sudo unshare --pid bash
$0> cat /proc/19499/cmdline
bash
```

We've confirmed that these are our processes, `bash` is our command executed inside the namespace and `sudo` (with `unshare --pid bash` as arguments) is our parent process.

> notice anything?

#### **where is the namespace info in `/proc/`**

```bash
$0> sudo ls -l /proc/19498/ns/ | grep pid
lrwxrwxrwx 1 root root 0 10. Mai 15:58 pid -> pid:[4026531836]
lrwxrwxrwx 1 root root 0 10. Mai 15:58 pid_for_children -> pid:[4026531836]
$0> sudo ls -s /proc/19499/ns | grep pidthe 
lrwxrwxrwx 1 root root 0 10. Mai 16:00 pid -> pid:[4026531836]
lrwxrwxrwx 1 root root 0 10. Mai 16:00 pid_for_children -> pid:[4026533205]
```

Note that our `bash` process has a different namespace for `pid_for_children` this means that all children (e.g. `ls`) will be spawned with PIDs residing in the new namespace.

#### **strace to the rescue**

Let's have a quick look at what `unshare` and our comomands are doing (taking `ls` as an example), this might provide us with some insight into why our command is failing.

I can recommend reading the full `strace` log but I'll spare you the effort of finding the interesting bits:

<details>
<summary>strace --follow-forks unshare ls</summary>

```bash
$ strace --follow-forks unshare ls
3807 execve("/usr/bin/ls", ["ls"], 0x7ffc049120f0 /* 63 vars */) = 0
[...]
3807 execve("/usr/local/sbin/ls", ["ls"], 0x7fffb1a5bf60 /* 63 vars */) = -1 ENOENT (No such file or directory)
3807 execve("/usr/local/bin/ls", ["ls"], 0x7fffb1a5bf60 /* 63 vars */) = -1 ENOENT (No such file or directory)
[...]
3807 execve("/usr/bin/ls", ["ls"], 0x7ffff9934e20 /* 63 vars */) = 0
```

</details>

#### why are you showing me some execve calls

Well, what's so interesting about `execve` and what is it? Let's steal content from the man-pages again:

```text
execve()  executes  the  program  referred  to by pathname.  This causes the program that is currently being run by the calling process to be replaced with a new program, with newly initialized stack, heap, and (initialized and uninitialized) data segments.
```

`execve` is a fairly common syscall, the interesting part is that `execve` simply replaces the current process.

For our `unshare` call this means that the `unshare` command "disappears" and `ls` "appears" in it's place with a lot of the same metadata (details on this later).

I've sprinkled the `--follow-forks` in there so that we can see that we keep our previous pid when we switch from `unshare` to `ls`.

#### back to debugging

contrasting this with grep'ing for `execve` in `ls` we see that the `execve` calls further down the road do not happen with `1s`.

```bash
$ strace --trace=execve ls
execve("/usr/bin/ls", ["ls"], 0x7ffd1237b0f0 /* 63 vars */) = 0
[...]
```

Let's have a look at the `execve` man page and check whether namespaces are mentioned (spoiler, they are not).

But, we do have a section which shows us a list of non-presered attributes:

```text
  Effect on process attributes
       All process attributes are preserved during an execve(), except the following:
```

Since namespaces aren't explicitly mentioned here we simply assume that the namespaces info is preserved after `execve` (in our `ls` command).

#### **reading the help usually... helps**

if we have a look at the `unshare` help the following option jumps out:

```bash
$ unshare --help
[...]
 -f, --fork                fork before launching <program>
[...]
```

By now we're experienced in reading and stealing from man pages so we have a quick refresher on what fork is:

```bash
fork() This  function  creates  a new process. The return value is the zero in the child and the process-id number of the child in the parent, or -1 upon error. In the latter case, ERRNO indicates the problem. In the child, PROCINFO["pid"] and PROCINFO["ppid"] are updated to reflect the correct values.
```

Since there are no pesky details about with data/attributes is and isn't preserved we assume that fork actually spawns a completely new process with no connection to our callee except (sorta) the PPID.

#### let's get on with f*rking

This is what you've all been waiting for

```bash
$0> unshare --pid --fork bash
$1> ls -l
[correct output -> can allocate memory]
```

_much success_

Let's have a look at the difference in our processes

> Reminder: previously we had a parent process (`sudo` with `unshare --pid bash` as arguments which had `bash` as a child process)

> the `-e` flag for `ps` is `Select all processes.  Identical to -A.`
>
> the `-f` flag is ```
       -f     Do full-format listing.  This option can be combined with many other UNIX-style options to add additional columns.  It also causes the command arguments to be printed.  When used with -L, the NLWP (number of threads) and LWP (thread ID) columns will be added. See the c option, the format keyword args, and the format keyword comm.```

```bash
$0> ps -ef | grep bash
root       21109    6984  0 16:20 pts/2    00:00:00 sudo unshare --pid --fork bash
root       21110   21109  0 16:20 pts/2    00:00:00 unshare --pid --fork bash
root       21111   21110  0 16:20 pts/2    00:00:00 bash
```

instead of `sudo` being the `pid`, we now have a separate `unshare` process which is the parent of our `bash` process (this makes sense since `bash` is started as a forked process).

Looking at the namespaces we also observe something interesting

```bash
$0> sudo ls -l /proc/21109/ns/ | grep pid
lrwxrwxrwx 1 root root 0 10. Mai 16:23 pid -> pid:[4026531836]
lrwxrwxrwx 1 root root 0 10. Mai 16:23 pid_for_children -> pid:[4026531836]
$0> sudo ls -l /proc/21110/ns/ | grep pid
lrwxrwxrwx 1 root root 0 10. Mai 16:24 pid -> pid:[4026531836]
lrwxrwxrwx 1 root root 0 10. Mai 16:24 pid_for_children -> pid:[4026533086] # (!) 06 not 36
$0> sudo ls -l /proc/21111/ns/ | grep pid
lrwxrwxrwx 1 root root 0 10. Mai 16:24 pid -> pid:[4026533086]
lrwxrwxrwx 1 root root 0 10. Mai 16:24 pid_for_children -> pid:[4026533086]
```

Previously our `bash` namespace had it's own pid inside of our root namespace, whereas now the `bash` process is in our new namespace and `unshare` has it's pid in the root namespace while `pid_for_children` is set to the new namespace. This makes sense since, otherwise `bash` wouldn't have been started in our new namespace otherwise.

`bash` also has `pid_for_children` in the new namepace (as before), so any children will also be executed in the new namespace. The difference now is that the children have a parent process in the same pid namespace as before.

This is also be seen by looking at our pid (remember: before our `bash` process had a pid != 1)

```bash
$ echo $$
1
```

Since we've started bash in our new namespace as the root process, bash now has pid 1.

#### **execve vs fork**

comparing syscalls for both versions:

```bash
$ strace --follow-forks unshare --pid ls
[...]
3878  unshare(CLONE_NEWPID)             = 0
3878  execve("/usr/local/sbin/ls", ["ls"], 0x7ffcfb0251b8 /* 27 vars */) = -1 ENOENT (No such file or directory)
3878  execve("/usr/local/bin/ls", ["ls"], 0x7ffcfb0251b8 /* 27 vars */) = -1 ENOENT (No such file or directory)
3878  execve("/usr/bin/ls", ["ls"], 0x7ffcfb0251b8 /* 27 vars */) = 0
3878  brk(NULL)
[...]       
```

Here the pid at the start of the line confirms that `unshare` simply calls `execve` immediately while still being the same process.

In the following trace the `unshare` command calls `clone` (basically `fork` with fine-grained controls) and only executes `execve` after creating a new process (`3805` -> `3806`).

```bash
$ strace --follow-forks unshare --pid --fork ls
[...]
3805  unshare(CLONE_NEWPID)             = 0
3805  rt_sigprocmask(SIG_BLOCK, [INT TERM], [], 8) = 0
3805  clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f77911a7a10) = 3806
3805  wait4(3806,  <unfinished ...>
3806  set_robust_list(0x7f77911a7a20, 24) = 0
3806  rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
3806  execve("/usr/local/sbin/ls", ["ls"], 0x7ffe4e825060 /* 27 vars */) = -1 ENOENT (No such file or directory)
3806  execve("/usr/local/bin/ls", ["ls"], 0x7ffe4e825060 /* 27 vars */) = -1 ENOENT (No such file or directory)
3806  execve("/usr/bin/ls", ["ls"], 0x7ffe4e825060 /* 27 vars */) = 0
3806  brk(NULL)
[...]
3806  +++ exited with 0 +++
3805  <... wait4 resumed>[{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 3806
[...]
```

#### **why does f*rking help**

Commands we execute there (e.g. the `ls -la`) will have a parent process in the same namespace (i.e. `bash`).

Without `fork` (i.e. with `execve`), commands that we execute in our unshared pid namespace would have no parent process which lives in the same namspace, Linux doesn't like this (having a pid namespace without a PID 1) and so we cannot allocate memory.

From the `execve` manpage:

```text
  Effect on process attributes
       All process attributes are preserved during an execve(), except the following:
```

if you've a look at this man page yourself you'll see that namespaces aren't mentioned here -> they are preserved.

`fork` doesn't mention namespaces explicitly either, but we know that fork creates a new process and that `pid_for_children` is the new namespace for our `unshare` process.

excerpt from the `pid_namespaces` man page:

```text
If the "init" process of a PID namespace terminates, the kernel terminates all of the processes in the namespace via a SIGKILL signal.  This behavior reflects the fact that the "init" process is  essential for the correct operation of a PID namespace.  In this case, a subsequent fork(2) into this PID namespace fail with the error ENOMEM; it is notv possible to create a new process in a PID namespace whose "init" process has terminated.  Such scenarios can occur when, for example, a process uses an open file descriptor for a /proc/pid/ns/pid file corresponding to a process  that  was  in  a namespace  to  setns(2)  into  that  namespace  after  the "init" process has terminated.  Another possible scenario can occur after a call to unshare(2): if the first child subsequently created by a fork(2) terminates, then subsequent calls to fork(2) fail with ENOMEM.

Only signals for which the "init" process has established a signal handler can be sent to the "init" process by other members of the PID namespace.  This restriction applies even to  privileged  processes, and prevents other members of the PID namespace from accidentally killing the "init" process.
```

> note the `a subsequent fork(2) into this PID namespace fail with the error ENOMEM`.

#### **TODO: rewrite in rust**

```c
#include <stdio.h>
#include <unistd.h>

int main() {
  printf("%d -> %d\n", (int)getppid(), (int)getpid());

  return 0;
}

```

compile this c program with a compiler of your choice and let's execute this:

```bash
$ sudo unshare --pid --fork ./a.out
0 -> 1 # new namespace
$ sudo unshare --pid ./a.out
23767 -> 23768 # old namespace
```

#### **disappointment**

so, we now know that with `--fork` we are pid 1 in our new namespace.

If we have a look at our current processes we should only see the process which we pass to unshare since this is our PID 1, correct?

```bash
$0> sudo unshare --pid --fork bash
$ ./a.out
1 -> 3 # bash is our parent process with PID 1
$1> ps -ef
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 14:46 ?        00:00:02 /usr/lib/systemd/systemd --switched-root --system --de
root           2       0  0 14:46 ?        00:00:00 [kthreadd]
root           3       2  0 14:46 ?        00:00:00 [rcu_gp]
root           4       2  0 14:46 ?        00:00:00 [rcu_par_gp]
[...]
```

well, `ps` thinks that `systemd` is our root process in this namespace (PID 1).

let's have a look at what `ps` is doing to retrieve processes.

`strace` will become your friend at some point, just trust me on this.

<details>
<summary>strace --trace=openat ps</summary>
```bash
$1> strace --trace=openat ps 2>&1 | head -n 50
[...] # ps setup
openat(AT_FDCWD, "/proc/sys/kernel/pid_max", O_RDONLY) = 4
openat(AT_FDCWD, "/proc/sys/kernel/osrelease", O_RDONLY) = 4
openat(AT_FDCWD, "/proc/meminfo", O_RDONLY) = 4
openat(AT_FDCWD, "/proc", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 5
openat(AT_FDCWD, "/proc/1/stat", O_RDONLY) = 6
openat(AT_FDCWD, "/proc/1/status", O_RDONLY) = 6
openat(AT_FDCWD, "/proc/2/stat", O_RDONLY) = 6
openat(AT_FDCWD, "/proc/2/status", O_RDONLY) = 6
openat(AT_FDCWD, "/proc/3/stat", O_RDONLY) = 6
openat(AT_FDCWD, "/proc/3/status", O_RDONLY) = 6
openat(AT_FDCWD, "/proc/4/stat", O_RDONLY) = 6
openat(AT_FDCWD, "/proc/4/status", O_RDONLY) = 6
openat(AT_FDCWD, "/proc/5/stat", O_RDONLY) = 6
openat(AT_FDCWD, "/proc/5/status", O_RDONLY) = 6
openat(AT_FDCWD, "/proc/6/stat", O_RDONLY) = 6
openat(AT_FDCWD, "/proc/6/status", O_RDONLY) = 6
openat(AT_FDCWD, "/proc/8/stat", O_RDONLY) = 6
openat(AT_FDCWD, "/proc/8/status", O_RDONLY) = 6
openat(AT_FDCWD, "/proc/10/stat", O_RDONLY) = 6
openat(AT_FDCWD, "/proc/10/status", O_RDONLY) = 6
openat(AT_FDCWD, "/proc/12/stat", O_RDONLY) = 6
openat(AT_FDCWD, "/proc/12/status", O_RDONLY) = 6
openat(AT_FDCWD, "/proc/13/stat", O_RDONLY) = 6
openat(AT_FDCWD, "/proc/13/status", O_RDONLY) = 6
```

</details>

`ps` reads from `/proc`, while we do have a new pid namespace, we still have the same filesystem (you may've noticed this when doing `ls` inside and outside of our unshared namespace).

With our process in another namespace accessing `/proc/$$/*` doesn't work anymore since we'd access the pid from the root namespace.

note that the `/proc/self` is still valid:

```bash
$0> unshare --pid --fork bash
$1> ls -l /proc/ | grep "self ->"
lrwxrwxrwx  1 root             root                           0 11. Mai 20:01 self -> 23105
```

### mount namespace

Since we know that `/proc` is just a virtual filesystem which is conveniently mounted by systemd for us, let's try to "overmount" it in a new mount namespace

```bash
$0> unshare --pid --fork --mount bash
$1> ls /proc/ -l | head -n 5
total 0
dr-xr-xr-x  9 root             root                           0 10. Mai 16:46 1
dr-xr-xr-x  9 root             root                           0 10. Mai 16:46 10
dr-xr-xr-x  9 root             root                           0 10. Mai 16:46 100
dr-xr-xr-x  9 root             root                           0 10. Mai 16:46 101
dr-xr-xr-x  9 root             root                           0 10. Mai 16:46 102
```

This is what we saw before, just our `/proc` filesystem from our "parent" namespace

```bash
$1> mount -t proc proc /proc
$1> ls -l /proc | head -n 5
total 0
dr-xr-xr-x  9 root root               0 10. Mai 17:26 1
dr-xr-xr-x  9 root root               0 10. Mai 17:26 12
dr-xr-xr-x  9 root root               0 10. Mai 17:26 13
dr-xr-xr-x  4 root root               0 10. Mai 17:26 acpi
$0> ls -l /proc | head -n 5
total 0
dr-xr-xr-x  9 root             root                           0 10. Mai 16:46 1
dr-xr-xr-x  9 root             root                           0 10. Mai 16:46 10
dr-xr-xr-x  9 root             root                           0 10. Mai 16:46 100
dr-xr-xr-x  9 root             root                           0 10. Mai 16:46 101
```

Similar to the `pid` and `uts` namespace we observe that we now see different files in `/proc` for different namespaces after we've remounted it.

The "parent" namespace still has the same `/proc` system as before.

Checking out the mount information in both namespaces:

```bash
$0> sudo mount | grep "/proc type proc"
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)

$1> sudo mount | grep "/proc type proc"
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime) # root proc
proc on /proc type proc (rw,relatime) # our namespaced /proc
```

We also observe that we don't lose access to the root mount namespace, this is because unshare copies the mount list from the previous mount namespace.

`unshare` has the convenient `--mount-proc` argument (implies `--mount`), when setting this `unshare` will setup a new `/proc` mount for us before dropping us into the namespace.

```bash
$ unshare --fork --pid --mount-proc ls /proc | head -n 2
1
acpi
```

#### **where `mount` retrieves the information from

```bash
$ cat /proc/$$/mounts | head -n 5
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
devtmpfs /dev devtmpfs rw,nosuid,size=4096k,nr_inodes=4054021,mode=755,inode64 0 0
securityfs /sys/kernel/security securityfs rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev,inode64 0 0
```

This is pretty much what we see if we simply list our mounts

<details>
<summary><pre style="display: inline;">mount</pre></summary>

```bash
$ mount | head -n 5
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)
devtmpfs on /dev type devtmpfs (rw,nosuid,size=4096k,nr_inodes=4054021,mode=755,inode64)
securityfs on /sys/kernel/security type securityfs (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,inode64)
```

</details>

Does mount read from `/proc/$$/mounts` though?

<details>
<summary>strace answer</summary>

```bash
$ strace -e trace=openat mount
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/libmount.so.1", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/libblkid.so.1", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/proc/self/mountinfo", O_RDONLY|O_CLOEXEC) = 3
```

No, mount reads from `/proc/self/mountinfo` which looks like this

```bash
$ cat /proc/$$/mountinfo | head -n 5
20 107 0:19 / /proc rw,nosuid,nodev,noexec,relatime shared:26 - proc proc rw
21 107 0:20 / /sys rw,nosuid,nodev,noexec,relatime shared:2 - sysfs sysfs rw
22 107 0:5 / /dev rw,nosuid shared:22 - devtmpfs devtmpfs rw,size=4096k,nr_inodes=4054021,mode=755,inode64
23 21 0:6 / /sys/kernel/security rw,nosuid,nodev,noexec,relatime shared:3 - securityfs securityfs rw
24 22 0:21 / /dev/shm rw,nosuid,nodev shared:23 - tmpfs tmpfs rw,inode64
```

</details>

```bash
$0> unshare -m bash
$1> mount -t tmpfs tmpfs /mnt
$1> touch /mnt/myspace
$0> ls /mnt
# no myspace :(
$1> ls /mnt
myspace
$0> ps -C bash
    PID TTY          TIME CMD
  16255 pts/2    00:00:00 bash
$0> nsenter -t 16255 -m ls /mnt
myspace
```

**TODO** talk about peer groups (slave, unbindable, [...])

### combining pid and mount

Now that we know how to setup a new `/proc` mount we can incorporate this into our pid-namespace to make `ps` behave correctly:

```bash
$0> sudo unshare --pid --fork --mount-proc bash
$0> ps -ef | grep bash
root        5466    1481  0 20:09 pts/0    00:00:00 sudo unshare --pid --fork --mount-proc bash
root        5467    5466  0 20:09 pts/0    00:00:00 unshare --pid --fork --mount-proc bash
root        5468    5467  0 20:09 pts/0    00:00:00 bash

$1> ps -ef
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 13:01 pts/0    00:00:00 bash
root           3       1  0 13:02 pts/0    00:00:00 ps -ef
```

#### nesting

We've done `unshare` inside of our root namespace up to now, what happens if we execute `unshare` inside a new namespace?

```bash
$1> sudo unshare --pid --fork --mount-proc bash

$0> ps -ef | grep bash
root        5466    1481  0 20:09 pts/0    00:00:00 sudo unshare --pid --fork --mount-proc bash
root        5467    5466  0 20:09 pts/0    00:00:00 unshare --pid --fork --mount-proc bash
root        5468    5467  0 20:09 pts/0    00:00:00 bash
root        5660    5468  0 20:10 pts/0    00:00:00 sudo unshare --pid --fork --mount-proc bash
root        5661    5660  0 20:10 pts/0    00:00:00 unshare --pid --fork --mount-proc bash
root        5662    5661  0 20:10 pts/0    00:00:00 bash

$1> sudo unshare --pid --fork --mount-proc bash
$1> ps -ef # by doing nsenter --target {pid of $1/bash} --all ps -ef
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 13:01 pts/0    00:00:00 bash
root           5       1  0 13:04 pts/0    00:00:00 sudo unshare --pid --fork --mount-proc bash
root           6       5  0 13:04 pts/0    00:00:00 unshare --pid --fork --mount-proc bash
root           7       6  0 13:04 pts/0    00:00:00 bash
root           8       0  0 13:04 pts/1    00:00:00 ps -ef

$2> ps -ef
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 13:04 pts/0    00:00:00 bash
root           2       1  0 13:05 pts/0    00:00:00 ps -ef
```

Nesting namespaces doesn't seem to be a problem and behaves as we could've expected (the same as in the root namespace).

There is a limit when nesting user namespaces, the maximum nesting limit is 32.

#### checking all PIDs for a process

Since a process can have several PIDs in several namespaces it might be handy to see them all, all PIDs for a process can be found in `/proc/pid/status`

```bash
$0> cat /proc/5468/status | grep NSpid
NSpid:	5468	1

$0> cat /proc/5662/status | grep NSpid
NSpid:	5662	7	1
```

Nesting PIDs go from left to right (`{root namespace} {ns1} {ns2} [...]`)

(block keeps IDs (`${id}>`) from above)

```bash
$0> nsenter --target 5468 --all
$1> cat /proc/7/status | grep NSpid
NSpid:	7	1
$1> cat /proc/7/cmdline
bash

$2> cat /proc/1/status | grep NSpid
NSpid:	1
```

### ips namespace

Quick and dirty, the `ips` namespace is mostly about System V features such as shared memory or shared semaphores.

> ipcs shows information on System V inter-process communication facilities. By default it shows information about all three resources: shared memory segments, message queues, and semaphore arrays.

\- man-page

<details>
<summary>ipcs output for different namespaces</summary>

```bash
$ ipcs
------ Message Queues --------
key        msqid      owner      perms      used-bytes   messages

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x51300022 3          torben     600        16         1
0xca040002 4          torben     600        65536      1
0x00000000 7          torben     600        69632      2          dest
[...]
------ Semaphore Arrays --------
key        semid      owner      perms      nsems
0xcc040002 2          torben     600        1
0xcb040002 3          torben     600        1

$ sudo unshare --ipc ipcs

------ Message Queues --------
key        msqid      owner      perms      used-bytes   messages

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status

------ Semaphore Arrays --------
key        semid      owner      perms      nsems
```

</details>

### net namespace

A fairly common want is to separate a process from the network completely or to limit it in a certain way.

Another point is that, especially when running multiple webservers, you don't want to care about which process is running on which port and whether they might overlap.

Currently, if we try to run two processes which listen on the same port we get this (`python -m http.server` (omitted stacktrace)):

```
OSError: [Errno 98] Address already in use
```

Let's try executing the second server in a new net namespace:

```bash
$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
$ unshare --net python -m http.server
Serving HTTP on :: port 8000 (http://[::]:8000/) ...
```

The second info simply shows us that the python server is listening on the IPv6 address which is equivalent to IPv4s 0.0.0.0 (`::` omits `0` blocks for IPv6 addresses).

But why is this the case?

Let's have a quick look at the interfaces for our new namespace:

```bash
$ unshare --net ip a
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
```

Well, apparently we only have a loopback interface, we won't get a lot of use out of it if we want to connect to it from the outside.

#### **creating a namespace which isn't bound to a process**

Since we might want to connect multiple processes to a single net namespace or preserve a namespace across process restarts we want to create a namespace which isn't bound to a PID.

We're using a separate command for creating our namespace here since it'll make following along a bit easier.

This step isn't necessary and an alternative is talked about below.

```bash
$ ip netns add demons
```

#### **where do the demons live**

**TODO**: talk about nsfs

```bash
$ ls -l /var/run/netns
.r--r--r-- 0 root 12 Mai 09:23 demons
```

#### **setting up interfaces**

First we're going to set-up a virtual interface with a peer.

We're gonna name the virtual interfaces `veth0` for our host and `neth0` for the interface which will reside in our namespace.

```bash
$ ip link add veth0 type veth peer name neth0
$ ip a | grep neth -A 4
5: neth0@veth0: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 42:5f:6d:66:a3:d5 brd ff:ff:ff:ff:ff:ff
6: veth0@neth0: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether b2:5a:06:5f:cf:9b brd ff:ff:ff:ff:ff:ff
```

> Peered interfaces are always displayed as `{name}@{name or if{id}}: [...]`

Both interfaces are now in our root namespace, we can assign the interface to a namespace via the `ip` command:

```bash
$ ip link set neth0 netns demons
$ ip a | grep neth
# no output

$ ip a | grep veth
6: veth0@if5: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether b2:5a:06:5f:cf:9b brd ff:ff:ff:ff:ff:ff link-netns demons
```

#### separating our interfaces

We notice that our peer was renamed to `if5` instead of `neth0`, this is simply because interface IDs are globally unique while names are only unique in namespaces.

With this id you can also track an interface across namespaces.

`ip netns exec` is a shorthand for `nsenter --net=/var/run/netns/{netnsname}`

> when using `unshare --net bash` you can also use the net namespace file at `/proc/pid/ns/net` (pid=pid for bash in root namespace) 

```bash
$ ip netns exec demons ip a
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
5: neth0@if6: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 42:5f:6d:66:a3:d5 brd ff:ff:ff:ff:ff:ff link-netnsid 0
```

```bash
$ ip netns exec demons ping 127.0.0.1
ping: connect: Network is unreachable
```

while the namespace did create the `lo` interface by itself, we have no `NetworkManager` (or similar) to manage this interface.

So we have to bring it up ourselves:
```bash
$ ip netns exec demons ip link set lo up
$ ip netns exec demons ping 127.0.0.1
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.014 ms
```

#### **everyone gets an IP address**

Next, we want to connect from one interface to the other, for this to work we need to assign IPs to our interfaces and bring them up (same as we did with the `lo` interface).

```bash
$ ip addr add 172.16.0.2/24 dev veth0
$ ip a
6: veth0@if5: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether b2:5a:06:5f:cf:9b brd ff:ff:ff:ff:ff:ff link-netns demons
    inet 172.16.0.2/24 scope global veth0
       valid_lft forever preferred_lft forever

$ ip netns exec demons ip addr add 172.16.0.3/24 dev neth0
$ ip netns exec demons ip a
5: neth0@if6: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 42:5f:6d:66:a3:d5 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.16.0.2/24 scope global neth0
       valid_lft forever preferred_lft forever

$ ip link set veth0 up
$ ip netns exec demons ip link set neth0 up
```

#### **talk to me baby**

```bash
$ ping 172.16.0.3
PING 172.16.0.3 (172.16.0.3) 56(84) bytes of data.
64 bytes from 172.16.0.3: icmp_seq=1 ttl=64 time=0.119 ms

$ ip netns exec demons ping 172.16.0.2
PING 172.16.0.2 (172.16.0.2) 56(84) bytes of data.
64 bytes from 172.16.0.2: icmp_seq=1 ttl=64 time=0.056 ms
```

#### **I don't want to share my database**

Let's say you're running your backend and database on the same server.

While you obviously want to connect to the database with your backend, you might not want others to be able to do so.

Since we want both processes isolated in their own net namespace, we need to connect these two namespaces.

First, let's setup a second namespace (we'll run our server in our `demons` namespace):

```bash
$ ip netns add database
$ ip link add veth1 type veth peer name neth1
$ ip link set neth1 netns database

$ ip netns exec database ip link set lo up
$ ip netns exec database ip link set neth1 up

$ ip link set veth1 up

$ ip addr add 172.16.0.4/24 dev veth1
$ ip netns exec database ip addr add 172.16.0.5/24 dev neth0
```

#### **pinging all namespaced interfaces**

```bash
$ ping 172.16.0.3
PING 172.16.0.3 (172.16.0.3) 56(84) bytes of data.
64 bytes from 172.16.0.3: icmp_seq=1 ttl=64 time=0.034 ms

$ ping 172.16.0.5
PING 172.16.0.5 (172.16.0.5) 56(84) bytes of data.
From 172.16.0.2 icmp_seq=1 Destination Host Unreachable
```

so... why can't we ping the second interface?

Let's have a quick look at the routing table:

```bash
$ ip route
default via 192.168.2.1 dev wlan0 proto dhcp src 192.168.2.55 metric 600
172.16.0.0/24 dev veth0 proto kernel scope link src 172.16.0.2
172.16.0.0/24 dev veth1 proto kernel scope link src 172.16.0.4
192.168.2.0/24 dev wlan0 proto kernel scope link src 192.168.2.55 metric 600
```

we have 2 routes for `172.16.0.0/24` on 2 different interfaces, since the first route is always preferred ping tries to connect to our database IP via the backend IP.

These two can't talk to each other yet since we don't have any connection (e.g. peered interfaces) between them. 

We can instruct ping to use a specific interface though via `-I`:

```bash
PING 172.16.0.5 (172.16.0.5) from 172.16.0.4 veth1: 56(84) bytes of data.
64 bytes from 172.16.0.5: icmp_seq=1 ttl=64 time=0.057 ms
```

this works, so setting up multiple interfaces in different namespaces is fine as long as we're careful about how we connect to them.

To let these 2 network interfaces talk to each other, we'll setup a bridge:

```bash
$ ip link add name br0 type bridge
$ ip addr add 172.16.0.100/24 brd + dev br0
$ ip link set br0 up
```

Next we're going to connect our virtual interfaces to the bridge:

```bash
$ ip link set veth0 master br0
$ ip link set veth1 master br0
$ bridge link show br
$ ip a
[...]
# note the br0 v
14: veth0@if13: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br0 state UP group default qlen 1000
[...]
# note the br0 v
16: veth1@if15: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br0 state UP group default qlen 1000
[...]
17: br0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 0e:c3:2f:5d:55:1f brd ff:ff:ff:ff:ff:ff
    inet 172.16.0.100/24 brd 172.16.0.255 scope global br0
       valid_lft forever preferred_lft forever
    inet6 fe80::cc3:2fff:fe5d:551f/64 scope link
       valid_lft forever preferred_lft forever
```

we now have a bridge which is connected to both our veth devices.

**TODO**: explicitly show that the ping below doesn't work without the bridge

#### **ping ping ping**

```bash
$ ip netns exec database ping 172.16.0.3
PING 172.16.0.3 (172.16.0.3) 56(84) bytes of data.
64 bytes from 172.16.0.3: icmp_seq=1 ttl=64 time=0.053 ms
```

pinging our database interface is still not possible though:

```bash
PING 172.16.0.5 (172.16.0.5) from 172.16.0.4 veth1: 56(84) bytes of data.
64 bytes from 172.16.0.5: icmp_seq=1 ttl=64 time=0.057 ms
```

let's have a look at our routes again:

```bash
default via 192.168.2.1 dev wlan0 proto dhcp src 192.168.2.55 metric 600
172.16.0.0/24 dev veth0 proto kernel scope link src 172.16.0.2
172.16.0.0/24 dev veth1 proto kernel scope link src 172.16.0.4
172.16.0.0/24 dev br0 proto kernel scope link src 172.16.0.100
192.168.2.0/24 dev wlan0 proto kernel scope link src 192.168.2.55 metric 600
```

Since the old non-bridge routes are still there, we're simply going to delete them:

```bash
sudo ip route delete 172.16.0.0/24 dev veth0
sudo ip route delete 172.16.0.0/24 dev veth1
```

and now we're able to ping both IPs in namespaces connected to the bridge

```bash
$ ping 172.16.0.3
PING 172.16.0.3 (172.16.0.3) 56(84) bytes of data.
64 bytes from 172.16.0.3: icmp_seq=1 ttl=64 time=0.105 ms

$ ping 172.16.0.5
PING 172.16.0.5 (172.16.0.5) 56(84) bytes of data.
64 bytes from 172.16.0.5: icmp_seq=1 ttl=64 time=0.061 ms

$ ip route
default via 192.168.2.1 dev wlan0 proto dhcp src 192.168.2.55 metric 600
172.16.0.0/24 dev br0 proto kernel scope link src 172.16.0.100
192.168.2.0/24 dev wlan0 proto kernel scope link src 192.168.2.55 metric 600 
```

#### **let me be your guide to the internet**

Since our backend might want to connect to the outside world, we should check whether this is possible:

```bash
$ sudo ip netns exec demons ping 1.1
ping: connect: Network is unreachable

$ sudo ip netns exec demons ip route
172.16.0.0/24 dev neth0 proto kernel scope link src 172.16.0.3
```

Seems like we can't connect to the outside world.

When looking at the routing table we observe that we don't have a route for `1.0.0.1`.

We want to add a default route which uses the bridge as the default gateway since the veth devices are connected to it.

```bash
$ ip netns exec demons ip route add default 172.16.0.100
$ ip netns exec demons ip route
default via 172.16.0.100 dev neth0
172.16.0.0/24 dev neth0 proto kernel scope link src 172.16.0.3

$ ping 1.1
PING 1.1 (1.0.0.1) 56(84) bytes of data.
[...]
^C
--- 1.1 ping statistics ---
16 packets transmitted, 0 received, 100% packet loss, time 15213ms
```

While we can transmit outbound packets, apparently we can't get any incoming packages.

Let's have a quick look at tcpdump:


(the next few code blocks which use tcpdump will use `${id}>` to denote different terminals, not namespaces)

```bash
$0> tcpdump -i veth0
listening on veth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
09:05:13.617057 IP 172.16.0.3 > one.one.one.one: ICMP echo request, id 58067, seq 1, length 64
09:05:14.629357 IP 172.16.0.3 > one.one.one.one: ICMP echo request, id 58067, seq 2, length 64
09:05:15.642648 IP 172.16.0.3 > one.one.one.one: ICMP echo request, id 58067, seq 3, length 64

$1> sudo ip netns exec demons ping 1.1
PING 1.1 (1.0.0.1) 56(84) bytes of data.
^C
--- 1.1 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2022ms
```

What're we missing?

Normally we would expect a ICMP reply, checking this on our host:

```bash
$0> tcpdump src 1.0.0.1 or dst 1.0.0.1 and icmp
listening on wlan0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
09:11:29.138072 IP torben-xps9320 > one.one.one.one: ICMP echo request, id 22, seq 1, length 64
09:11:29.188307 IP one.one.one.one > torben-xps9320: ICMP echo reply, id 22, seq 1, length 64
09:11:30.139337 IP torben-xps9320 > one.one.one.one: ICMP echo request, id 22, seq 2, length 64
09:11:30.191649 IP one.one.one.one > torben-xps9320: ICMP echo reply, id 22, seq 2, length 64
09:11:31.141023 IP torben-xps9320 > one.one.one.one: ICMP echo request, id 22, seq 3, length 64
09:11:31.196535 IP one.one.one.one > torben-xps9320: ICMP echo reply, id 22, seq 3, length 64

$1> ping 1.1
```

As stated before, the NetworkManager isn't controlling our new self-made LAN.

This means that NetworkManager has neither setup any iptable rules and thus we don't have a NAT for our LAN.

One way of enabling different LANs on a linux machine to reach out to the internet is via `MASQUERADING`, this is basically Linuxs way to do NAT.

```bash
$ sysctl -w net.ipv4.ip_forward=1
$ iptables -t nat -A POSTROUTING -s 172.16.0.0/24 -j MASQUERADE
$ ip netns exec demons ping 1.1
PING 1.1 (1.0.0.1) 56(84) bytes of data.
64 bytes from 1.0.0.1: icmp_seq=1 ttl=57 time=135 ms
64 bytes from 1.0.0.1: icmp_seq=2 ttl=57 time=283 ms
64 bytes from 1.0.0.1: icmp_seq=3 ttl=57 time=52.6 ms
```

> note: make sure that the ip_forward value isn't overriden in `/etc/sysctl.conf`, otherwise you'l lose this setting on the next reboot

Why the `ip_forward=1`, per default the kernel rejects any messages of which the destination IP is not configured on the incoming interface.

Let's have a quick look at the tcpdumps for pinging `1.1` with `ip_forward=0` and `ip_forward=1`:

```bash
$0> sysctl -w net.ipv4.ip_forward=0
$0> ip netns exec demons ping 1.1
$1 tcpdump -i any src 1.0.0.1 or dst 1.0.0.1 and icmp
listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes
09:24:43.893068 veth0 P   IP 172.16.0.3 > one.one.one.one: ICMP echo request, id 36300, seq 1, length 64
09:24:43.893068 br0   In  IP 172.16.0.3 > one.one.one.one: ICMP echo request, id 36300, seq 1, length 64
```

We see that the "can transmit" has a catch, while we can go out from our interface, our packet stops on our bridge interface and is rejected (not visible in the tcpdump) by our default interface (`wlan0` currently for me). So `ip_forward` isn't only concerning incoming packets, but outgoing packets as well (since both are incoming for our default interface).

```bash
$0> sysctl -w net.ipv4.ip_forward=1
$0> ip netns exec demons ping 1.1
$1> tcpdump -i any src 1.0.0.1 or dst 1.0.0.1 and icmp
listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes
09:25:08.442557 veth0 P   IP 172.16.0.3 > one.one.one.one: ICMP echo request, id 22358, seq 1, length 64
09:25:08.442557 br0   In  IP 172.16.0.3 > one.one.one.one: ICMP echo request, id 22358, seq 1, length 64
09:25:08.442602 wlan0 Out IP torben-xps9320 > one.one.one.one: ICMP echo request, id 22358, seq 1, length 64
09:25:08.492767 wlan0 In  IP one.one.one.one > torben-xps9320: ICMP echo reply, id 22358, seq 1, length 64
09:25:08.492816 br0   Out IP one.one.one.one > 172.16.0.3: ICMP echo reply, id 22358, seq 1, length 64
09:25:08.492826 veth0 Out IP one.one.one.one > 172.16.0.3: ICMP echo reply, id 22358, seq 1, length 64
```

With `ip_forward=1` the tcpdump is pretty much as expected, our packet travels outbound via `veth0` -> `br0` -> `wlan0` (default interface) and comes in on the same route (obviously backwards).

Let's take a small break from the network namespace and focus on a different namespace.

### user namespaces

```bash
$ unshare id
uid=1000(torben) gid=1000(torben) groups=1000(torben),3(sys),982(rfkill),998(wheel)
$ unshare --user id
uid=65534(nobody) gid=65534(nobody) groups=65534(nobody)
$ unshare --user ls -ln
-rw-r--r-- 1 65534 65534  41335 15. Mai 12:11 README.md
$ unshare --user /bin/ls / -lna | grep ' \.$'
drwxr-xr-x  17 65534 65534  4096 29. Mär 19:53 .
```

We observe that all files are now shown as if the user rights were `nobody:nogroup`.

When testing this (e.g. by writing to `/`) we see that this is not actually true

```bash
$ touch /test.txt
touch: cannot touch '/test.txt': Permission denied
$ cat /proc/bashpid/uid_map
# <EMPTY>
```

comparing the `uid_map` to a non-namespaces `uid_map`

```bash
$ cat /proc/self/uid_map
# ID-inside     ID-outside      length
0               0               4294967295
```

The `uid_map` file maps uid regions from the callee's namespace to the current namespace.

In the case above, we start in our namespace with user id 0 (first `0`), and map 4294967295 ID's from the parent namespace into ours, starting at user id 0 (second `0`).

> How does the permission check work?
>
> For checking permissions the internal uid is mapped to that on the parent namespace, permission are checked from there recursively (in case of namespace nesting).

# TODO: continue on user namespaces

## control groups (cgroups)

cgroups also allow us to separate certain resources for a threads, processes or a group of processes.

> Control  groups, usually referred to as cgroups, are a Linux kernel feature which allow processes to be organized into hierarchical groups whose usage of various types of resources can then be limited and monitored.
> The kernel's cgroup interface is provided through a pseudo-filesystem called cgroupfs.
> Grouping is implemented in the core cgroup kernel code, while resource tracking and limits are implemented in a set of per-resource-type subsystems (memory, CPU, and so on).

\- man cgroups

### cgroups v1 vs cgroups v2

# TODO

### cgroups v1 overview

https://www.kernel.org/doc/Documentation/admin-guide/cgroup-v1/

#### cpu

#### cpuacct

#### cpuset

#### memory

#### devices

#### freezer

#### net_cls

#### blkio

#### perf_event

#### net_prio

#### hugetlb

#### pids

#### rdma


### create a v1 cgroup

First we create a cgroup with the helper command `cgcreate` (we'll do this manually later on).

The minimal amount of arguments to `cgcreate` is a cgroup and the name (path to be exact) for our cgroup.

```bash
$ cgcreate -g memory:tcg1
```

so, where do these cgroups live and how can we access them?

Similar to the `proc` fs we also have a special `cgroup` fs

```bash
$ mount -t cgroup
cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,xattr,name=systemd)
cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,hugetlb)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,net_cls,net_prio)
cgroup on /sys/fs/cgroup/memory type cgroup (rw,nosuid,nodev,noexec,relatime,memory)
cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,perf_event)
cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,blkio)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,cpuset)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (rw,nosuid,nodev,noexec,relatime,cpu,cpuacct)
cgroup on /sys/fs/cgroup/rdma type cgroup (rw,nosuid,nodev,noexec,relatime,rdma)
cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,pids)
cgroup on /sys/fs/cgroup/misc type cgroup (rw,nosuid,nodev,noexec,relatime,misc)
cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,freezer)
```

# TODO: explain cgroupfs mounts

Having a look at the memory cgroup we see the following (here we see why the part behind the colon in `cgcreate` is actually the path).

I've "highlighted" the `tcg1` directory, we'll explore this below 

<details>

<summary><pre style="display: inline;">ls -l /sys/fs/cgroup/memory</pre></summary>

```bash
$ ls -l /sys/fs/cgroup/memory
.rw-r--r-- 0 root 13 Jun 16:20 cgroup.clone_children
.-w--w--w- 0 root 13 Jun 16:20 cgroup.event_control
.rw-r--r-- 0 root 13 Jun 16:00 cgroup.procs
.r--r--r-- 0 root 13 Jun 16:20 cgroup.sane_behavior
drwxr-xr-x - root 13 Jun 16:00 dev-hugepages.mount
drwxr-xr-x - root 13 Jun 16:00 dev-mqueue.mount
drwxr-xr-x - root 13 Jun 16:00 init.scope
.rw-r--r-- 0 root 13 Jun 16:20 memory.failcnt
.-w------- 0 root 13 Jun 16:20 memory.force_empty
.rw-r--r-- 0 root 13 Jun 16:20 memory.kmem.failcnt
.rw-r--r-- 0 root 13 Jun 16:20 memory.kmem.limit_in_bytes
.rw-r--r-- 0 root 13 Jun 16:20 memory.kmem.max_usage_in_bytes
.r--r--r-- 0 root 13 Jun 16:20 memory.kmem.slabinfo
.rw-r--r-- 0 root 13 Jun 16:20 memory.kmem.tcp.failcnt
.rw-r--r-- 0 root 13 Jun 16:20 memory.kmem.tcp.limit_in_bytes
.rw-r--r-- 0 root 13 Jun 16:20 memory.kmem.tcp.max_usage_in_bytes
.r--r--r-- 0 root 13 Jun 16:20 memory.kmem.tcp.usage_in_bytes
.r--r--r-- 0 root 13 Jun 16:20 memory.kmem.usage_in_bytes
.rw-r--r-- 0 root 13 Jun 16:00 memory.limit_in_bytes
.rw-r--r-- 0 root 13 Jun 16:20 memory.max_usage_in_bytes
.rw-r--r-- 0 root 13 Jun 16:20 memory.memsw.failcnt
.rw-r--r-- 0 root 13 Jun 16:20 memory.memsw.limit_in_bytes
.rw-r--r-- 0 root 13 Jun 16:20 memory.memsw.max_usage_in_bytes
.r--r--r-- 0 root 13 Jun 16:20 memory.memsw.usage_in_bytes
.rw-r--r-- 0 root 13 Jun 16:20 memory.move_charge_at_immigrate
.r--r--r-- 0 root 13 Jun 16:20 memory.numa_stat
.rw-r--r-- 0 root 13 Jun 16:20 memory.oom_control
.--------- 0 root 13 Jun 16:20 memory.pressure_level
.rw-r--r-- 0 root 13 Jun 16:20 memory.soft_limit_in_bytes
.r--r--r-- 0 root 13 Jun 16:20 memory.stat
.rw-r--r-- 0 root 13 Jun 16:20 memory.swappiness
.r--r--r-- 0 root 13 Jun 16:20 memory.usage_in_bytes
.rw-r--r-- 0 root 13 Jun 16:00 memory.use_hierarchy
.rw-r--r-- 0 root 13 Jun 16:20 notify_on_release
.rw-r--r-- 0 root 13 Jun 16:20 release_agent
drwxr-xr-x - root 13 Jun 16:00 sys-fs-fuse-connections.mount
drwxr-xr-x - root 13 Jun 16:00 sys-kernel-config.mount
drwxr-xr-x - root 13 Jun 16:00 sys-kernel-debug.mount
drwxr-xr-x - root 13 Jun 16:00 sys-kernel-tracing.mount
drwxr-xr-x - root 13 Jun 16:00 system.slice
.rw-r--r-- 0 root 13 Jun 16:20 tasks
drwxr-xr-x - root 13 Jun 16:19 tcg1 # ===========================================================
drwxr-xr-x - root 13 Jun 16:00 user.slice
```

</details>

Before we explore the complete `/sys/fs/cgroup` directory let's have a look at our own (`tcg1`) cgroup first.

<details>
<summary>ls for tcg1 cgroup</summary>

```bash
$ ls -l /sys/fs/cgroup/memory/tcg1
.rw-r--r-- 0 root 13 Jun 16:19 cgroup.clone_children
.-w--w--w- 0 root 13 Jun 16:19 cgroup.event_control
.rw-r--r-- 0 root 13 Jun 16:19 cgroup.procs
.rw-r--r-- 0 root 13 Jun 16:19 memory.failcnt
.-w------- 0 root 13 Jun 16:19 memory.force_empty
.rw-r--r-- 0 root 13 Jun 16:19 memory.kmem.failcnt
.rw-r--r-- 0 root 13 Jun 16:19 memory.kmem.limit_in_bytes
.rw-r--r-- 0 root 13 Jun 16:19 memory.kmem.max_usage_in_bytes
.r--r--r-- 0 root 13 Jun 16:19 memory.kmem.slabinfo
.rw-r--r-- 0 root 13 Jun 16:19 memory.kmem.tcp.failcnt
.rw-r--r-- 0 root 13 Jun 16:19 memory.kmem.tcp.limit_in_bytes
.rw-r--r-- 0 root 13 Jun 16:19 memory.kmem.tcp.max_usage_in_bytes
.r--r--r-- 0 root 13 Jun 16:19 memory.kmem.tcp.usage_in_bytes
.r--r--r-- 0 root 13 Jun 16:19 memory.kmem.usage_in_bytes
.rw-r--r-- 0 root 13 Jun 16:19 memory.limit_in_bytes
.rw-r--r-- 0 root 13 Jun 16:19 memory.max_usage_in_bytes
.rw-r--r-- 0 root 13 Jun 16:19 memory.memsw.failcnt
.rw-r--r-- 0 root 13 Jun 16:19 memory.memsw.limit_in_bytes
.rw-r--r-- 0 root 13 Jun 16:19 memory.memsw.max_usage_in_bytes
.r--r--r-- 0 root 13 Jun 16:19 memory.memsw.usage_in_bytes
.rw-r--r-- 0 root 13 Jun 16:19 memory.move_charge_at_immigrate
.r--r--r-- 0 root 13 Jun 16:19 memory.numa_stat
.rw-r--r-- 0 root 13 Jun 16:19 memory.oom_control
.--------- 0 root 13 Jun 16:19 memory.pressure_level
.rw-r--r-- 0 root 13 Jun 16:19 memory.soft_limit_in_bytes
.r--r--r-- 0 root 13 Jun 16:19 memory.stat
.rw-r--r-- 0 root 13 Jun 16:19 memory.swappiness
.r--r--r-- 0 root 13 Jun 16:19 memory.usage_in_bytes
.rw-r--r-- 0 root 13 Jun 16:19 memory.use_hierarchy
.rw-r--r-- 0 root 13 Jun 16:19 notify_on_release
.rw-r--r-- 0 root 13 Jun 16:19 tasks
```

</details>

Having a look at all the files, the file which is probably most relevant for a normal application is `memory.limit_in_bytes`

```bash
cat /sys/fs/cgroup/memory/tcg1/memory.limit_in_bytes
9223372036854771712
```

<details>
<summary>explanation for the value from stackexchange</summary>

<blockquote>
The value comes from the cgroup setup in the memory management layer; by default, it’s set to PAGE_COUNTER_MAX, which is LONG_MAX / PAGE_SIZE on 64-bit platforms, and multiplied by PAGE_SIZE again when read.

This confirms ilkkachu’s explanation: the value is the maximum 64-bit signed integer, rounded to the nearest page (by dropping the last bits).
</blockquote>

<blockquote>
That's the highest positive signed 64-bit integer (263-1), rounded down to multiples of 4096 (212), the most common page size on x86 systems. It would seem difficult to get anything higher while avoiding possible confusion between signed and unsigned, so it seems at least a reasonable approximation for infinity.

That said, I don't know for sure, this is just a guess.
</blockquote>

[source](https://unix.stackexchange.com/questions/420906/what-is-the-value-for-the-cgroups-limit-in-bytes-if-the-memory-is-not-restricte)
</details>

This simply means that we've "infinite" memory by default, this is the default behaviour. Processes can allocate memory as long as the system has any memory left.

If we want to constrain our application to a certain memory limit (which it shouldn't reach) then we can write this value into the `memory.limit_in_bytes` file.

```bash
$ echo -n 0 > /sys/fs/cgroup/memory/tcg1/memory.limit_in_bytes
$ cat /sys/fs/cgroup/memory/tcg1/memory.limit_in_bytes
0
```

With this the process we'll execute in this cgroup should be killed immediately since it cannot allocate any memory.

#### executing a process inside a cgroup

We're starting out with a helper command once again, `cgexec` is the equivalent of `nsenter` for cgroups

```bash
$ cgexec memory:tcg1 bash
[1]    32060 killed     sudo cgexec -g memory:tcg1 bash
$ echo $?
137
```

Our command got killed immediately (as suspected).

<details>

<summary>having a closer look at exit code 137</summary>

> When a command terminates on a fatal signal N, bash uses the value of 128+N as the exit status.

\- man bash (`EXIT STATUS` section)

We now need to find the signal with the number 9 (137 - 128 = 9).

We can do this with the kill command

```bash
$ kill -l 9
KILL
```

How do we know that in our case exit code `137` is an oom kill and not something else (I could just as well have sent a `SIGKILL` with `kill -9 {process}`).

Luckily for us the kernel logs all oom kills in it's ring buffer, we can check this with `dmesg`

```bash
$ dmesg
[...]
[ 3777.664404] Memory cgroup out of memory: Killed process 32311 (cgexec) total-vm:7620kB, anon-rss:640kB, file-rss:2432kB, shmem-rss:0kB, UID:0 pgtables:52kB oom_score_adj:0
```

So, while `137` isn't necessarily an OOMError, in this case we've confirmed that it is one.

Most tools (container runtimes, kubernetes, [...]) will provide you with the reason why they've killed the process.

</details>

Let's allow `ls` to allocate 1 MB of memory

```bash
$ sudo sh -c 'echo -n 1000000 > /sys/fs/cgroup/memory/tcg1/memory.limit_in_bytes'
$ sudo cgexec -g memory:tcg1 ls
Downloads  execve.log  projects  tmp  trace.log
```

You might think that `1 MB` is now an acceptable value for maximum memory consumption for `ls`, setting this value for your application should be carefully tested for all use cases though

```bash
$ cgexec -g memory:tcg1 ls -R /
[...]
/etc/wpa_supplicant:
[1]    34293 killed     sudo cgexec -g memory:tcg1 ls -R /
$ dmesg
[ 4751.852361] Memory cgroup out of memory: Killed process 34294 (ls) total-vm:6280kB, anon-rss:256kB, file-rss:2304kB, shmem-rss:0kB, UID:0 pgtables:44kB oom_score_adj:0
```

#### connection between process and cgroup

```bash
$ ps -C bash
    PID TTY          TIME CMD
  35156 pts/0    00:00:00 bash
$ cat /proc/35156/cgroup
13:freezer:/
12:misc:/
11:pids:/user.slice/user-1000.slice/session-2.scope
10:rdma:/
9:cpu,cpuacct:/
8:cpuset:/
7:blkio:/
6:perf_event:/
5:memory:/tcg1
4:net_cls,net_prio:/
3:devices:/user.slice
2:hugetlb:/
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```

We see that the memory cgroup has the `/tcg1` path, in contrast to most other groups having the root (`/`) path.

# TODO: talk more about cgroup mountpoints

I know you've been anxious to finally see strace again, so here we go (I'll spare you the complete output though ;))

```bash
$ strace --trace=openat,write,close cgexec -g memory:tcg1 bash
[...]
openat(AT_FDCWD, "/sys/fs/cgroup/memory//tcg1/tasks", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 3
write(3, "37051", 5)                    = 5
close(3)
[...]
execve("/usr/bin/bash", ["bash"], 0x7ffd0201da30 /* 27 vars */) = 0
[...]
$ ps -C bash
    PID TTY          TIME CMD
  37051 pts/1    00:00:00 bash
$ cat /sys/fs/cgroup/memory/tcg1/tasks
37051
```

We now know that processes are connected via the `tasks` file in the respective cgroup (we'll explore this later on when we create cgroups manually).

Note that `execve` is executed after writing the PID to the tasks file (also keep in mind that `execve` keeps the PID; in constrast to `fork`).

# TODO: not quite correct
> Note: This file is called tasks since `tasks` is what linux calls processes internally

#### cleanup

we can delete our cgroup via the helper command `cgdelete`

```bash
$ cgdelete memory:tcg1
$ stat /sys/fs/cgroup/memory/tcg1
stat: cannot statx '/sys/fs/cgroup/memory/tcg1': No such file or directory
```

### manually creating a cgroup

Manually creating a cgroup is easy since most of the work is done by the kernel for us.

We simply create a directory (name of the cgroup) in the correct control group mount.

```bash
$ cd /sys/fs/cgroup/memory
$ mkdir tcg1
```

<details>
<summary>ls for the memory:tcg1 cgroup</summary>

```bash
$ ls -l tcg1
.rw-r--r-- 0 root 13 Jun 17:25 cgroup.clone_children
.-w--w--w- 0 root 13 Jun 17:25 cgroup.event_control
.rw-r--r-- 0 root 13 Jun 17:25 cgroup.procs
.rw-r--r-- 0 root 13 Jun 17:25 memory.failcnt
.-w------- 0 root 13 Jun 17:25 memory.force_empty
.rw-r--r-- 0 root 13 Jun 17:25 memory.kmem.failcnt
.rw-r--r-- 0 root 13 Jun 17:25 memory.kmem.limit_in_bytes
.rw-r--r-- 0 root 13 Jun 17:25 memory.kmem.max_usage_in_bytes
.r--r--r-- 0 root 13 Jun 17:25 memory.kmem.slabinfo
.rw-r--r-- 0 root 13 Jun 17:25 memory.kmem.tcp.failcnt
.rw-r--r-- 0 root 13 Jun 17:25 memory.kmem.tcp.limit_in_bytes
.rw-r--r-- 0 root 13 Jun 17:25 memory.kmem.tcp.max_usage_in_bytes
.r--r--r-- 0 root 13 Jun 17:25 memory.kmem.tcp.usage_in_bytes
.r--r--r-- 0 root 13 Jun 17:25 memory.kmem.usage_in_bytes
.rw-r--r-- 0 root 13 Jun 17:25 memory.limit_in_bytes
.rw-r--r-- 0 root 13 Jun 17:25 memory.max_usage_in_bytes
.rw-r--r-- 0 root 13 Jun 17:25 memory.memsw.failcnt
.rw-r--r-- 0 root 13 Jun 17:25 memory.memsw.limit_in_bytes
.rw-r--r-- 0 root 13 Jun 17:25 memory.memsw.max_usage_in_bytes
.r--r--r-- 0 root 13 Jun 17:25 memory.memsw.usage_in_bytes
.rw-r--r-- 0 root 13 Jun 17:25 memory.move_charge_at_immigrate
.r--r--r-- 0 root 13 Jun 17:25 memory.numa_stat
.rw-r--r-- 0 root 13 Jun 17:25 memory.oom_control
.--------- 0 root 13 Jun 17:25 memory.pressure_level
.rw-r--r-- 0 root 13 Jun 17:25 memory.soft_limit_in_bytes
.r--r--r-- 0 root 13 Jun 17:25 memory.stat
.rw-r--r-- 0 root 13 Jun 17:25 memory.swappiness
.r--r--r-- 0 root 13 Jun 17:25 memory.usage_in_bytes
.rw-r--r-- 0 root 13 Jun 17:25 memory.use_hierarchy
.rw-r--r-- 0 root 13 Jun 17:25 notify_on_release
.rw-r--r-- 0 root 13 Jun 17:25 tasks
```

</details>

Since we know that the `tasks` file has a list of associated PIDs we start a process and try to write this into the tasks file.

```bash
$0> bash # creates shell with id #1
$1> echo -n $$ > /sys/fs/cgroup/memory/tcg1/tasks # this can be executed in any cgroup
$1> cat /sys/fs/cgroup/memory/tcg1/tasks
37697
37766
$0> cat /sys/fs/cgroup/memory/tcg1/tasks
37697
```

We observe that all subprocesses inherit the cgroup from the current process (PID `37766` is `cat` inside the bash shell which we connected to the `memory:tcg1` group).

What is the difference to executing the process before writing it to the tasks file (manual) vs. writing it after (`cgexec`).

Mainly that the process can use more of the to be assigned resource (memory in our case).

For a VERY simplified version with hardcoded values have a look at [cgexec.c](cgexec.c).

`cgdelete` essentially just deletes our cgroup directories, so let's do the same.

```bash
$ rmdir /sys/fs/cgroup/memory/tcg1
```

This works as long as there are no remaining processes associated with this cgroup.

> NOTE: `rm -rf /sys/fs/cgroup/memory/tcg1` doesn't work (Operation not permitted) in this case since the files are locked by the kernel.
