//! The ptrace sandbox (BEDROCK_SPEC.md 5.5). Linux on x86-64 and arm64.
//!
//! The child gets its own mount namespace (and, when unprivileged, a user
//! namespace mapping the image's user onto the invoking user), is chrooted
//! into the extracted rootfs, and execs the entrypoint under ptrace. Every
//! syscall that names a file is decoded and recorded.
//!
//! This isolates the filesystem view and credentials only. Network, process
//! and IPC namespaces are shared with the host: HTTP workloads need the
//! network, and signals must reach the tracee. Do not trace an image you do not
//! trust on a machine you care about.
use super::record::Recorder;
use libc::{c_char, c_int, c_long, c_void};
use std::collections::HashMap;
use std::ffi::{CString, OsString};
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const GRACE: Duration = Duration::from_secs(3);

pub struct RunSpec {
    pub rootfs: PathBuf,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    /// Working directory inside the image.
    pub cwd: String,
    /// Image user/group to run as.
    pub uid: u32,
    pub gid: u32,
    /// Stop the whole run after this long.
    pub timeout: Duration,
    /// Substring that marks readiness when seen in the tracee's output.
    pub log_pattern: Option<String>,
}

/// Shared between the tracer thread and the thread driving the workload.
#[derive(Default)]
pub struct Control {
    /// 0 = run, 1 = ask the process group to terminate, 2 = kill it now.
    pub stop: AtomicU8,
    pub log_seen: AtomicBool,
    /// Set once the traced process tree is gone.
    pub finished: AtomicBool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExitInfo {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

pub struct Outcome {
    pub recorder: Recorder,
    pub exit: ExitInfo,
    pub timed_out: bool,
    /// The entrypoint was still running and the tracer ended it.
    pub terminated_by_tracer: bool,
    /// Set when the sandbox could not start the entrypoint.
    pub spawn_error: Option<String>,
}

// ------------------------------------------------------------ registers

struct Regs {
    nr: i64,
    args: [u64; 6],
    ret: i64,
}

#[cfg(target_arch = "x86_64")]
fn read_regs(pid: i32) -> Option<Regs> {
    // SAFETY: plain-old-data struct filled by the kernel.
    let mut r: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ptrace(libc::PTRACE_GETREGS as _, pid, 0usize, &mut r as *mut _) };
    (rc >= 0).then_some(Regs {
        nr: r.orig_rax as i64,
        args: [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9],
        ret: r.rax as i64,
    })
}

#[cfg(target_arch = "aarch64")]
fn read_regs(pid: i32) -> Option<Regs> {
    // SAFETY: plain-old-data struct filled by the kernel.
    let mut r: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: &mut r as *mut _ as *mut c_void,
        iov_len: std::mem::size_of_val(&r),
    };
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGSET as _,
            pid,
            libc::NT_PRSTATUS as usize,
            &mut iov as *mut _,
        )
    };
    (rc >= 0).then_some(Regs {
        nr: r.regs[8] as i64,
        args: [r.regs[0], r.regs[1], r.regs[2], r.regs[3], r.regs[4], r.regs[5]],
        ret: r.regs[0] as i64,
    })
}

// ------------------------------------------------------------- syscalls

#[derive(Clone, Copy)]
enum NoFollow {
    Never,
    Always,
    /// Set when `args[idx] & mask != 0`.
    Flag(usize, u64),
}

#[derive(Clone, Copy)]
enum Kind {
    Path { path: usize, dirfd: Option<usize>, nofollow: NoFollow },
    Exec { path: usize, dirfd: Option<usize> },
    Mmap,
}

const O_NOFOLLOW: u64 = libc::O_NOFOLLOW as u64;
const AT_SYMLINK_NOFOLLOW: u64 = libc::AT_SYMLINK_NOFOLLOW as u64;

fn classify(nr: i64) -> Option<(&'static str, Kind)> {
    use Kind::*;
    use NoFollow::*;
    let at = |p, f| Path { path: p, dirfd: Some(0), nofollow: f };
    Some(match nr {
        #[cfg(target_arch = "x86_64")]
        libc::SYS_open => ("open", Path { path: 0, dirfd: None, nofollow: Flag(1, O_NOFOLLOW) }),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_stat => ("stat", Path { path: 0, dirfd: None, nofollow: Never }),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_lstat => ("lstat", Path { path: 0, dirfd: None, nofollow: Always }),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_access => ("access", Path { path: 0, dirfd: None, nofollow: Never }),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_readlink => ("readlink", Path { path: 0, dirfd: None, nofollow: Always }),
        libc::SYS_openat => ("openat", at(1, Flag(2, O_NOFOLLOW))),
        libc::SYS_openat2 => ("openat2", at(1, Never)),
        libc::SYS_newfstatat => ("newfstatat", at(1, Flag(3, AT_SYMLINK_NOFOLLOW))),
        libc::SYS_statx => ("statx", at(1, Flag(2, AT_SYMLINK_NOFOLLOW))),
        libc::SYS_faccessat => ("faccessat", at(1, Never)),
        libc::SYS_faccessat2 => ("faccessat2", at(1, Flag(3, AT_SYMLINK_NOFOLLOW))),
        libc::SYS_readlinkat => ("readlinkat", at(1, Always)),
        libc::SYS_execve => ("execve", Exec { path: 0, dirfd: None }),
        libc::SYS_execveat => ("execveat", Exec { path: 1, dirfd: Some(0) }),
        libc::SYS_mmap => ("mmap", Mmap),
        _ => return None,
    })
}

// -------------------------------------------------------------- tracees

struct Pending {
    syscall: &'static str,
    path: PathBuf,
    follow: bool,
    exec: bool,
}

struct Tracee {
    in_syscall: bool,
    pending: Option<Pending>,
    /// Image path of the running program, for evidence.
    exe: String,
    /// Waiting to swallow the initial SIGSTOP of an auto-attached child.
    fresh: bool,
}

fn raw_ptrace(req: c_int, pid: i32, addr: usize, data: usize) -> c_long {
    // SAFETY: requests used here take integer addr/data.
    unsafe { libc::ptrace(req as _, pid, addr, data) }
}

fn resume(pid: i32, sig: i32) {
    raw_ptrace(libc::PTRACE_SYSCALL as c_int, pid, 0, sig as usize);
}

fn readlink_str(p: &str) -> Option<PathBuf> {
    std::fs::read_link(p).ok()
}

struct Tracer {
    root: PathBuf,
    recording: bool,
    tracees: HashMap<i32, Tracee>,
    recorder: Recorder,
}

impl Tracer {
    /// A host path under the rootfs as an image path (leading `/`).
    fn to_image(&self, host: &Path) -> Option<PathBuf> {
        let s = host.to_string_lossy();
        let host = Path::new(s.strip_suffix(" (deleted)").unwrap_or(&s)).to_path_buf();
        let rest = host.strip_prefix(&self.root).ok()?;
        Some(Path::new("/").join(rest))
    }

    fn fd_path(&self, pid: i32, fd: i32) -> Option<PathBuf> {
        self.to_image(&readlink_str(&format!("/proc/{pid}/fd/{fd}"))?)
    }

    fn cwd_path(&self, pid: i32) -> Option<PathBuf> {
        self.to_image(&readlink_str(&format!("/proc/{pid}/cwd"))?)
    }

    fn decode(&self, pid: i32, r: &Regs) -> Option<Pending> {
        let (name, kind) = classify(r.nr)?;
        match kind {
            Kind::Mmap => {
                let (flags, fd) = (r.args[3], r.args[4] as i32);
                if flags & libc::MAP_ANONYMOUS as u64 != 0 || fd < 0 {
                    return None;
                }
                Some(Pending {
                    syscall: name,
                    path: self.fd_path(pid, fd)?,
                    follow: true,
                    exec: false,
                })
            }
            Kind::Path { path, dirfd, nofollow } => {
                let follow = match nofollow {
                    NoFollow::Never => true,
                    NoFollow::Always => false,
                    NoFollow::Flag(i, mask) => r.args[i] & mask == 0,
                };
                Some(Pending {
                    syscall: name,
                    path: self.path_arg(pid, r, path, dirfd)?,
                    follow,
                    exec: false,
                })
            }
            Kind::Exec { path, dirfd } => Some(Pending {
                syscall: name,
                path: self.path_arg(pid, r, path, dirfd)?,
                follow: true,
                exec: true,
            }),
        }
    }

    /// The image path a syscall's path argument names, relative to its dirfd or cwd.
    fn path_arg(&self, pid: i32, r: &Regs, path: usize, dirfd: Option<usize>) -> Option<PathBuf> {
        let raw = read_cstring(pid, r.args[path])?;
        let dirfd = dirfd.map(|i| r.args[i] as i32);
        let dir_of = |fd: Option<i32>| match fd {
            None | Some(libc::AT_FDCWD) => self.cwd_path(pid),
            Some(fd) => self.fd_path(pid, fd),
        };
        if raw.as_bytes().is_empty() {
            return dir_of(dirfd); // AT_EMPTY_PATH: the fd itself
        }
        let raw = PathBuf::from(raw);
        if raw.is_absolute() {
            Some(raw)
        } else {
            Some(dir_of(dirfd)?.join(raw))
        }
    }

    fn finish(&mut self, pid: i32, p: Pending, ret: i64) {
        let errno = (-4095..0).contains(&ret).then_some((-ret) as i32);
        let exe = self.tracees.get(&pid).map_or("?", |t| t.exe.as_str()).to_string();
        self.recorder.record(p.syscall, &exe, &p.path, p.follow, errno);
    }

    fn syscall_stop(&mut self, pid: i32) {
        let Some(r) = read_regs(pid) else { return };
        let entering = !self.tracees[&pid].in_syscall;
        if entering {
            let pending = match classify(r.nr) {
                Some((_, Kind::Exec { .. })) => self.decode(pid, &r),
                Some(_) if self.recording => self.decode(pid, &r),
                _ => None,
            };
            let t = self.tracees.get_mut(&pid).expect("tracee exists");
            t.in_syscall = true;
            t.pending = pending;
        } else {
            let t = self.tracees.get_mut(&pid).expect("tracee exists");
            t.in_syscall = false;
            if let Some(p) = t.pending.take() {
                if self.recording {
                    self.finish(pid, p, r.ret);
                }
            }
        }
    }

    fn exec_event(&mut self, pid: i32) {
        self.recording = true;
        let exe = readlink_str(&format!("/proc/{pid}/exe"))
            .and_then(|h| self.to_image(&h))
            .map_or_else(|| "?".to_string(), |p| p.display().to_string());
        let t = self.tracees.get_mut(&pid).expect("tracee exists");
        t.exe = exe;
        t.in_syscall = true; // the next syscall stop is execve's exit
        if let Some(p) = t.pending.take() {
            if p.exec {
                self.finish(pid, p, 0);
            }
        }
    }
}

fn read_cstring(pid: i32, addr: u64) -> Option<OsString> {
    let mem = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    let mut out = Vec::new();
    let mut at = addr;
    while out.len() < libc::PATH_MAX as usize {
        // Stay within one page so a string ending before an unmapped page reads fine.
        let chunk = (4096 - (at % 4096)) as usize;
        let mut buf = vec![0u8; chunk];
        let n = mem.read_at(&mut buf, at).ok()?;
        if n == 0 {
            return None;
        }
        if let Some(z) = buf[..n].iter().position(|&b| b == 0) {
            out.extend(&buf[..z]);
            return Some(OsString::from_vec(out));
        }
        out.extend(&buf[..n]);
        at += n as u64;
    }
    None
}

// ---------------------------------------------------------------- spawn

struct Prepared {
    rootfs: CString,
    cwd: CString,
    argv: Vec<CString>,
    env: Vec<CString>,
    devs: Vec<(CString, CString)>,
    proc_target: CString,
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
    root_mode: bool,
    uid: u32,
    gid: u32,
}

fn cstr(s: impl AsRef<[u8]>) -> std::io::Result<CString> {
    CString::new(s.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL byte in argument"))
}

/// Creates the mount points and files the child will bind over, on the host side.
fn prepare(spec: &RunSpec, root: &Path) -> std::io::Result<Prepared> {
    use super::resolve::resolve;
    let place_dir = |p: &str| -> std::io::Result<PathBuf> {
        let r = resolve(root, Path::new(p), true)
            .ok_or_else(|| std::io::Error::other("symlink loop"))?;
        let dir = root.join(r.real);
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    };
    let proc_target = place_dir("/proc")?;
    let dev = place_dir("/dev")?;
    let mut devs = Vec::new();
    for name in ["null", "zero", "urandom", "random", "tty"] {
        let src = Path::new("/dev").join(name);
        let dst = dev.join(name);
        if !src.exists() || dst.symlink_metadata().is_ok_and(|m| m.file_type().is_symlink()) {
            continue;
        }
        if !dst.exists() {
            std::fs::write(&dst, b"")?;
        }
        devs.push((cstr(src.as_os_str().as_bytes())?, cstr(dst.as_os_str().as_bytes())?));
    }
    let etc = place_dir("/etc")?;
    if !etc.join("hosts").exists() {
        std::fs::write(etc.join("hosts"), "127.0.0.1 localhost\n::1 localhost\n")?;
    }
    if !etc.join("resolv.conf").exists() {
        let _ = std::fs::copy("/etc/resolv.conf", etc.join("resolv.conf"));
    }
    place_dir(&spec.cwd)?;

    // SAFETY: getuid/getgid cannot fail.
    let (host_uid, host_gid) = unsafe { (libc::getuid(), libc::getgid()) };
    Ok(Prepared {
        rootfs: cstr(root.as_os_str().as_bytes())?,
        cwd: cstr(&spec.cwd)?,
        argv: spec.argv.iter().map(cstr).collect::<Result<_, _>>()?,
        env: spec.env.iter().map(cstr).collect::<Result<_, _>>()?,
        devs,
        proc_target: cstr(proc_target.as_os_str().as_bytes())?,
        uid_map: format!("{} {} 1\n", spec.uid, host_uid).into_bytes(),
        gid_map: format!("{} {} 1\n", spec.gid, host_gid).into_bytes(),
        root_mode: host_uid == 0,
        uid: spec.uid,
        gid: spec.gid,
    })
}

/// Writes `msg` and the current errno to `fd`, then exits. Async-signal-safe.
unsafe fn die(fd: c_int, msg: &[u8]) -> ! {
    let errno = *libc::__errno_location();
    let mut buf = [0u8; 160];
    let n = msg.len().min(120);
    buf[..n].copy_from_slice(&msg[..n]);
    let mut len = n;
    for b in b": errno " {
        buf[len] = *b;
        len += 1;
    }
    let mut digits = [0u8; 10];
    let (mut v, mut d) = (errno.max(0) as u32, 0);
    loop {
        digits[d] = b'0' + (v % 10) as u8;
        d += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while d > 0 {
        d -= 1;
        buf[len] = digits[d];
        len += 1;
    }
    libc::write(fd, buf.as_ptr() as *const c_void, len);
    libc::_exit(127)
}

unsafe fn write_file(path: &[u8], data: &[u8]) -> bool {
    let fd = libc::open(path.as_ptr() as *const c_char, libc::O_WRONLY);
    if fd < 0 {
        return false;
    }
    let n = libc::write(fd, data.as_ptr() as *const c_void, data.len());
    libc::close(fd);
    n == data.len() as isize
}

/// Runs in the forked child. Only async-signal-safe calls: no allocation.
unsafe fn child_main(
    p: &Prepared,
    argv: &[*const c_char],
    envp: &[*const c_char],
    err_fd: c_int,
    out_fd: c_int,
) -> ! {
    libc::setpgid(0, 0);
    if libc::ptrace(libc::PTRACE_TRACEME as _, 0, 0usize, 0usize) < 0 {
        die(err_fd, b"PTRACE_TRACEME failed (ptrace not permitted?)");
    }
    libc::raise(libc::SIGSTOP); // the tracer sets options, then resumes us

    let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
    if devnull >= 0 {
        libc::dup2(devnull, 0);
    }
    libc::dup2(out_fd, 1);
    libc::dup2(out_fd, 2);

    let flags =
        if p.root_mode { libc::CLONE_NEWNS } else { libc::CLONE_NEWUSER | libc::CLONE_NEWNS };
    if libc::unshare(flags) != 0 {
        die(err_fd, b"unshare failed (are unprivileged user namespaces enabled?)");
    }
    if !p.root_mode {
        // setgroups must be denied before an unprivileged gid_map write.
        if !write_file(b"/proc/self/setgroups\0", b"deny")
            || !write_file(b"/proc/self/gid_map\0", &p.gid_map)
            || !write_file(b"/proc/self/uid_map\0", &p.uid_map)
        {
            die(err_fd, b"writing user namespace id maps failed");
        }
    }
    let null_c: *const c_char = std::ptr::null();
    let null_v: *const c_void = std::ptr::null();
    if libc::mount(null_c, c"/".as_ptr(), null_c, libc::MS_REC | libc::MS_PRIVATE, null_v) != 0 {
        die(err_fd, b"making mounts private failed");
    }
    // Host /proc shows the tracee under its real pid, which is what tracing needs.
    // Failure is tolerated: many programs run without /proc.
    let proc_src = c"/proc".as_ptr();
    if libc::mount(proc_src, p.proc_target.as_ptr(), null_c, libc::MS_BIND | libc::MS_REC, null_v)
        != 0
    {
        libc::mount(proc_src, p.proc_target.as_ptr(), null_c, libc::MS_BIND, null_v);
    }
    for (src, dst) in &p.devs {
        libc::mount(src.as_ptr(), dst.as_ptr(), null_c, libc::MS_BIND, null_v);
    }
    if libc::chroot(p.rootfs.as_ptr()) != 0 {
        die(err_fd, b"chroot failed");
    }
    if libc::chdir(p.cwd.as_ptr()) != 0 {
        die(err_fd, b"chdir to the image working directory failed");
    }
    if p.root_mode
        && (libc::setgroups(0, std::ptr::null()) != 0
            || libc::setgid(p.gid) != 0
            || libc::setuid(p.uid) != 0)
    {
        die(err_fd, b"dropping to the image user failed");
    }
    libc::execve(argv[0], argv.as_ptr(), envp.as_ptr());
    die(err_fd, b"execve of the entrypoint failed")
}

fn pipe(cloexec: bool) -> std::io::Result<(c_int, c_int)> {
    let mut fds = [0 as c_int; 2];
    // SAFETY: fds has room for two descriptors.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), if cloexec { libc::O_CLOEXEC } else { 0 }) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

fn status_exit(status: c_int) -> ExitInfo {
    if libc::WIFEXITED(status) {
        ExitInfo { code: Some(libc::WEXITSTATUS(status)), signal: None }
    } else {
        ExitInfo { code: None, signal: Some(libc::WTERMSIG(status)) }
    }
}

/// Runs the entrypoint under ptrace. `driver` is started once the child exists
/// and runs the workload on its own thread; the tracer loop runs on this one,
/// because ptrace requests must come from the thread that forked the tracee.
pub fn run<T: Send + 'static>(
    spec: &RunSpec,
    control: &Arc<Control>,
    driver: impl FnOnce(Arc<Control>) -> std::thread::JoinHandle<T>,
) -> std::io::Result<(Outcome, T)> {
    let root = std::fs::canonicalize(&spec.rootfs)?;
    let prepared = prepare(spec, &root)?;
    let argv: Vec<*const c_char> =
        prepared.argv.iter().map(|c| c.as_ptr()).chain([std::ptr::null()]).collect();
    let envp: Vec<*const c_char> =
        prepared.env.iter().map(|c| c.as_ptr()).chain([std::ptr::null()]).collect();
    let (err_r, err_w) = pipe(true)?;
    let (out_r, out_w) = pipe(true)?;

    // Fork before any helper thread exists: the child may then only use
    // async-signal-safe calls, with no lock held by another thread.
    // SAFETY: see child_main; everything it touches was prepared above.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe { child_main(&prepared, &argv, &envp, err_w, out_w) }
    }
    // SAFETY: closing our copies of the child's ends.
    unsafe {
        libc::close(err_w);
        libc::close(out_w);
    }

    let mut status = 0;
    // SAFETY: waiting on our own child.
    unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
    let mut outcome = Outcome {
        recorder: Recorder::new(&root),
        exit: ExitInfo::default(),
        timed_out: false,
        terminated_by_tracer: false,
        spawn_error: None,
    };
    if !libc::WIFSTOPPED(status) {
        outcome.spawn_error =
            Some(read_all(err_r).unwrap_or_else(|| "child died before it could be traced".into()));
        outcome.exit = status_exit(status);
        return Ok((outcome, driver_finished(control, driver)));
    }
    let opts = libc::PTRACE_O_TRACESYSGOOD
        | libc::PTRACE_O_TRACEEXEC
        | libc::PTRACE_O_TRACEFORK
        | libc::PTRACE_O_TRACEVFORK
        | libc::PTRACE_O_TRACECLONE
        | libc::PTRACE_O_EXITKILL;
    raw_ptrace(libc::PTRACE_SETOPTIONS as c_int, pid, 0, opts as usize);

    let log_thread = forward_output(out_r, control.clone(), spec.log_pattern.clone());
    let handle = driver(control.clone());

    let mut t = Tracer {
        root,
        recording: false,
        tracees: HashMap::from([(
            pid,
            Tracee { in_syscall: false, pending: None, exe: "?".into(), fresh: false },
        )]),
        recorder: outcome.recorder,
    };
    resume(pid, 0);

    let started = Instant::now();
    let mut asked_term_at: Option<Instant> = None;
    let mut killed = false;
    let mut root_done = false;
    let mut idle = 0u32;
    loop {
        let stop = control.stop.load(Ordering::SeqCst);
        if started.elapsed() > spec.timeout && !killed {
            outcome.timed_out = true;
            control.stop.store(2, Ordering::SeqCst);
        }
        let want_kill = stop == 2 || asked_term_at.is_some_and(|at| at.elapsed() > GRACE);
        if stop >= 1 && asked_term_at.is_none() && !want_kill {
            // SAFETY: signalling our child's process group.
            unsafe { libc::kill(-pid, libc::SIGTERM) };
            asked_term_at = Some(Instant::now());
            outcome.terminated_by_tracer = !root_done;
        }
        if want_kill && !killed {
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            killed = true;
            outcome.terminated_by_tracer |= !root_done;
        }

        let mut status = 0;
        // SAFETY: standard wait on any traced child.
        let w = unsafe { libc::waitpid(-1, &mut status, libc::__WALL | libc::WNOHANG) };
        if w == 0 {
            // A traced process stops on every syscall, so the next event is
            // usually microseconds away: spin briefly before sleeping, or
            // each syscall would cost a full sleep interval.
            if idle < 4000 {
                idle += 1;
                std::thread::yield_now();
            } else {
                std::thread::sleep(Duration::from_millis(1));
            }
            continue;
        }
        idle = 0;
        if w < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break; // ECHILD: nothing left to trace
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            t.tracees.remove(&w);
            if w == pid {
                root_done = true;
                control.finished.store(true, Ordering::SeqCst);
                outcome.exit = status_exit(status);
                // Anything the entrypoint left running gets the same grace, then the group is killed.
                if !t.tracees.is_empty() && asked_term_at.is_none() {
                    asked_term_at = Some(Instant::now());
                }
            }
            if t.tracees.is_empty() {
                break;
            }
            continue;
        }
        if !libc::WIFSTOPPED(status) {
            continue;
        }
        let sig = libc::WSTOPSIG(status);
        let event = (status >> 16) & 0xff;
        let parent_exe = t.tracees.get(&w).map(|p| p.exe.clone());
        t.tracees.entry(w).or_insert_with(|| Tracee {
            in_syscall: false,
            pending: None,
            exe: "?".into(),
            fresh: true,
        });
        if sig == (libc::SIGTRAP | 0x80) {
            t.syscall_stop(w);
            resume(w, 0);
        } else if event != 0 {
            match event {
                libc::PTRACE_EVENT_EXEC => t.exec_event(w),
                libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK | libc::PTRACE_EVENT_CLONE => {
                    let mut child: c_long = 0;
                    raw_ptrace(
                        libc::PTRACE_GETEVENTMSG as c_int,
                        w,
                        0,
                        &mut child as *mut _ as usize,
                    );
                    let exe = parent_exe.unwrap_or_else(|| "?".into());
                    t.tracees.entry(child as i32).or_insert_with(|| Tracee {
                        in_syscall: false,
                        pending: None,
                        exe,
                        fresh: true,
                    });
                }
                _ => {}
            }
            resume(w, 0);
        } else if sig == libc::SIGSTOP && t.tracees[&w].fresh {
            t.tracees.get_mut(&w).expect("tracee").fresh = false;
            resume(w, 0);
        } else {
            resume(w, if sig == libc::SIGTRAP { 0 } else { sig });
        }
    }

    // Reap anything the loop left (a daemonised grandchild keeps the output pipe open).
    unsafe { libc::kill(-pid, libc::SIGKILL) };
    control.finished.store(true, Ordering::SeqCst);
    let _ = log_thread.join();
    outcome.recorder = t.recorder;
    if !t.recording {
        outcome.spawn_error = read_all(err_r);
    }
    unsafe { libc::close(err_r) };
    let result = handle.join().expect("workload thread panicked");
    Ok((outcome, result))
}

fn driver_finished<T: Send + 'static>(
    control: &Arc<Control>,
    driver: impl FnOnce(Arc<Control>) -> std::thread::JoinHandle<T>,
) -> T {
    control.finished.store(true, Ordering::SeqCst);
    driver(control.clone()).join().expect("workload thread panicked")
}

fn read_all(fd: c_int) -> Option<String> {
    use std::os::fd::FromRawFd;
    // SAFETY: fd is a pipe read end we own; File takes it over.
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut s = String::new();
    f.read_to_string(&mut s).ok()?;
    std::mem::forget(f); // the caller closes it
    (!s.is_empty()).then_some(s)
}

/// Copies the tracee's output to our stderr and watches it for the readiness pattern.
fn forward_output(
    fd: c_int,
    control: Arc<Control>,
    pattern: Option<String>,
) -> std::thread::JoinHandle<()> {
    use std::io::Write;
    use std::os::fd::FromRawFd;
    // SAFETY: fd is a pipe read end handed over to this thread.
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let mut window = String::new();
        while let Ok(n) = f.read(&mut buf) {
            if n == 0 {
                break;
            }
            let _ = std::io::stderr().write_all(&buf[..n]);
            if let Some(p) = &pattern {
                window.push_str(&String::from_utf8_lossy(&buf[..n]));
                if window.contains(p.as_str()) {
                    control.log_seen.store(true, Ordering::SeqCst);
                }
                // Keep just enough tail to catch a pattern split across reads.
                if window.len() > 2 * p.len() + 4096 {
                    let cut = window.len() - (p.len() + 4096);
                    let cut = (cut..window.len())
                        .find(|&i| window.is_char_boundary(i))
                        .unwrap_or(window.len());
                    window.drain(..cut);
                }
            }
        }
    })
}
