//! Linux memory locking and native core-dump exclusion.

use super::{DefaultMemoryCreator, MmapMemory};
use crate::prelude::*;
use crate::runtime::vm::{HostAlignedByteCount, host_page_size};
use crate::{LinearMemory, MemoryCreator, MemoryKind, MemoryRequest};
use rustix::mm::{Advice, MlockFlags, madvise, mlock_with};

pub struct LockedMemoryCreator(pub usize);

// SAFETY: MmapMemory owns the allocation and preserves the LinearMemory invariants.
unsafe impl MemoryCreator for LockedMemoryCreator {
    fn new_memory(&self, request: &MemoryRequest<'_>) -> Result<Box<dyn LinearMemory>> {
        if request.kind() != MemoryKind::LinearMemory {
            return DefaultMemoryCreator.new_memory(request);
        }
        let limit = self.0 / host_page_size() * host_page_size();
        let capacity =
            HostAlignedByteCount::new_rounded_up(request.maximum().unwrap_or(limit).min(limit))?
                .byte_count();
        ensure!(
            request.minimum() <= capacity,
            "linear memory exceeds the locking limit"
        );
        let inner = MmapMemory::new(
            request.wasmtime_memory(),
            request.tunables(),
            request.minimum(),
            request.maximum(),
        )?;
        let capacity = capacity.min(inner.byte_capacity());
        if capacity != 0 {
            // SAFETY: this new, page-aligned reservation is exclusively owned and
            // not published. On-fault locking also covers its inaccessible pages.
            unsafe {
                madvise(inner.as_ptr().cast(), capacity, Advice::LinuxDontDump)
                    .context("excluding linear memory from core dumps")?;
                mlock_with(inner.as_ptr().cast(), capacity, MlockFlags::ONFAULT)
                    .context("locking linear memory; check RLIMIT_MEMLOCK")?;
            }
        }
        // Dropping inner on any error unmaps the reservation and releases locks.
        Ok(try_new::<Box<_>>(LockedMemory { inner, capacity })?)
    }
}

struct LockedMemory {
    inner: MmapMemory,
    capacity: usize,
}

// SAFETY: the underlying mapping retains its guards and never relocates.
// The protected capacity is reserved up front. Growth only changes permissions.
unsafe impl LinearMemory for LockedMemory {
    fn byte_size(&self) -> usize {
        self.inner.byte_size()
    }

    fn byte_capacity(&self) -> usize {
        self.capacity
    }

    fn grow_to(&mut self, new_size: usize) -> Result<()> {
        ensure!(
            new_size <= self.capacity,
            "locked memory reservation exhausted"
        );
        self.inner.grow_to(new_size)
    }

    fn as_ptr(&self) -> *mut u8 {
        self.inner.as_ptr()
    }

    // The init_from_image fallback copies data. Remapping loses locks and advice.
}

#[cfg(all(test, not(miri), feature = "cranelift", feature = "wat"))]
mod tests {
    use super::*;
    use crate::{Config, Engine, Instance, Memory, MemoryType, Module, Store};
    use std::{fs, process::Command};

    const WASM_PAGE: usize = 65536;

    fn status_bytes(field: &str) -> usize {
        fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse::<usize>()
            .unwrap()
            * 1024
    }

    fn locked_bytes() -> usize {
        status_bytes("VmLck:")
    }

    fn protected(addr: usize, expected_permissions: &str) {
        let mut selected = false;
        let mut permissions = "";
        let smaps = fs::read_to_string("/proc/self/smaps").unwrap();
        for line in smaps.lines() {
            if let Some((start, end)) = line.split_whitespace().next().unwrap_or("").split_once('-')
            {
                if let (Ok(start), Ok(end)) = (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(end, 16),
                ) {
                    selected = (start..end).contains(&addr);
                    if selected {
                        permissions = line.split_whitespace().nth(1).unwrap();
                    }
                }
            }
            if selected && line.starts_with("VmFlags:") {
                assert_eq!(permissions, expected_permissions);
                assert!(line.split_whitespace().any(|flag| flag == "lo"), "{line}");
                assert!(line.split_whitespace().any(|flag| flag == "dd"), "{line}");
                return;
            }
        }
        panic!("protected mapping not found");
    }

    fn isolated(name: &str, quota: usize, test: impl FnOnce()) {
        if std::env::var("WASMTIME_TEST_LOCKED_MEMORY").as_deref() != Ok(name) {
            let module = module_path!().split_once("::").unwrap().1;
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &format!("{module}::{name}"), "--nocapture"])
                .env_clear()
                .env("WASMTIME_TEST_LOCKED_MEMORY", name)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }
        // SAFETY: these are valid Linux capability v3 and rlimit buffers.
        // Drop the child's capabilities so CAP_IPC_LOCK cannot bypass the quota.
        unsafe {
            let header = [0x2008_0522u32, 0];
            let capabilities = [0u32; 6];
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::syscall(libc::SYS_capset, header.as_ptr(), capabilities.as_ptr()),
                0
            );
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit), 0);
            limit.rlim_cur = quota as libc::rlim_t;
            assert!(limit.rlim_cur <= limit.rlim_max);
            assert_eq!(libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit), 0);
        }
        test();
    }

    fn byte_memory(minimum: usize, maximum: usize) -> MemoryType {
        MemoryType::builder()
            .min(minimum as u64)
            .max(Some(maximum as u64))
            .page_size_log2(0)
            .build()
            .unwrap()
    }

    #[test]
    fn quota_growth_and_cleanup() {
        isolated("quota_growth_and_cleanup", 2 * host_page_size(), || {
            let page = host_page_size();
            let mut config = Config::new();
            config.memory_locking(2 * page).wasm_custom_page_sizes(true);
            let engine = Engine::new(&config).unwrap();
            let baseline = locked_bytes();
            for _ in 0..3 {
                let mut store = Store::new(&engine, ());
                let memory = Memory::new(&mut store, byte_memory(1, 3 * page)).unwrap();
                let base = memory.data_ptr(&store);
                assert_eq!(locked_bytes(), baseline + 2 * page);
                protected(base as usize, "rw-p");
                protected(base as usize + page, "---p");
                memory.write(&mut store, 0, b"x").unwrap();
                for _ in 0..8 {
                    assert!(Memory::new(&mut store, byte_memory(1, page)).is_err());
                    assert_eq!(locked_bytes(), baseline + 2 * page);
                }
                assert_eq!(memory.grow(&mut store, page as u64).unwrap(), 1);
                assert_eq!(memory.data_ptr(&store), base);
                assert_eq!(memory.data(&store)[0], b'x');
                assert!(memory.data(&store)[1..].iter().all(|byte| *byte == 0));
                protected(base as usize + page, "rw-p");
                assert!(memory.grow(&mut store, page as u64).is_err());
                assert_eq!(memory.data_size(&store), page + 1);
                assert_eq!(locked_bytes(), baseline + 2 * page);
                drop(store);
                assert_eq!(locked_bytes(), baseline);
            }
            // Rounding a cap to host pages must not exceed its byte limit.
            config.memory_locking(page - 1);
            let small = Engine::new(&config).unwrap();
            let mut store = Store::new(&small, ());
            assert!(Memory::new(&mut store, byte_memory(1, page)).is_err());
            assert!(Memory::new(&mut store, byte_memory(0, 0)).is_ok());
            assert_eq!(locked_bytes(), baseline);
        });
    }

    #[test]
    fn initialization_and_shared_cleanup() {
        isolated("initialization_and_shared_cleanup", 2 * WASM_PAGE, || {
            let page = WASM_PAGE;
            let mut config = Config::new();
            config.memory_locking(2 * page);
            let engine = Engine::new(&config).unwrap();
            let baseline = locked_bytes();
            let module = Module::new(
                &engine,
                r#"(module
                    (memory (export "memory") 1 3)
                    (data (i32.const 0) "secret")
                    (func (export "grow") (result i32) i32.const 1 memory.grow))"#,
            )
            .unwrap();
            assert!(
                module
                    .memory_images()
                    .unwrap()
                    .unwrap()
                    .get_memory_image(wasmtime_environ::DefinedMemoryIndex::from_u32(0))
                    .is_some()
            );
            let mut store = Store::new(&engine, ());
            let instance = Instance::new(&mut store, &module, &[]).unwrap();
            let memory = instance.get_memory(&mut store, "memory").unwrap();
            assert_eq!(&memory.data(&store)[..6], b"secret");
            protected(memory.data_ptr(&store) as usize, "rw-p");
            let grow = instance
                .get_typed_func::<(), i32>(&mut store, "grow")
                .unwrap();
            assert_eq!(grow.call(&mut store, ()).unwrap(), 1);
            assert_eq!(grow.call(&mut store, ()).unwrap(), -1);
            protected(memory.data_ptr(&store) as usize + page, "rw-p");
            drop(store);
            assert_eq!(locked_bytes(), baseline);

            #[cfg(feature = "threads")]
            {
                config.memory_locking(page).shared_memory(true);
                let engine = Engine::new(&config).unwrap();
                let shared =
                    crate::SharedMemory::new(&engine, MemoryType::shared(0, 2).unwrap()).unwrap();
                assert_eq!(shared.grow(1).unwrap(), 0);
                protected(shared.data().as_ptr() as usize, "rw-p");
                assert!(shared.grow(1).is_err());
                assert_eq!(shared.size(), 1);
                let module = Module::new(
                    &engine,
                    r#"(module (import "env" "memory" (memory 0 2 shared)))"#,
                )
                .unwrap();
                let mut store = Store::new(&engine, ());
                Instance::new(&mut store, &module, &[shared.clone().into()]).unwrap();
                drop(shared);
                assert_eq!(locked_bytes(), baseline + page);
                drop(store);
                assert_eq!(locked_bytes(), baseline);
            }
            #[cfg(feature = "gc-drc")]
            {
                config.memory_locking(0);
                let engine = Engine::new(&config).unwrap();
                let module = Module::new(
                    &engine,
                    r#"(module (type (array (mut i8)))
                        (func (export "run") i32.const 1 array.new_default 0 drop))"#,
                )
                .unwrap();
                let mut store = Store::new(&engine, ());
                let instance = Instance::new(&mut store, &module, &[]).unwrap();
                instance
                    .get_typed_func::<(), ()>(&mut store, "run")
                    .unwrap()
                    .call(&mut store, ())
                    .unwrap();
                assert_eq!(locked_bytes(), baseline);
            }
        });
    }

    fn deny_syscall(syscall: libc::c_long, argument: u32, error: u32) {
        let instruction = |code, jt, jf, k| libc::sock_filter {
            code: code as u16,
            jt,
            jf,
            k,
        };
        // Match the syscall number and third argument in seccomp_data.
        let mut filter = [
            instruction(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
            instruction(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                0,
                3,
                syscall as u32,
            ),
            instruction(
                libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
                0,
                0,
                if cfg!(target_endian = "big") { 36 } else { 32 },
            ),
            instruction(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 1, argument),
            instruction(
                libc::BPF_RET | libc::BPF_K,
                0,
                0,
                libc::SECCOMP_RET_ERRNO | error,
            ),
            instruction(libc::BPF_RET | libc::BPF_K, 0, 0, libc::SECCOMP_RET_ALLOW),
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: the kernel copies this live filter. The filter applies only to the isolated child.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
                0
            );
        }
    }

    fn creation_failure(name: &str, syscall: libc::c_long, argument: u32, error: u32) {
        isolated(name, 2 * host_page_size(), || {
            let page = host_page_size();
            let mut config = Config::new();
            config.memory_locking(page).wasm_custom_page_sizes(true);
            let engine = Engine::new(&config).unwrap();
            let baseline = locked_bytes();
            let mut store = Store::new(&engine, ());
            Memory::new(&mut store, byte_memory(1, page)).unwrap();
            drop(store);
            assert_eq!(locked_bytes(), baseline);
            let mut store = Store::new(&engine, ());
            deny_syscall(syscall, argument, error);
            let address_space = status_bytes("VmSize:");
            for _ in 0..3 {
                assert!(Memory::new(&mut store, byte_memory(1, page)).is_err());
                assert_eq!(locked_bytes(), baseline);
                assert_eq!(status_bytes("VmSize:"), address_space);
            }
        });
    }

    #[test]
    fn dump_exclusion_failure() {
        creation_failure(
            "dump_exclusion_failure",
            libc::SYS_madvise,
            libc::MADV_DONTDUMP as u32,
            libc::EPERM as u32,
        );
    }

    #[test]
    fn locking_failure() {
        creation_failure(
            "locking_failure",
            libc::SYS_mlock2,
            libc::MLOCK_ONFAULT,
            libc::ENOSYS as u32,
        );
    }

    #[test]
    fn growth_failure_preserves_memory() {
        isolated(
            "growth_failure_preserves_memory",
            2 * host_page_size(),
            || {
                let page = host_page_size();
                let mut config = Config::new();
                config.memory_locking(2 * page).wasm_custom_page_sizes(true);
                let engine = Engine::new(&config).unwrap();
                let baseline = locked_bytes();
                let mut store = Store::new(&engine, ());
                let memory = Memory::new(&mut store, byte_memory(1, 3 * page)).unwrap();
                let base = memory.data_ptr(&store);
                memory.write(&mut store, 0, b"x").unwrap();
                deny_syscall(
                    libc::SYS_mprotect,
                    (libc::PROT_READ | libc::PROT_WRITE) as u32,
                    libc::ENOMEM as u32,
                );
                for _ in 0..3 {
                    assert!(memory.grow(&mut store, page as u64).is_err());
                    assert_eq!(memory.grow(&mut store, 0).unwrap(), 1);
                    assert_eq!(memory.data_ptr(&store), base);
                    assert_eq!(memory.data(&store), b"x");
                    assert_eq!(locked_bytes(), baseline + 2 * page);
                    protected(base as usize, "rw-p");
                    protected(base as usize + page, "---p");
                }
                drop(store);
                assert_eq!(locked_bytes(), baseline);
            },
        );
    }

    #[test]
    fn reservation_boundaries() {
        isolated("reservation_boundaries", 2 * host_page_size(), || {
            let page = host_page_size();
            let baseline = locked_bytes();
            let mut store = Store::new(&Engine::default(), ());
            Memory::new(&mut store, MemoryType::new(1, Some(1)).unwrap()).unwrap();
            assert_eq!(locked_bytes(), baseline);
            drop(store);
            let unbounded = MemoryType::builder()
                .memory64(true)
                .min(1)
                .page_size_log2(0)
                .build()
                .unwrap();
            for (limit, ty, minimal_reservation, capacity) in [
                (3 * page - 1, byte_memory(1, 3 * page), false, 2 * page),
                (usize::MAX, byte_memory(1, page), false, page),
                (2 * page, unbounded, false, 2 * page),
                (2 * page, byte_memory(1, 3 * page), true, page),
            ] {
                let mut config = Config::new();
                config.memory_locking(limit).wasm_custom_page_sizes(true);
                if minimal_reservation {
                    config
                        .memory_reservation(0)
                        .memory_reservation_for_growth(0);
                }
                let engine = Engine::new(&config).unwrap();
                let mut store = Store::new(&engine, ());
                let memory = Memory::new(&mut store, ty).unwrap();
                let base = memory.data_ptr(&store);
                memory.write(&mut store, 0, b"x").unwrap();
                assert_eq!(locked_bytes(), baseline + capacity);
                assert_eq!(memory.grow(&mut store, (capacity - 1) as u64).unwrap(), 1);
                assert!(memory.grow(&mut store, 1).is_err());
                assert!(memory.grow(&mut store, u64::MAX).is_err());
                assert_eq!(memory.grow(&mut store, 0).unwrap(), capacity as u64);
                assert_eq!(memory.data_ptr(&store), base);
                assert_eq!(memory.data_size(&store), capacity);
                assert_eq!(memory.data(&store)[0], b'x');
                assert!(memory.data(&store)[1..].iter().all(|byte| *byte == 0));
                protected(base as usize + capacity - 1, "rw-p");
                drop(store);
                assert_eq!(locked_bytes(), baseline);
            }
        });
    }

    #[test]
    fn partial_allocation_cleanup() {
        isolated("partial_allocation_cleanup", 2 * WASM_PAGE, || {
            let mut config = Config::new();
            config.memory_locking(WASM_PAGE);
            let engine = Engine::new(&config).unwrap();
            let module =
                Module::new(&engine, "(module (memory 1 1) (memory 1 1) (memory 1 1))").unwrap();
            let baseline = locked_bytes();
            let mut store = Store::new(&engine, ());
            for _ in 0..4 {
                assert!(Instance::new(&mut store, &module, &[]).is_err());
                assert_eq!(locked_bytes(), baseline);
            }
            Memory::new(&mut store, MemoryType::new(1, Some(1)).unwrap()).unwrap();
            let other = Engine::new(&config).unwrap();
            let mut other_store = Store::new(&other, ());
            Memory::new(&mut other_store, MemoryType::new(1, Some(1)).unwrap()).unwrap();
            assert!(Memory::new(&mut store, MemoryType::new(1, Some(1)).unwrap()).is_err());
            drop(other_store);
            assert_eq!(locked_bytes(), baseline + WASM_PAGE);
            drop(store);
            assert_eq!(locked_bytes(), baseline);
        });
    }

    #[test]
    fn configuration_contracts() {
        assert_eq!(Engine::default().get_memory_locking(), None);
        let mut config = Config::new();
        config.memory_locking(0);
        assert_eq!(Engine::new(&config).unwrap().get_memory_locking(), Some(0));
        config.with_host_memory(alloc::sync::Arc::new(DefaultMemoryCreator));
        assert!(
            Engine::new(&config)
                .err()
                .unwrap()
                .to_string()
                .contains("custom memory creator")
        );
        #[cfg(feature = "pooling-allocator")]
        {
            let mut config = Config::new();
            config.memory_locking(1).allocation_strategy(
                crate::InstanceAllocationStrategy::Pooling(Default::default()),
            );
            assert!(
                Engine::new(&config)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("on-demand")
            );
        }
        #[cfg(feature = "coredump")]
        {
            let mut config = Config::new();
            config.memory_locking(1).coredump_on_trap(true);
            assert!(
                Engine::new(&config)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("coredumps")
            );
        }
    }
}
