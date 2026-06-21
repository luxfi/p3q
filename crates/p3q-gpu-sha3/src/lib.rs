// P3Q SHA3-256 / SHAKE256 GPU backend over libluxgpu 0.4.
//
// This crate is the ONE place in the workspace where `unsafe` is
// permitted. The FFI surface is intentionally tiny — four dlsym'd
// symbols (`lux_gpu_create`, `lux_gpu_destroy`, `lux_gpu_sha3_256_batch`,
// `lux_gpu_shake256_batch`) plus a `catch_unwind` boundary so a
// libluxgpu panic NEVER crosses the seam into the audited verifier.

#![allow(unsafe_code)] // FFI: see crate-level rationale above.
#![deny(missing_docs)]
//! libluxgpu-backed SHA3-256 / SHAKE256 batch hashing.
//!
//! The library is loaded by `dlopen` at runtime (`libluxgpu.dylib` on
//! macOS, `libluxgpu.so` on Linux). If the library is missing, the
//! symbols are missing, or the GPU context fails to initialise, the
//! crate returns `None` from [`try_load_default`] and the consumer
//! falls back to CPU.

use libloading::{Library, Symbol};
use p3q_sha3::backend::{CpuShake, Sha3Backend};
use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::Arc;

// Internal CPU fallback handle reused on every error path so callers
// see byte-identical output on backend failure. Stateless; cheap to
// construct, but pinning it as a single static skips even the cost of
// the construction.
const CPU_FALLBACK: CpuShake = CpuShake;

/// libluxgpu opaque GPU context pointer.
#[repr(C)]
struct LuxGpu {
    _private: [u8; 0],
}

/// libluxgpu error codes — kept as a plain `c_int` since we only check
/// for `0 == LUX_OK` at the FFI seam.
type LuxError = c_int;

const LUX_OK: LuxError = 0;

// FIPS 202 padding sanity: per `lux/gpu.h` lux_gpu_sha3_256_batch /
// lux_gpu_shake256_batch reject NULL input pointers even when the
// concatenated buffer would be empty. We pass a non-null sentinel byte.
static EMPTY_SENTINEL: u8 = 0;

type LuxGpuCreate = unsafe extern "C" fn() -> *mut LuxGpu;
type LuxGpuDestroy = unsafe extern "C" fn(*mut LuxGpu);
type LuxGpuBackendName = unsafe extern "C" fn(*mut LuxGpu) -> *const c_char;
type LuxGpuSha3_256Batch = unsafe extern "C" fn(
    *mut LuxGpu,
    *const u8,    // inputs (concatenated)
    *mut u8,      // outputs (num_inputs * 32)
    *const usize, // input_lens (num_inputs)
    usize,        // num_inputs
) -> LuxError;
type LuxGpuShake256Batch = unsafe extern "C" fn(
    *mut LuxGpu,
    *const u8,    // inputs (concatenated)
    *mut u8,      // outputs (concatenated, sum of output_lens)
    *const usize, // input_lens (num_inputs)
    *const usize, // output_lens (num_inputs)
    usize,        // num_inputs
) -> LuxError;

/// Loaded libluxgpu plus the four dispatch symbols we care about. The
/// `Library` is held alongside the symbols (since `Symbol<'_>` borrows
/// from the library) so the dylib stays mapped for the GPU context's
/// lifetime.
struct LoadedLib {
    // SAFETY: `_lib` must outlive the four `extern "C" fn` pointers
    // below. The struct never moves out of an Arc, and Library holds the
    // dlopen handle that keeps the dylib mapped for the process. We
    // re-cast `Symbol<'static>` to bare `extern "C" fn` to break the
    // lifetime tie — sound because `_lib` is owned by the same Arc.
    _lib: Library,
    create: LuxGpuCreate,
    destroy: LuxGpuDestroy,
    backend_name: LuxGpuBackendName,
    sha3_256: LuxGpuSha3_256Batch,
    shake256: LuxGpuShake256Batch,
}

/// GPU-backed `Sha3Backend`. Owns one libluxgpu context + the loaded
/// library. `Send` and `Sync` because libluxgpu's gpu_core takes its
/// own internal mutex on every dispatch (see luxcpp/gpu/src/gpu_core.cpp).
///
/// Field order is load-bearing: Rust drops fields in declaration order,
/// so `gpu` (which calls `destroy`) MUST drop BEFORE `lib` (which
/// unmaps the dylib that `destroy` lives in). Reordering these would
/// produce a use-after-free at shutdown.
pub struct GpuShake {
    gpu: GpuHandle,
    lib: Arc<LoadedLib>,
    name_str: &'static str,
}

/// Wrapper for `*mut LuxGpu` that destroys the context on drop. Separate
/// type so we can derive nothing on it and hand-implement Send + Sync.
struct GpuHandle {
    ptr: *mut LuxGpu,
    destroy: LuxGpuDestroy,
}

// SAFETY: libluxgpu serialises every dispatch through gpu->backend_mu
// (see gpu_core.cpp). The opaque pointer is safe to share across
// threads as long as we never invoke `destroy` concurrently with any
// other call; `GpuHandle::drop` runs at most once.
unsafe impl Send for GpuHandle {}
unsafe impl Sync for GpuHandle {}

impl Drop for GpuHandle {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: ptr was produced by `lux_gpu_create` exactly once
            // and is destroyed exactly once here. catch_unwind protects
            // the audited caller from a panic in the destructor (e.g.
            // a backend plugin that aborts during teardown).
            let _ = catch_unwind(AssertUnwindSafe(|| unsafe { (self.destroy)(self.ptr) }));
            self.ptr = std::ptr::null_mut();
        }
    }
}

/// Try to load libluxgpu + initialise a GPU context. Returns
/// `Some(Arc<dyn Sha3Backend>)` on success or `None` if anything along
/// the way fails — caller MUST transparently fall back to CPU.
pub fn try_load_default() -> Option<Arc<dyn Sha3Backend>> {
    let lib = load_library()?;
    let gpu_ptr = call_create(&lib)?;
    let backend_name = resolve_backend_name(&lib, gpu_ptr);
    Some(Arc::new(GpuShake {
        gpu: GpuHandle {
            ptr: gpu_ptr,
            destroy: lib.destroy,
        },
        lib,
        name_str: backend_name,
    }))
}

/// Best-effort `dlopen` over the conventional library names. Returns
/// `None` if no library can be loaded with all four required symbols.
fn load_library() -> Option<Arc<LoadedLib>> {
    for name in candidate_lib_names() {
        if let Some(lib) = try_open_with_symbols(&name) {
            return Some(Arc::new(lib));
        }
    }
    None
}

/// Platform-specific candidate dylib names + a `$LUXGPU_LIB` override
/// for unusual install paths. Order matters: first hit wins.
fn candidate_lib_names() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(env) = std::env::var("LUXGPU_LIB") {
        if !env.is_empty() {
            out.push(env);
        }
    }
    if let Ok(prefix) = std::env::var("LUXCPP_PREFIX") {
        out.push(format!("{prefix}/lib/{}", platform_default_name()));
    }
    // System search path (DYLD_LIBRARY_PATH / LD_LIBRARY_PATH / ldconfig).
    out.push(platform_default_name().to_string());
    // Convention: build tree alongside lux/p3q checkout.
    out.push(format!(
        "{}/work/luxcpp/install/lib/{}",
        std::env::var("HOME").unwrap_or_default(),
        platform_default_name()
    ));
    out.push(format!(
        "{}/work/luxcpp/gpu/build/{}",
        std::env::var("HOME").unwrap_or_default(),
        platform_default_name()
    ));
    out
}

#[cfg(target_os = "macos")]
fn platform_default_name() -> &'static str {
    "libluxgpu.dylib"
}

#[cfg(target_os = "linux")]
fn platform_default_name() -> &'static str {
    "libluxgpu.so"
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn platform_default_name() -> &'static str {
    "libluxgpu"
}

/// Open `path` and look up all required symbols. Returns `None` on any
/// failure — never panics.
fn try_open_with_symbols(path: &str) -> Option<LoadedLib> {
    if !Path::new(path).exists() && !path.starts_with("libluxgpu") {
        // libloading::Library::new with a bare name searches the system
        // loader path; with an absolute path that doesn't exist it'll
        // fail loudly. Skip non-existent absolute paths quietly.
        return None;
    }
    // SAFETY: dlopen is inherently unsafe (executes the library's
    // initialisers). We trust libluxgpu is well-formed; the alternative
    // is shipping no GPU backend.
    let lib = unsafe { Library::new(path) }.ok()?;
    let create_sym: Symbol<LuxGpuCreate> = unsafe { lib.get(b"lux_gpu_create\0") }.ok()?;
    let destroy_sym: Symbol<LuxGpuDestroy> = unsafe { lib.get(b"lux_gpu_destroy\0") }.ok()?;
    let bn_sym: Symbol<LuxGpuBackendName> = unsafe { lib.get(b"lux_gpu_backend_name\0") }.ok()?;
    let sha3_sym: Symbol<LuxGpuSha3_256Batch> =
        unsafe { lib.get(b"lux_gpu_sha3_256_batch\0") }.ok()?;
    let shake_sym: Symbol<LuxGpuShake256Batch> =
        unsafe { lib.get(b"lux_gpu_shake256_batch\0") }.ok()?;
    // Capture bare function pointers; `_lib` keeps the dylib mapped.
    // `Symbol<'_, F>` for an F that is `Copy` (like fn-ptr) lets us
    // dereference once and forget the lifetime — the dylib stays
    // mapped for as long as `_lib` is held below.
    let create = *create_sym;
    let destroy = *destroy_sym;
    let backend_name = *bn_sym;
    let sha3_256 = *sha3_sym;
    let shake256 = *shake_sym;
    Some(LoadedLib {
        _lib: lib,
        create,
        destroy,
        backend_name,
        sha3_256,
        shake256,
    })
}

fn call_create(lib: &LoadedLib) -> Option<*mut LuxGpu> {
    // SAFETY: lux_gpu_create takes no arguments and may panic in the
    // backend plugin loader on broken installs (rare but possible).
    // catch_unwind degrades the failure to None.
    match catch_unwind(AssertUnwindSafe(|| unsafe { (lib.create)() })) {
        Ok(p) if !p.is_null() => Some(p),
        _ => None,
    }
}

/// Resolve the backend name to a 'static string (one of "cpu", "metal",
/// "cuda", "dawn"; or "unknown" on failure). Used purely for logging
/// in [`Sha3Backend::name`].
fn resolve_backend_name(lib: &LoadedLib, gpu: *mut LuxGpu) -> &'static str {
    // SAFETY: backend_name returns a pointer to a static C string owned
    // by libluxgpu — never freed by the caller.
    let cstr_ptr = match catch_unwind(AssertUnwindSafe(|| unsafe { (lib.backend_name)(gpu) })) {
        Ok(p) if !p.is_null() => p,
        _ => return "gpu-sha3-unknown",
    };
    let bytes = unsafe { std::ffi::CStr::from_ptr(cstr_ptr) }.to_bytes();
    match bytes {
        b"cpu" | b"CPU" => "gpu-sha3-cpu",
        b"metal" | b"Metal" => "gpu-sha3-metal",
        b"cuda" | b"CUDA" => "gpu-sha3-cuda",
        b"dawn" | b"Dawn" | b"webgpu" | b"WebGPU" => "gpu-sha3-dawn",
        _ => "gpu-sha3-unknown",
    }
}

impl Sha3Backend for GpuShake {
    fn sha3_256_batch(&self, inputs: &[&[u8]]) -> Vec<[u8; 32]> {
        let n = inputs.len();
        if n == 0 {
            return Vec::new();
        }
        let input_lens: Vec<usize> = inputs.iter().map(|b| b.len()).collect();
        let total: usize = input_lens.iter().sum();
        let mut concat: Vec<u8> = Vec::with_capacity(total);
        for b in inputs {
            concat.extend_from_slice(b);
        }
        let mut outputs = vec![0u8; n * 32];
        let inputs_ptr: *const u8 = if total == 0 {
            &EMPTY_SENTINEL as *const u8
        } else {
            concat.as_ptr()
        };
        // SAFETY: pointers point into Rust-owned buffers whose lengths
        // match the size args. catch_unwind degrades a backend panic to
        // a CPU re-run rather than unwinding into the audited caller.
        let result = catch_unwind(AssertUnwindSafe(|| unsafe {
            (self.lib.sha3_256)(
                self.gpu.ptr,
                inputs_ptr,
                outputs.as_mut_ptr(),
                input_lens.as_ptr(),
                n,
            )
        }));
        match result {
            Ok(LUX_OK) => outputs
                .chunks_exact(32)
                .map(|c| {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(c);
                    a
                })
                .collect(),
            // GPU error or panic: silently fall back to the CPU reference.
            // Byte-identical output by the KAT-parity contract.
            _ => CPU_FALLBACK.sha3_256_batch(inputs),
        }
    }

    fn shake256_batch(&self, inputs: &[&[u8]], out_lens: &[usize]) -> Vec<Vec<u8>> {
        debug_assert_eq!(inputs.len(), out_lens.len());
        let n = inputs.len();
        if n == 0 {
            return Vec::new();
        }
        let input_lens: Vec<usize> = inputs.iter().map(|b| b.len()).collect();
        let total_in: usize = input_lens.iter().sum();
        let total_out: usize = out_lens.iter().sum();
        let mut concat: Vec<u8> = Vec::with_capacity(total_in);
        for b in inputs {
            concat.extend_from_slice(b);
        }
        let mut outputs = vec![0u8; total_out];
        let inputs_ptr: *const u8 = if total_in == 0 {
            &EMPTY_SENTINEL as *const u8
        } else {
            concat.as_ptr()
        };
        let outputs_ptr: *mut u8 = if total_out == 0 {
            // outputs is empty Vec; chunks loop below handles n inputs
            // with all-zero out_lens — just take any non-null sentinel.
            (&EMPTY_SENTINEL as *const u8) as *mut u8
        } else {
            outputs.as_mut_ptr()
        };
        // SAFETY: same FFI contract as sha3_256_batch above.
        let result = catch_unwind(AssertUnwindSafe(|| unsafe {
            (self.lib.shake256)(
                self.gpu.ptr,
                inputs_ptr,
                outputs_ptr,
                input_lens.as_ptr(),
                out_lens.as_ptr(),
                n,
            )
        }));
        match result {
            Ok(LUX_OK) => {
                let mut out_vecs = Vec::with_capacity(n);
                let mut off = 0usize;
                for &len in out_lens {
                    out_vecs.push(outputs[off..off + len].to_vec());
                    off += len;
                }
                out_vecs
            }
            _ => CPU_FALLBACK.shake256_batch(inputs, out_lens),
        }
    }

    /// Override the default `tuple_hash256_batch` to go via the CPU
    /// streaming impl instead of the alloc-heavy default. This is
    /// IMPORTANT: libluxgpu 0.4 has no GPU cSHAKE primitive, so
    /// TupleHash256 work always lands on the CPU regardless of which
    /// backend the verifier picks. Routing through `CpuShake::tuple_
    /// hash256_batch` (the streaming TupleHash256 path) keeps the GPU-
    /// enabled build's wall-clock comparable to the CPU-only build.
    /// When libluxgpu adds a native cSHAKE / TupleHash batch, replace
    /// this override with a proper FFI dispatch.
    fn tuple_hash256_batch(
        &self,
        customisations: &[&[u8]],
        items: &[&[&[u8]]],
        out_lens: &[usize],
    ) -> Vec<Vec<u8>> {
        CPU_FALLBACK.tuple_hash256_batch(customisations, items, out_lens)
    }

    /// Override the default `cshake256_batch` for the same reason as
    /// `tuple_hash256_batch` above — libluxgpu 0.4 has no cSHAKE
    /// primitive (its `lux_gpu_shake256_batch` uses 0x1F domain, NOT
    /// 0x04; outputs are NOT byte-equivalent), so we route to the CPU
    /// streaming path for now. Future GPU cSHAKE: replace with FFI.
    fn cshake256_batch(
        &self,
        name: &[u8],
        customisations: &[&[u8]],
        payloads: &[&[u8]],
        out_lens: &[usize],
    ) -> Vec<Vec<u8>> {
        CPU_FALLBACK.cshake256_batch(name, customisations, payloads, out_lens)
    }

    fn name(&self) -> &'static str {
        self.name_str
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // KAT vectors from FIPS 202 (also embedded in the luxcpp test
    // suite at luxcpp/gpu/test/test_sha3_batch.cpp).
    const SHA3_256_EMPTY: [u8; 32] = [
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6,
        0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8,
        0x43, 0x4a,
    ];
    const SHA3_256_ABC: [u8; 32] = [
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90,
        0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43,
        0x15, 0x32,
    ];

    /// If libluxgpu is unreachable at a given path, `try_open_with_symbols`
    /// must return `None` (no panic). Env-var manipulation is unsafe in
    /// tests (other tests may be threading), so we test the low-level
    /// path-based loader directly.
    #[test]
    fn missing_library_falls_back_silently() {
        let result = try_open_with_symbols("/nonexistent/path/libluxgpu.so.does.not.exist");
        assert!(result.is_none(), "expected None on missing library path");
    }

    /// When libluxgpu IS available (typical dev host), parity with the
    /// CPU reference on the canonical KAT vectors.
    #[test]
    fn gpu_sha3_256_kat_when_available() {
        let Some(gpu) = try_load_default() else {
            eprintln!("libluxgpu not present — skipping GPU KAT test");
            return;
        };
        let out = gpu.sha3_256_batch(&[b"", b"abc"]);
        assert_eq!(out[0], SHA3_256_EMPTY, "GPU SHA3-256('') diverged from KAT");
        assert_eq!(
            out[1], SHA3_256_ABC,
            "GPU SHA3-256('abc') diverged from KAT"
        );
    }

    /// CPU and GPU must produce byte-identical SHAKE256 output across a
    /// range of input sizes and squeeze lengths.
    #[test]
    fn gpu_shake256_parity_with_cpu() {
        let Some(gpu) = try_load_default() else {
            eprintln!("libluxgpu not present — skipping GPU parity test");
            return;
        };
        let inputs: &[&[u8]] = &[
            b"",
            b"a",
            b"abc",
            b"the quick brown fox jumps over the lazy dog",
            &[0u8; 256],
            &[0xFFu8; 512],
        ];
        let out_lens = vec![32, 32, 64, 32, 16, 128];
        let gpu_out = gpu.shake256_batch(inputs, &out_lens);
        let cpu_out = CpuShake.shake256_batch(inputs, &out_lens);
        for (i, (g, c)) in gpu_out.iter().zip(cpu_out.iter()).enumerate() {
            assert_eq!(
                g,
                c,
                "GPU vs CPU SHAKE256 diverged for input {i} (len {}, out_len {})",
                inputs[i].len(),
                out_lens[i]
            );
        }
    }

    /// CPU and GPU must produce byte-identical SHA3-256 output across a
    /// range of input sizes.
    #[test]
    fn gpu_sha3_256_parity_with_cpu() {
        let Some(gpu) = try_load_default() else {
            eprintln!("libluxgpu not present — skipping GPU parity test");
            return;
        };
        let inputs: &[&[u8]] = &[
            b"",
            b"a",
            b"abc",
            b"the quick brown fox jumps over the lazy dog",
            &[0u8; 256],
            &[0xFFu8; 512],
        ];
        let gpu_out = gpu.sha3_256_batch(inputs);
        let cpu_out = CpuShake.sha3_256_batch(inputs);
        for (i, (g, c)) in gpu_out.iter().zip(cpu_out.iter()).enumerate() {
            assert_eq!(
                g,
                c,
                "GPU vs CPU SHA3-256 diverged for input {i} (len {})",
                inputs[i].len()
            );
        }
    }
}
