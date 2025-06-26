#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use std::arch::asm;

#[cfg(all(not(target_arch = "x86_64"), not(target_arch = "aarch64")))]
use std::sync::LazyLock;

use clap::Parser;
use std::{
    io::{self, Write},
    time::Instant,
};

#[cfg(feature = "hash")]
use sha3::{Digest, Sha3_256};

use std::fs;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{__cpuid,__cpuid_count};

fn print_cpuid_leaf(leaf: u32) {
    let cpuid = unsafe { __cpuid(leaf) };
    eprintln!("CPUID[0x{:08x}] = eax={:08x}, ebx={:08x}, ecx={:08x}, edx={:08x}",
             leaf, cpuid.eax, cpuid.ebx, cpuid.ecx, cpuid.edx);
}

#[cfg(target_arch = "x86_64")]
fn has_tsc() -> bool {
    let cpuid = unsafe { __cpuid(1) };
    cpuid.edx & (1 << 4) != 0
}

#[cfg(target_arch = "x86_64")]
fn has_invariant_tsc() -> bool {
    // CPUID leaf 0x80000007 (Advanced Power Management Information)
    // Bit 8 of EDX indicates "Invariant TSC"
    let cpuid = unsafe { __cpuid(0x80000007) };
    (cpuid.edx & (1 << 8)) != 0
}

#[cfg(target_arch = "x86_64")]
fn has_rdtscp() -> bool {
    // CPUID leaf 0x80000001, bit 27 of EDX indicates RDTSCP support
    let cpuid = unsafe { __cpuid(0x80000001) };
    (cpuid.edx & (1 << 27)) != 0
}

#[cfg(target_arch = "x86_64")]
fn has_tsc_deadline_timer() -> bool {
    // CPUID leaf 1, bit 24 of ECX indicates TSC deadline timer
    let cpuid = unsafe { __cpuid(0x1) };
    (cpuid.ecx & (1 << 24)) != 0
}


fn max_extended_leaf() -> u32 {
    unsafe { __cpuid(0x80000000).eax }
}

fn tsc_frequency() -> Option<u64> {
    let max_leaf = max_extended_leaf();
    if max_leaf >= 0x15 {
        let cpuid = unsafe { __cpuid_count(0x15, 0) };
        let denom = cpuid.ebx;
        let numer = cpuid.eax;
        let freq = cpuid.ecx;

        if denom != 0 && numer != 0 {
            if freq != 0 {
                // freq is the TSC frequency in Hz (optional)
                Some(freq as u64)
            } else {
                // Estimate frequency: (numer / denom) * reference clock
                // Reference clock is often 24 or 25 MHz (platform dependent)
                // For now, return as undefined
                None
            }
        } else {
            None
        }
    } else {
        None
    }
}

fn has_virtual_tsc_scaling() -> bool {
    let max_leaf = unsafe { __cpuid(0).eax };
    if max_leaf >= 0x40000010 {
        let cpuid = unsafe { __cpuid(0x40000010) };
        cpuid.eax != 0
    } else {
        false
    }
}

#[cfg(target_arch = "x86_64")]
fn measure_monotonicity() -> bool {
    // Very simple test: ensure RDTSC never goes backward in a tight loop
    let mut last = unsafe { std::arch::x86_64::_rdtsc() };
    for _ in 0..1_000_000 {
        let current = unsafe { std::arch::x86_64::_rdtsc() };
        if current < last {
            return false;
        }
        last = current;
    }
    true
}

#[cfg(target_arch = "x86_64")]
fn test_rdtsc() {
    eprintln!("🧠 TSC & CPUID Analysis\n");

    eprintln!("✅ TSC supported: {}", has_tsc());
    eprintln!("✅ RDTSCP supported: {}", has_rdtscp());
    eprintln!("✅ Invariant TSC: {}", has_invariant_tsc());
    eprintln!("✅ TSC Deadline Timer: {}", has_tsc_deadline_timer());
    eprintln!("✅ Virtual TSC scaling: {}", has_virtual_tsc_scaling());

    match tsc_frequency() {
        Some(freq) => eprintln!("✅ Reported TSC frequency: {} Hz", freq),
        None => eprintln!("❓ TSC frequency unavailable or must be estimated manually"),
    }

    eprintln!("\n🔍 Raw CPUID dumps for reference:");
    print_cpuid_leaf(0x1);           // Basic info
    print_cpuid_leaf(0x80000001);    // RDTSCP support
    print_cpuid_leaf(0x80000007);    // Invariant TSC
    print_cpuid_leaf(0x15);          // TSC frequency info (if supported)
    print_cpuid_leaf(0x40000010);    // Virtual TSC scaling (if on a VM)

    let invariant = has_invariant_tsc();
    eprintln!("  Invariant TSC: {}", invariant);

    let rdtscp = has_rdtscp();
    eprintln!("  RDTSCP supported: {}", rdtscp);

    let deadline = has_tsc_deadline_timer();
    eprintln!("  TSC Deadline Timer: {}", deadline);

    let monotonic = measure_monotonicity();
    eprintln!("  Monotonic in tight loop: {}", monotonic);

    if invariant && rdtscp && deadline && monotonic {
        eprintln!("\n✅ RDTSC is modern and stable.");
    } else {
        eprintln!("\n⚠️ RDTSC may be unstable or unsuitable for high-precision or entropy use.");
    }
}

fn get_tsc_frequency_khz() -> Option<u64> {
    let path = "/sys/devices/system/cpu/cpu0/tsc_freq_khz";
    let contents = fs::read_to_string(path).ok()?;
    contents.trim().parse::<u64>().ok()
}

/// A tool to collect entropy from CPU timing information
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Enable hashing operation during timing measurement
    #[cfg(feature = "hash")]
    #[arg(short = 'H', long)]
    hash: bool,

    /// Number of samples to collect
    #[arg(short, long, default_value_t = 1_000_000)]
    samples: usize,
}

// rdtsc typically introduces more randomness, than rdtscp
#[cfg(target_arch = "x86_64")]
#[allow(clippy::similar_names)]
#[inline(always)]
#[must_use]
pub fn rdtsc() -> u64 {
    let eax: u32;
    let edx: u32;

    unsafe {
        asm!(
          "rdtsc",
          lateout("eax") eax,
          lateout("edx") edx,
          options(nomem, nostack)
        );
    }

    (u64::from(edx) << 32) | u64::from(eax)
}

#[cfg(target_arch = "x86_64")]
#[allow(clippy::similar_names)]
#[inline(always)]
#[must_use]
pub fn rdtscp() -> u64 {
    let eax: u32;
    let edx: u32;

    unsafe {
        asm!(
          "rdtscp",
          lateout("eax") eax,
          lateout("edx") edx,
          options(nomem, nostack)
        );
    }

    (u64::from(edx) << 32) | u64::from(eax)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn get_nstime() -> u64 {
    #[cfg(feature = "rdtscp")]
    {
        rdtscp()
    }

    #[cfg(not(feature = "rdtscp"))]
    {
        rdtsc()
    }
}

#[cfg(target_arch = "aarch64")]
#[allow(clippy::similar_names)]
#[inline(always)]
#[must_use]
pub fn get_nstime() -> u64 {
    let ticks: u64;
    unsafe {
        asm!(
            "mrs x0, cntvct_el0",
            out("x0") ticks
        );
    }
    ticks
}

#[cfg(all(not(target_arch = "x86_64"), not(target_arch = "aarch64")))]
fn get_nstime() -> u64 {
    use std::time::Instant;

    static START_TIME: LazyLock<Instant> = LazyLock::new(|| Instant::now());

    let dur = Instant::now().duration_since(*START_TIME);

    dur.as_secs() * 1_000_000_000 + u64::from(dur.subsec_nanos())
}

fn calculate_min_entropy(counts: &[usize; 256], total_samples: usize) -> f64 {
    if total_samples == 0 {
        return 0.0;
    }

    // Find the maximum probability
    let max_probability = counts
        .iter()
        .map(|&count| count as f64 / total_samples as f64)
        .fold(0.0, f64::max);

    if max_probability <= 0.0 {
        return 0.0;
    }

    eprintln!("max probability: {max_probability}");

    // Calculate min-entropy: -log2(max_probability)
    -max_probability.log2()
}

fn measure_timer() {
    let measure_iterations = 1_000_000;
    let freq = match get_tsc_frequency_khz() {
        Some(s) => (s as f64) * 1000.0,
        None => 2800.0 * 1E6, // clock speed of my T470s. Change accordingly.
    };

    let begin = Instant::now();
    for _ in 0..measure_iterations {
        let _ = get_nstime();
    }
    let duration = (Instant::now() - begin).as_secs_f64();

    let calls_per_sec = measure_iterations as f64 / duration;

    eprintln!("get_nstime() calls per sec: {}", calls_per_sec);
    eprintln!(
        "estimated get_nstime() latency: {}",
        freq as f64 / calls_per_sec
    );
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    #[cfg(target_arch = "x86_64")]
    test_rdtsc();

    measure_timer();

    #[cfg(feature = "hash")]
    let mut hasher = Sha3_256::new();

    let mut counts = [0usize; 256];
    let total_samples = args.samples;

    for _ in 0..total_samples {
        let a = get_nstime();

        #[cfg(feature = "hash")]
        if args.hash {
            hasher.update(b"abc");
            let _ = hasher.finalize_reset();
        }

        let b = get_nstime();

        if let Ok(diff) = u8::try_from((b - a) & 0xFF) {
            io::stdout().write_all(&diff.to_ne_bytes())?;
            counts[diff as usize] += 1;
        } else {
            println!("{b} {a} {}", b - a);
        }
    }

    let min_entropy = calculate_min_entropy(&counts, total_samples);
    eprintln!("Min-entropy estimation: {} bits per byte", min_entropy);

    Ok(())
}
