 # RDTSC Tests

 This project collects entropy from CPU timing information using the RDTSC instruction on x86_64 or equivalent timing functions on other architectures. It measures the time differences between consecutive calls to the timing function and outputs the lower 8 bits of these differences to stdout.

 ## Features

 - Collects timing differences using architecture-specific instructions (RDTSC on x86_64, CNTVCT_EL0 on aarch64)
 - Calculates and displays min-entropy estimation for the collected data
 - Outputs raw binary data to stdout for further analysis

 ## Building for aarch64

 ```
 CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-Clink-self-contained=yes -Clinker=rust-lld" cargo build --target aarch64-unknown-linux-musl
 ```

 ## Usage

 Run the program to collect timing differences and estimate min-entropy:

 ```
 cargo run > output.bin
 ```

 The min-entropy estimation will be printed to stderr, while the raw binary data will be saved to output.bin.

 ### Command Line Options

 The program supports the following command line options:

 - `--hash` or `-H`: Enable hashing operation during timing measurement. This can affect the timing differences and potentially increase entropy.
 - `--samples` or `-s`: Specify the number of samples to collect (default: 1,000,000).

 Examples:

 ```
 # Run with hashing enabled
 cargo run -- --hash > output.bin

 # Run with 2 million samples
 cargo run -- --samples 2000000 > output.bin

 # Run with both options
 cargo run -- --hash --samples 500000 > output.bin
 ```
