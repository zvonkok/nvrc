// SPDX-License-Identifier: Apache-2.0
// Copyright (c) NVIDIA CORPORATION

// Link against libc for #![no_std] builds
fn main() {
    println!("cargo:rustc-link-lib=c");
}
