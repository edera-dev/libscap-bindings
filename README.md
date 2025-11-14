# libscap-bindings

Basic `bindgen` types and glue generated against [Falco's libscap C library](https://github.com/falcosecurity/libs/tree/master/userspace/libscap).

Currently, only `gnu` and `musl` x86 targets are tested, and only Linux is supported.

## Usage

This crate needs build tools and build libraries sufficient to compile Falco's `libscap` C lib, which is the bulk of what [`build.rs`](./build.rs) sets up.

Since quite often you don't need the *full* bindings when you take this crate as a dep, and don't wish to incur the build and local dependency cost for building all of Falco's `libscap`, this crate exposes the `full_bindings` feature flag, which is enabled by default.

If that feature flag is **disabled**, only the simple types (enums, consts) will be emitted and exported, using previously-generated and checked versions in `src`, (namely [`src/enums.rs`](./src/enums.rs) and [`src/consts.rs`](./src/consts.rs)) so no C build is necessary for anything that only needs the simple types:

``` toml
libscap-bindings = { version = 0.0.1, default-features = false }
```

If that feature flag is **enabled** (as it is by default), the upstream libscap repo will be cloned, and a full C build will be performed, exposing function types and the full interop capability. This will also update/regen the checked-in simple types in `/src`.

``` toml
libscap-bindings = { version = 0.0.1 }
```
