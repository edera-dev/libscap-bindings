use anyhow::{Context, Result, anyhow, bail};
use flate2::read::GzDecoder;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    thread,
};
use tar::Archive;

const BPFTOOL_VERSION: &str = "7.6.0";
const BPFTOOL_ARM64_SHA: &str = "b53ff306dc1d51d64f13a2b717f6ba5687a3613b87277ad0108464cf7b886cb7";
const BPFTOOL_AMD64_SHA: &str = "51ffd3dd4f46fdc46736433a971e828dc70835c6b18ad20cabffd10abcf00358";
const BPFTOOL_RELEASE_URL: &str = "https://github.com/libbpf/bpftool/releases/download";

const LIBSCAP_REPO: &str = "https://github.com/falcosecurity/libs.git";
const LIBSCAP_CHECKOUT_SHA: &str = "7250ae96aa8878385f85a5643a43459d3d32fca4";

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_FULL_BINDINGS");
    let full_bindings_enabled = env::var("CARGO_FEATURE_FULL_BINDINGS").is_ok();

    // If the `full_bindings` feature is NOT enabled, this crate will only
    // export the simple types generated into the source tree by the last
    // "full" build with the binding feature enabled, so we can skip
    // cloning the repo and doing a full clang build.
    if !full_bindings_enabled {
        println!("cargo:rerun-if-changed=build.rs");
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let repo_dir = out_dir.join("external-libscap");
    let target = std::env::var("TARGET").unwrap();
    let is_musl = target.contains("musl");

    // Offline hook: copy a pre-fetched falcosecurity/libs tree instead of
    // cloning. The tree need not contain .git — .git-less trees take their
    // version strings from VENDOR_LIBS_VERSION / VENDOR_DRIVER_VERSION (see
    // below).
    println!("cargo:rerun-if-env-changed=VENDOR_LIBSCAP_SRC_DIR");
    // A tree copied from a previous source path must not win silently — the
    // stamp records where the tree came from so it can be recopied when the
    // path changes (e.g. a pin bump), or discarded when the hook is unset.
    let stamp = out_dir.join("external-libscap.src-stamp");
    if let Ok(src) = env::var("VENDOR_LIBSCAP_SRC_DIR") {
        // The pinned SHA is part of the stamp so a pin bump forces a recopy
        // even when the source path is unchanged.
        let stamp_val = format!("{LIBSCAP_CHECKOUT_SHA} {src}");
        let stale = fs::read_to_string(&stamp)
            .map(|s| s != stamp_val)
            .unwrap_or(true);
        if stale && repo_dir.exists() {
            fs::remove_dir_all(&repo_dir).expect("remove stale libscap tree");
        }
        if !repo_dir.exists() {
            let status = Command::new("cp")
                .args([
                    "-r",
                    "--no-preserve=mode,ownership",
                    &src,
                    repo_dir.to_str().unwrap(),
                ])
                .status()
                .expect("failed to copy VENDOR_LIBSCAP_SRC_DIR");
            assert!(status.success(), "copy of VENDOR_LIBSCAP_SRC_DIR failed");
            fs::write(&stamp, &stamp_val).expect("write libscap src stamp");
        }
    } else if stamp.exists() {
        // Hook unset after a vendored build: drop the copied tree so the
        // clone path below restores upstream behavior, and the cmake build
        // dir so the vendored version defines don't linger in CMakeCache.
        if repo_dir.exists() {
            fs::remove_dir_all(&repo_dir).expect("remove vendored libscap tree");
        }
        let _ = fs::remove_dir_all(out_dir.join("build"));
        fs::remove_file(&stamp).expect("remove libscap src stamp");
    }

    // The `bpftool` binary is a build dep of libscap. Start its download in
    // the background so it overlaps with the git fetch below (both are
    // network-bound); it is then extracted into the repo dir so we can tell
    // libscap's CMAKE to use the local one, rather than try to find a system
    // binary.
    let bpftool_download = spawn_bpftool_download(&repo_dir);

    if !repo_dir.exists()
        && let Err(err) = clone_libscap(&repo_dir)
    {
        // Remove the partially-initialized repo so the next build attempt
        // starts from scratch instead of trusting whatever half-state exists.
        let _ = fs::remove_dir_all(&repo_dir);
        panic!("Failed to fetch libscap sources: {err}");
    }

    let relative_exe =
        install_bpftool(&repo_dir, bpftool_download).expect("must fetch bpftool build dep");

    // The cmake-generated compile rules honor CMAKE_C_COMPILER_LAUNCHER
    // (sccache/ccache) from the environment, but two libscap build steps
    // bypass it: the modern_bpf eBPF objects are compiled by
    // ${MODERN_CLANG_EXE} inside add_custom_command rules, and libbpf builds
    // through a raw `make` BUILD_COMMAND with an unwrapped CC. Shim both
    // through the launcher so their compiles are cached too.
    let launcher = env::var("CMAKE_C_COMPILER_LAUNCHER")
        .ok()
        .filter(|launcher| !launcher.is_empty());
    let mut modern_clang_shim = None;
    let mut libbpf_cc_shim = None;
    if cfg!(unix)
        && let Some(launcher) = &launcher
    {
        let clang = env::var("MODERN_CLANG_EXE").unwrap_or_else(|_| "clang".to_string());
        modern_clang_shim = write_shim(&out_dir, "launcher-clang", launcher, &clang).ok();
        libbpf_cc_shim = write_shim(&out_dir, "launcher-cc", launcher, "cc").ok();
    }
    patch_libbpf_build(&repo_dir, libbpf_cc_shim.as_deref());

    let mut cmake_config = cmake::Config::new(&repo_dir);
    cmake_config
        .define("USE_BUNDLED_DEPS", "ON")
        .define("MODERN_BPFTOOL_EXE", relative_exe)
        .define("BUILD_LIBSCAP_GVISOR", "OFF")
        .define("CREATE_TEST_TARGETS", "OFF")
        .define("BUILD_LIBSCAP_MODERN_BPF", "ON")
        .define("ENABLE_PIC", "ON")
        .define("MUSL_OPTIMIZED_BUILD", if is_musl { "ON" } else { "OFF" });

    // Version strings normally come from `git describe` in the clone. A
    // vendored tree has no .git, so pass the caller-provided versions —
    // falling back to GetVersionFromGit's own no-git default rather than
    // letting git walk up from OUT_DIR and describe whatever enclosing repo
    // it happens to find.
    println!("cargo:rerun-if-env-changed=VENDOR_LIBS_VERSION");
    println!("cargo:rerun-if-env-changed=VENDOR_DRIVER_VERSION");
    if !repo_dir.join(".git").exists() {
        cmake_config.define(
            "FALCOSECURITY_LIBS_VERSION",
            env::var("VENDOR_LIBS_VERSION").unwrap_or_else(|_| "0.0.0".into()),
        );
        cmake_config.define(
            "DRIVER_VERSION",
            env::var("VENDOR_DRIVER_VERSION").unwrap_or_else(|_| "0.0.0".into()),
        );
    }

    // libscap eBPF prog loading fails the kernel verifier for kernels < 6.16
    // if the eBPF objects built with newer clang (> 16 or so).
    // However, when building under alpine/MUSL, we need static clang/llvm, which
    // require newer, more complete clang-static package versions (20 or so).
    // We get around that by building everything except the eBPF objects with one version
    // of clang/llvm, but using a specific older version override to build the `modern_bpf` progs here.
    if let Some(shim) = &modern_clang_shim {
        // The shim wraps MODERN_CLANG_EXE (or plain `clang`) in the launcher.
        cmake_config.define("MODERN_CLANG_EXE", shim);
    } else if let Ok(clang_exe) = env::var("MODERN_CLANG_EXE") {
        println!("cargo:info=Using MODERN_CLANG_EXE={}", clang_exe);
        cmake_config.define("MODERN_CLANG_EXE", clang_exe);
    }

    let dst = cmake_config.build_target("scap").build();

    println!(
        "cargo:rustc-link-search=native={}/build/libbpf-prefix/src/libbpf-build/build",
        dst.display()
    );
    println!(
        "cargo:rustc-link-search=native={}/build/libpman",
        dst.display()
    );
    println!(
        "cargo:rustc-link-search=native={}/build/libscap",
        dst.display()
    );
    println!(
        "cargo:rustc-link-search=native={}/build/libscap/linux",
        dst.display()
    );
    println!(
        "cargo:rustc-link-search=native={}/build/libscap/engine/noop",
        dst.display()
    );
    println!(
        "cargo:rustc-link-search=native={}/build/libscap/engine/modern_bpf",
        dst.display()
    );
    println!(
        "cargo:rustc-link-search=native={}/build/_deps/libelf_elftoolchain-build/libelf",
        dst.display()
    );
    println!(
        "cargo:rustc-link-search=native={}/build/zlib-prefix/src/zlib",
        dst.display()
    );

    // Link order matters
    println!("cargo:rustc-link-lib=static=scap_engine_modern_bpf");
    println!("cargo:rustc-link-lib=static=scap_engine_noop");
    println!("cargo:rustc-link-lib=static=scap");

    println!("cargo:rustc-link-lib=static=pman");
    println!("cargo:rustc-link-lib=static=scap_engine_util");
    println!("cargo:rustc-link-lib=static=scap_platform");
    println!("cargo:rustc-link-lib=static=scap_platform_util");
    println!("cargo:rustc-link-lib=static=scap_event_schema");
    println!("cargo:rustc-link-lib=static=driver_event_schema");
    println!("cargo:rustc-link-lib=static=scap_error");

    println!("cargo:rustc-link-lib=static=bpf");
    println!("cargo:rustc-link-lib=static=elf");
    println!("cargo:rustc-link-lib=static=z");

    #[derive(Debug)]
    struct StrumMacroMungeCallback;

    impl bindgen::callbacks::ParseCallbacks for StrumMacroMungeCallback {
        fn add_derives(&self, info: &bindgen::callbacks::DeriveInfo<'_>) -> Vec<String> {
            if info.kind == bindgen::callbacks::TypeKind::Enum {
                vec!["EnumIter".into(), "FromRepr".into(), "Display".into()]
            } else {
                vec![]
            }
        }
    }

    let clang_args = vec![
        format!("-I{}", repo_dir.display()),
        format!("-I{}/userspace", repo_dir.display()),
        format!("-I{}/userspace/libscap", repo_dir.display()),
        format!("-I{}/build", dst.display()),
        format!("-I{}/build/libscap", dst.display()),
        format!("-I{}/build/uthash-prefix/src/uthash/src", dst.display()),
    ];

    fn get_builder(clang_args: &[String]) -> bindgen::Builder {
        bindgen::Builder::default()
            .header("inc/libscap.h")
            .clang_args(clang_args)
            .derive_default(true)
            .derive_debug(true)
            .derive_copy(true)
            .size_t_is_usize(true)
            .default_enum_style(bindgen::EnumVariation::Rust {
                non_exhaustive: true,
            })
            .vtable_generation(true)
            .generate_pure_virtual_functions(true)
            .generate_comments(true)
            .wrap_unsafe_ops(true)
            .rust_edition(bindgen::RustEdition::Edition2024)
            .parse_callbacks(Box::new(StrumMacroMungeCallback))
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
    }

    let enum_bindings = get_builder(&clang_args)
        .allowlist_type("ppm_sc_code")
        .allowlist_type("ppm_param_type")
        .allowlist_type("ppm_event_code")
        .allowlist_type("ppm_event_flags")
        .allowlist_type("scap_fd_type")
        .allowlist_type("scap_l4_proto")
        .generate()
        .expect("Unable to generate enum bindings");

    let enum_file_path = PathBuf::from("src/enums.rs");
    enum_bindings
        .write_to_file(&enum_file_path)
        .expect("Couldn't write enum bindings!");

    // Generate constants bindings for PPM_ prefixed constants
    let const_bindings = get_builder(&clang_args)
        .allowlist_var("PPM_.*")
        .generate()
        .expect("Unable to generate const bindings");

    let const_file_path = PathBuf::from("src/consts.rs");
    const_bindings
        .write_to_file(&const_file_path)
        .expect("Couldn't write const bindings!");

    let bindings = get_builder(&clang_args)
        .raw_line(
            "use super::types::{ppm_param_type, ppm_sc_code, ppm_event_code, ppm_event_flags, scap_fd_type, scap_l4_proto};",
        )
        .blocklist_type("ppm_sc_code")
        .blocklist_type("ppm_param_type")
        .blocklist_type("ppm_event_code")
        .blocklist_type("ppm_event_flags")
        .blocklist_type("scap_fd_type")
        .blocklist_type("scap_l4_proto")
        .blocklist_var("PPM_.*")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = out_dir.join("bindings.rs");
    bindings
        .write_to_file(&out_path)
        .expect("Couldn't write bindings!");

    println!("cargo:rerun-if-changed=build.rs");
}

/// Fetch only the pinned commit rather than cloning full history (~4 MB of
/// pack data instead of ~44 MB). Fetching by SHA is content-addressed, so the
/// checked-out tree is cryptographically verified against
/// `LIBSCAP_CHECKOUT_SHA`. Git 2.49's `clone --revision=<sha>` does this in
/// one step, but not all runners/cross environments ship it yet.
fn clone_libscap(repo_dir: &Path) -> Result<()> {
    let repo = repo_dir.to_str().unwrap();
    run_git(&["init", repo])?;
    run_git(&["-C", repo, "remote", "add", "origin", LIBSCAP_REPO])?;
    run_git(&[
        "-C",
        repo,
        "fetch",
        "--depth=1",
        "origin",
        LIBSCAP_CHECKOUT_SHA,
    ])?;
    run_git(&[
        "-C",
        repo,
        "-c",
        "advice.detachedHead=false",
        "checkout",
        "--detach",
        "FETCH_HEAD",
    ])?;
    Ok(())
}

fn run_git(args: &[&str]) -> Result<()> {
    let status = Command::new("git").args(args).status()?;
    if !status.success() {
        bail!("`git {}` failed with {}", args.join(" "), status);
    }
    Ok(())
}

type BpftoolDownload = Option<thread::JoinHandle<Result<Vec<u8>>>>;

/// Start the bpftool release download on a background thread so it overlaps
/// with the libscap git fetch. Skipped (returns None) when a previously
/// downloaded archive with a good checksum is already in place.
fn spawn_bpftool_download(repo_dir: &Path) -> BpftoolDownload {
    println!("cargo:rerun-if-env-changed=VENDOR_BPFTOOL_ARCHIVE");
    let (arch, expected_sha) = get_arch_sha();
    let archive = repo_dir.join("bpftool").join(archive_name(&arch));
    if archive_checksum_ok(&archive, &expected_sha) {
        return None;
    }
    // Offline hook: read a pre-fetched archive instead of downloading,
    // enforcing the same digest the download path does.
    let vendored = env::var("VENDOR_BPFTOOL_ARCHIVE").ok();
    Some(thread::spawn(move || match vendored {
        Some(path) => read_vendored_bpftool(&path, &expected_sha),
        None => download_bpftool_bytes(&arch, &expected_sha),
    }))
}

fn read_vendored_bpftool(path: &str, expected_sha: &str) -> Result<Vec<u8>> {
    let contents = fs::read(path).with_context(|| format!("reading {path}"))?;
    verify_sha256(&contents, expected_sha, path)?;
    Ok(contents)
}

/// Extract the bpftool binary into `<repo>/bpftool/`, first landing the
/// background download if one was started (otherwise the verified,
/// previously downloaded archive is reused).
fn install_bpftool(repo_dir: &Path, download: BpftoolDownload) -> Result<String> {
    let (arch, _) = get_arch_sha();
    let bpftool_dir = repo_dir.join("bpftool");
    let archive_name = archive_name(&arch);
    if let Some(handle) = download {
        let bytes = handle
            .join()
            .map_err(|_| anyhow!("bpftool download thread panicked"))??;
        // Replace whatever stale or partial state exists before unpacking.
        let _ = fs::remove_dir_all(&bpftool_dir);
        fs::create_dir_all(&bpftool_dir)?;
        fs::write(bpftool_dir.join(&archive_name), &bytes)?;
    }
    extract_bpftool(&archive_name, &bpftool_dir)
}

fn archive_name(arch: &str) -> String {
    format!("bpftool-v{}-{}.tar.gz", BPFTOOL_VERSION, arch)
}

fn archive_checksum_ok(archive: &Path, expected_sha: &str) -> bool {
    fs::read(archive).is_ok_and(|bytes| sha256::digest(bytes.as_slice()) == expected_sha)
}

/// Write a tiny wrapper script that runs `tool` through the configured
/// compiler launcher (sccache/ccache), for build steps that don't honor
/// CMAKE_C_COMPILER_LAUNCHER on their own.
fn write_shim(out_dir: &Path, name: &str, launcher: &str, tool: &str) -> Result<PathBuf> {
    let path = out_dir.join(name);
    fs::write(&path, format!("#!/bin/sh\nexec {launcher} {tool} \"$@\"\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms)?;
    }
    Ok(path)
}

/// libscap builds libbpf via an ExternalProject BUILD_COMMAND that invokes
/// raw `make`: it cannot inherit the jobserver (so it builds -j1) and its CC
/// is never routed through the compiler launcher. Patch the pinned cmake
/// module to parallelize it and (when a launcher is active) wrap CC.
fn patch_libbpf_build(repo_dir: &Path, cc_shim: Option<&Path>) {
    let module = repo_dir.join("cmake/modules/libbpf.cmake");
    let Ok(text) = fs::read_to_string(&module) else {
        return;
    };
    let jobs = env::var("NUM_JOBS").unwrap_or_else(|_| "1".to_string());
    let mut replacement = format!("make -j{jobs}");
    if let Some(shim) = cc_shim {
        replacement.push_str(&format!(" CC={}", shim.display()));
    }
    replacement.push_str(" BUILD_STATIC_ONLY=y");
    let patched = text.replace("make BUILD_STATIC_ONLY=y", &replacement);
    if patched != text {
        let _ = fs::write(&module, patched);
    } else if !text.contains("make -j") {
        println!(
            "cargo:warning=libbpf.cmake BUILD_COMMAND pattern not found; \
             libbpf will build single-threaded without the compiler launcher"
        );
    }
}

fn get_arch_sha() -> (String, String) {
    let target = env::var("TARGET").expect("rust builds should have a target");
    if !target.contains("linux") {
        panic!("only linux targets currently supported")
    }
    if target.starts_with("x86_64") {
        ("amd64".to_string(), BPFTOOL_AMD64_SHA.to_string())
    } else if target.starts_with("aarch64") {
        ("arm64".to_string(), BPFTOOL_ARM64_SHA.to_string())
    } else {
        panic!("unsupported target arch")
    }
}

fn download_bpftool_bytes(arch: &str, expected_sha: &str) -> Result<Vec<u8>> {
    let url = format!(
        "{}/v{}/{}",
        BPFTOOL_RELEASE_URL,
        BPFTOOL_VERSION,
        archive_name(arch)
    );

    // ureq (rustls + ring, bundled webpki roots) follows the GitHub release
    // redirect to the CDN and returns an error on a non-2xx status. Its
    // read_to_vec() defaults to a 10 MiB cap and the bpftool tarball is already
    // ~9.6 MiB, so raise the limit well clear of the release size while still
    // bounding memory. The download is content-verified against expected_sha
    // below, so TLS here is defense in depth.
    let content = ureq::get(&url)
        .call()
        .with_context(|| format!("downloading bpftool from {url}"))?
        .body_mut()
        .with_config()
        .limit(64 * 1024 * 1024)
        .read_to_vec()
        .with_context(|| format!("reading bpftool response body from {url}"))?;

    verify_sha256(&content, expected_sha, &url)?;
    Ok(content)
}

fn verify_sha256(contents: &[u8], expected_sha: &str, source: &str) -> Result<()> {
    let actual_checksum = sha256::digest(contents);
    if actual_checksum != expected_sha {
        bail!(
            "checksum mismatch for {}: expected: {}, got: {}",
            source,
            expected_sha,
            actual_checksum
        );
    }
    Ok(())
}

/// returns a relative path to the bpftool binary as a string (like `bpftool/bpftool`).
/// this is in the format (binary-parent-dir/binary) as that is what cmake will understand.
fn extract_bpftool(archive_name: &str, bpftool_dir: &Path) -> Result<String> {
    let tarball_path = bpftool_dir.join(archive_name);
    let tarball_file = fs::File::open(&tarball_path)?;
    let tar_gz = GzDecoder::new(tarball_file);
    let mut archive = Archive::new(tar_gz);
    let bpftool_binary = bpftool_dir.join("bpftool");

    archive.unpack(bpftool_dir)?;

    let full_path = fs::canonicalize(bpftool_binary)?;

    if !full_path.exists() {
        bail!("could not extract bpftool");
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&full_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&full_path, perms)?;
    }

    let file_name = full_path
        .file_name()
        .expect("has filename")
        .to_str()
        .unwrap();
    let parent_name = full_path
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    let relative_path = format!("{}/{}", parent_name, file_name);
    Ok(relative_path)
}
