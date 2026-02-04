use anyhow::{Result, bail};
use flate2::read::GzDecoder;
use std::{
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
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

    if !repo_dir.exists() {
        let status = Command::new("git")
            .args(["clone", LIBSCAP_REPO, repo_dir.to_str().unwrap()])
            .status()
            .expect("Failed to clone repository");

        if !status.success() {
            panic!("Failed to clone repository");
        }

        let checkout_dir = fs::canonicalize(repo_dir.clone()).unwrap();

        let status = Command::new("git")
            .args(["checkout", LIBSCAP_CHECKOUT_SHA])
            .current_dir(checkout_dir)
            .status()
            .expect("Failed to checkout ref {}");

        if !status.success() {
            panic!("Failed to checkout repository");
        }
    }

    // TODO(bml) - Git 2.49 adds --revision, so the above can be replaced with this,
    // which is faster. Unfortunately not all runners/cross envs have that one yet.

    // if !repo_dir.exists() {
    //     println!("cargo:info=Cloning external repository...");

    //     let status = Command::new("git")
    //         .args([
    //             "clone",
    //             "--revision",
    //             libscap_checkout_sha,
    //             "https://github.com/falcosecurity/libs.git",
    //             repo_dir.to_str().unwrap(),
    //         ])
    //         .status()
    //         .expect("Failed to clone repository");

    //     if !status.success() {
    //         panic!("Failed to clone repository");
    //     }
    // }

    // the `bpftool` binary is a build dep of libscap.
    // This attemts to fetch and extract it into the build directory,
    // so we can tell libscap's CMAKE to use the local one, rather than try to find a system binary.
    let relative_exe = fetch_bpftool(&repo_dir).expect("must fetch bpftool build dep");

    let mut cmake_config = cmake::Config::new(&repo_dir);
    cmake_config
        .define("USE_BUNDLED_DEPS", "ON")
        .define("MODERN_BPFTOOL_EXE", relative_exe)
        .define("BUILD_LIBSCAP_GVISOR", "OFF")
        .define("CREATE_TEST_TARGETS", "OFF")
        .define("BUILD_LIBSCAP_MODERN_BPF", "ON")
        .define("ENABLE_PIC", "ON")
        .define("MUSL_OPTIMIZED_BUILD", if is_musl { "ON" } else { "OFF" });

    // libscap eBPF prog loading fails the kernel verifier for kernels < 6.16
    // if the eBPF objects built with newer clang (> 16 or so).
    // However, when building under alpine/MUSL, we need static clang/llvm, which
    // require newer, more complete clang-static package versions (20 or so).
    // We get around that by building everything except the eBPF objects with one version
    // of clang/llvm, but using a specific older version override to build the `modern_bpf` progs here.
    if let Ok(clang_exe) = env::var("MODERN_CLANG_EXE") {
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
        .emit_clang_ast()
        .generate()
        .expect("Unable to generate bindings");

    let out_path = out_dir.join("bindings.rs");
    bindings
        .write_to_file(&out_path)
        .expect("Couldn't write bindings!");

    println!("cargo:rerun-if-changed=build.rs");
}

/// This will check to see if a tarfile matching our desired checksum already exists
/// at the target path. If it does, then extract it and use the binary.
/// If it does not, then delete the target path and refetch, then extract the binary.
fn fetch_bpftool(out_dir: &Path) -> Result<String> {
    let bpftool_dir = out_dir.join("bpftool/");
    let (arch, expected_sha) = get_arch_sha();
    let archive_name = format!("bpftool-v{}-{}.tar.gz", BPFTOOL_VERSION, arch);
    let bpftool_archive = bpftool_dir.join(&archive_name);

    // Check if archive was previously downloaded and verify its checksum.
    // If it wasn't, or checksum seems wrong, delete everything and signal refetch.
    let should_download = if bpftool_archive.exists() {
        let mut file = fs::File::open(&bpftool_archive)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        let actual_checksum = sha256::digest(&contents);

        if actual_checksum == expected_sha {
            false
        } else {
            println!("cargo:error=bpftool checksum mismatch, redownloading");
            let _ = fs::remove_dir_all(&bpftool_dir);
            true
        }
    } else {
        let _ = fs::remove_dir_all(&bpftool_dir);
        true
    };

    let _ = fs::create_dir_all(&bpftool_dir);
    if should_download {
        download_bpftool(&expected_sha, &archive_name, &bpftool_dir)?;
    }

    extract_bpftool(&archive_name, &bpftool_dir)
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

fn download_bpftool(expected_sha: &str, archive_name: &str, bpftool_dir: &Path) -> Result<()> {
    let url = format!(
        "{}/v{}/{}",
        BPFTOOL_RELEASE_URL, BPFTOOL_VERSION, archive_name
    );

    let response = reqwest::blocking::get(&url)?;
    if !response.status().is_success() {
        bail!(format!(
            "failed to download bpftool: HTTP {:?}",
            response.status()
        ));
    }

    let content = response.bytes()?;
    let actual_checksum = sha256::digest(content.as_ref());
    if actual_checksum != expected_sha {
        bail!(
            "checksum mismatch downloading {}: expected: {}, got: {}",
            url,
            expected_sha,
            actual_checksum
        );
    }

    let tarball_path = bpftool_dir.join(archive_name);
    let mut tarball_file = fs::File::create(&tarball_path)?;
    tarball_file.write_all(&content)?;
    Ok(())
}

/// returns a relative path to the bpftool binary as a string (like `bpftool/bpftool`).
/// this is in the format (binary-parent-dir/binary) as that is what cmake will understand.
fn extract_bpftool(archive_name: &str, bpftool_dir: &PathBuf) -> Result<String> {
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
