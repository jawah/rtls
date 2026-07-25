from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path

import nox


def tests_impl(
    session: nox.Session,
    tracemalloc_enable: bool = False,
) -> None:
    # Install deps and the package itself.
    session.install("-U", "pip", "maturin", silent=False)
    session.install("-r", "dev-requirements.txt", silent=False)

    session.install(".")

    # Show the pip version.
    session.run("pip", "--version")
    # Print the Python version and bytesize.
    session.run("python", "--version")
    session.run("python", "-c", "import struct; print(struct.calcsize('P') * 8)")

    session.run(
        "python",
        "-m",
        *(
            (
                "coverage",
                "run",
                "--parallel-mode",
                "-m",
            )
            if tracemalloc_enable is False
            else ()
        ),
        "pytest",
        "-v",
        "-ra",
        f"--color={'yes' if 'GITHUB_ACTIONS' in os.environ else 'auto'}",
        "--tb=native",
        "--durations=10",
        "--strict-config",
        "--strict-markers",
        *(session.posargs or ("tests/",)),
        env={
            "PYTHONWARNINGS": "always::DeprecationWarning",
            "COVERAGE_CORE": "sysmon",
            "PYTHONTRACEMALLOC": "25" if tracemalloc_enable else "",
        },
    )


@nox.session(
    python=[
        "3.7",
        "3.8",
        "3.9",
        "3.10",
        "3.11",
        "3.12",
        "3.13",
        "3.14",
        "3.13t",
        "3.14t",
    ]
)
def test(session: nox.Session) -> None:
    tests_impl(session)


@nox.session(python=["3.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14"])
def tracemalloc(session: nox.Session) -> None:
    tests_impl(session, tracemalloc_enable=True)


@nox.session()
def format(session: nox.Session) -> None:
    """Run code formatters."""
    lint(session)


@nox.session
def lint(session: nox.Session) -> None:
    session.install("pre-commit")
    session.run("pre-commit", "run", "--all-files")


ROOT = Path(__file__).parent.resolve()
WASI_SDK_VERSION = "33.0"
COMPONENTIZE_PY_VERSION = "0.25.0"
WASMTIME_VERSION = "47.0.1"
WASI_RUST_VERSION = "1.97.0"


@nox.session(python="3.12")
def wasi(session: nox.Session) -> None:
    """Build and run the real-network WASI TLS survival suite."""
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        session.error("the WASI smoke session requires Linux x86-64")

    session.install(f"componentize-py=={COMPONENTIZE_PY_VERSION}")

    cache = ROOT / ".nox" / "wasi-cache"
    cache.mkdir(parents=True, exist_ok=True)

    configured_sidecar = os.environ.get("RTLS_WASI_SIDECAR")
    sidecar = ROOT / "src" / "rtls" / "_wasi" / "_rustls.abi3.so"

    if configured_sidecar:
        shutil.copy2(Path(configured_sidecar), sidecar)
    else:
        sdk_name = f"wasi-sdk-{WASI_SDK_VERSION}-x86_64-linux"
        sdk = cache / sdk_name
        if not sdk.exists():
            sdk_archive = cache / f"{sdk_name}.tar.gz"
            session.run(
                "curl",
                "-fL",
                "https://github.com/WebAssembly/wasi-sdk/releases/download/"
                f"wasi-sdk-33/{sdk_archive.name}",
                "-o",
                str(sdk_archive),
                external=True,
            )
            session.run("tar", "-xf", str(sdk_archive), "-C", str(cache), external=True)

        rustc_version = subprocess.check_output(
            ("rustc", "--version"), text=True
        ).split()[1]
        cargo_toolchain: tuple[str, ...] = ()
        if rustc_version != WASI_RUST_VERSION:
            session.run(
                "rustup",
                "toolchain",
                "install",
                WASI_RUST_VERSION,
                "--profile",
                "minimal",
                "--target",
                "wasm32-wasip1",
                external=True,
            )
            cargo_toolchain = (f"+{WASI_RUST_VERSION}",)
        else:
            session.run("rustup", "target", "add", "wasm32-wasip1", external=True)
        session.run("rustc", *cargo_toolchain, "--version", external=True)

        cargo_target = ROOT / ".nox" / "wasi-target"
        wasi_lib = sdk / "share" / "wasi-sysroot" / "lib" / "wasm32-wasip1"
        compiler = sdk / "bin" / "clang"
        archiver = sdk / "bin" / "ar"
        env = {
            "PYO3_NO_PYTHON": "1",
            "CARGO_TARGET_DIR": str(cargo_target),
            "CARGO_TARGET_WASM32_WASIP1_LINKER": str(compiler),
            "CC_wasm32_wasip1": str(compiler),
            "AR_wasm32_wasip1": str(archiver),
            "CFLAGS_wasm32_wasip1": (
                f"--target=wasm32-wasip1 "
                f"--sysroot={sdk / 'share' / 'wasi-sysroot'} -fPIC"
            ),
            "RUSTFLAGS": " ".join(
                (
                    f"-C link-arg=-L{wasi_lib}",
                    "-C link-self-contained=no",
                    "-C link-arg=-Wl,--experimental-pic",
                    "-C link-arg=-Wl,--shared",
                    "-C link-arg=-Wl,--allow-undefined",
                    "-C relocation-model=pic",
                )
            ),
        }
        session.run(
            "cargo",
            *cargo_toolchain,
            "build",
            "--manifest-path",
            "rust/Cargo.toml",
            "--target",
            "wasm32-wasip1",
            "--release",
            env=env,
            external=True,
        )
        shutil.copy2(
            cargo_target / "wasm32-wasip1" / "release" / "_rustls.wasm",
            sidecar,
        )

    if sidecar.read_bytes()[:4] != b"\0asm":
        session.error("rtls WASI sidecar is not a WebAssembly module")

    componentize_name = f"componentize-py-{COMPONENTIZE_PY_VERSION}"
    componentize_source = cache / componentize_name
    if not componentize_source.exists():
        componentize_archive = cache / f"{componentize_name}.tar.gz"
        session.run(
            "curl",
            "-fL",
            "https://github.com/bytecodealliance/componentize-py/archive/refs/tags/"
            f"v{COMPONENTIZE_PY_VERSION}.tar.gz",
            "-o",
            str(componentize_archive),
            external=True,
        )
        session.run(
            "tar",
            "-xf",
            str(componentize_archive),
            "-C",
            str(cache),
            external=True,
        )
    componentize_wit = componentize_source / "wit"

    configured_wasmtime = os.environ.get("WASMTIME")
    installed_wasmtime = shutil.which("wasmtime")
    default_wasmtime = Path.home() / ".wasmtime" / "bin" / "wasmtime"
    if configured_wasmtime:
        wasmtime = Path(configured_wasmtime).expanduser().resolve()
    elif installed_wasmtime:
        wasmtime = Path(installed_wasmtime).resolve()
    elif default_wasmtime.exists():
        wasmtime = default_wasmtime
    else:
        wasmtime_name = f"wasmtime-v{WASMTIME_VERSION}-x86_64-linux"
        wasmtime_root = cache / wasmtime_name
        wasmtime = wasmtime_root / "wasmtime"
        if not wasmtime.exists():
            wasmtime_archive = cache / f"{wasmtime_name}.tar.xz"
            session.run(
                "curl",
                "-fL",
                "https://github.com/bytecodealliance/wasmtime/releases/download/"
                f"v{WASMTIME_VERSION}/{wasmtime_archive.name}",
                "-o",
                str(wasmtime_archive),
                external=True,
            )
            session.run(
                "tar",
                "-xf",
                str(wasmtime_archive),
                "-C",
                str(cache),
                external=True,
            )

    artifacts = ROOT / ".nox" / "wasi-artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)

    site_packages = artifacts / "site-packages"
    if site_packages.exists():
        shutil.rmtree(site_packages)
    session.install("--target", str(site_packages), "wassima>=1,<3")

    component = artifacts / "smoke.wasm"
    session.run(
        "componentize-py",
        "-d",
        str(componentize_wit),
        "-d",
        str(ROOT / "wasi" / "world.wit"),
        "-w",
        "test:dual/command",
        "componentize",
        "-p",
        str(ROOT / "bin"),
        "-p",
        str(ROOT / "src"),
        "-p",
        str(site_packages),
        "smoke",
        "-o",
        str(component),
    )
    session.run("sha256sum", str(sidecar), str(component), str(wasmtime), external=True)
    session.run(
        str(wasmtime),
        "run",
        "-S",
        "p3=y",
        "-S",
        "inherit-network=y",
        "-S",
        "allow-ip-name-lookup=y",
        "-S",
        "tcp=y",
        str(component),
        external=True,
    )
