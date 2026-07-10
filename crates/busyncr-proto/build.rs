//! Compiles `proto/busyncr.proto` into tonic client/server stubs using the
//! vendored protoc binary, so builders need no system protobuf install.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // tonic-build reads PROTOC to locate the compiler.
    std::env::set_var("PROTOC", protoc);
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&["../../proto/busyncr.proto"], &["../../proto"])?;
    println!("cargo:rerun-if-changed=../../proto/busyncr.proto");
    Ok(())
}
