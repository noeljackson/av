fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("locate vendored protoc");
    // The generated client/server contract must use the identical, pinned
    // compiler on a developer workstation and in the release builder.
    unsafe { std::env::set_var("PROTOC", protoc) };
    connectrpc_build::Config::new()
        .files(&["proto/av/v1/av.proto"])
        .includes(&["proto"])
        .include_file("_connectrpc.rs")
        .compile()
        .expect("compile AV Connect contract");
}
