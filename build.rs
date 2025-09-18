fn main() {
    let _l = std::io::stdout().lock();

    luau0_src::Build::new()
        .enable_codegen(false)
        .set_max_cstack_size(1000000)
        .set_vector_size(3)
        .build()
        .print_cargo_metadata();

    println!("cargo::rerun-if-changed=build.rs")
}