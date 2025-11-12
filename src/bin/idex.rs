use rust_kzg_blst::types::kzg_settings::FsKZGSettings;
use rust_kzg_blst::eip_7594::BlstBackend;
use kzg_traits::{EcBackend, DAS};
use kzg_traits::eth; // CELLS_PER_EXT_BLOB / FIELD_ELEMENTS_PER_CELL

fn main() {
    // 加载 trusted setup
    let settings = FsKZGSettings::load_trusted_setup("trusted_setup.txt")
        .expect("failed to load trusted setup");

    // 假设你有一个 blob
    let blob = vec![0u8; eth::BYTES_PER_BLOB];

    let mut cells = vec![<BlstBackend as EcBackend>::Fr::default(); eth::CELLS_PER_EXT_BLOB * eth::FIELD_ELEMENTS_PER_CELL];
    let mut proofs = vec![<BlstBackend as EcBackend>::G1::default(); eth::CELLS_PER_EXT_BLOB];

    // 调用原生 Rust 方法
    FsKZGSettings::compute_cells_and_kzg_proofs(
        &settings,
        Some(&mut cells),
        Some(&mut proofs),
        &blob,
    ).expect("compute failed");

    println!("cells: {:?}, proofs: {:?}", &cells[..10], &proofs[..10]);
}
