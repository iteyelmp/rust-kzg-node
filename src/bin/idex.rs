use rust_kzg_blst::types::kzg_settings::FsKZGSettings;
use rust_kzg_blst::eip_7594::BlstBackend;
use kzg_traits::{EcBackend, DAS};
use kzg_traits::eth;

fn main() {
    // 1. 加载 trusted setup (Rust 原生方法)
    let mut settings = FsKZGSettings::from_file("trusted_setup.txt")
        .expect("failed to load trusted setup");

    // 2. 创建一个示例 blob
    let blob = vec![0u8; eth::BYTES_PER_BLOB];

    // 3. 准备 cells 和 proofs buffer
    let mut cells = vec![<BlstBackend as EcBackend>::Fr::default(); eth::CELLS_PER_EXT_BLOB * eth::FIELD_ELEMENTS_PER_CELL];
    let mut proofs = vec![<BlstBackend as EcBackend>::G1::default(); eth::CELLS_PER_EXT_BLOB];

    // 4. 调用 Rust 原生方法计算 cells 和 KZG proofs
    settings
        .compute_cells_and_kzg_proofs(&blob, &mut cells, &mut proofs)
        .expect("compute failed");

    println!("cells: {:?}, proofs: {:?}", &cells[..10], &proofs[..10]);
}
