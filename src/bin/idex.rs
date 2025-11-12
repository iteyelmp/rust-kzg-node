use kzg_traits::DAS;        // trait for compute_cells_and_kzg_proofs
use kzg_traits::EcBackend;  // trait for backend
use rust_kzg_blst::BlstBackend;  // backend 类型
use rust_kzg_blst::FsKZGSettings; // KZGSettings 实现

use kzg_traits::eth;        // CELLS_PER_EXT_BLOB 等常量

fn main() {
    // 假设你有一个 trusted setup 文件
    let trusted_setup_path = "trusted_setup.txt";

    // 初始化 KZGSettings
    let settings = FsKZGSettings::load_trusted_setup(trusted_setup_path)
        .expect("failed to load trusted setup");

    // 假设 blob 已经是 Fr 向量
    let blob: Vec<<BlstBackend as EcBackend>::Fr> = vec![Default::default(); 4096];

    let mut cells = vec![<BlstBackend as EcBackend>::Fr::default(); kzg::eth::CELLS_PER_EXT_BLOB * kzg::eth::FIELD_ELEMENTS_PER_CELL];
    let mut proofs = vec![<BlstBackend as EcBackend>::G1::default(); kzg::eth::CELLS_PER_EXT_BLOB];

    // 调用 trait 方法计算 cells 和 KZG proofs
    <FsKZGSettings as DAS<BlstBackend>>::compute_cells_and_kzg_proofs(
        &settings,
        Some(&mut cells),
        Some(&mut proofs),
        &blob,
    ).expect("compute_cells_and_kzg_proofs failed");

    println!("cells: {:?}", &cells[..10]); // 打印前10个示例
    println!("proofs: {:?}", &proofs[..1]); // 打印第一个 proof
}
