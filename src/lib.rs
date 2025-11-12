use napi_derive::napi;
use napi::{bindgen_prelude::*, Error, Status};
use tokio::task;

// 核心修正：使用 rust_kzg_blst 的公共 API，并修正导入路径
use rust_kzg_blst::eip_4844::load_trusted_setup_rust; // 修正：使用纯 Rust API 版本
use rust_kzg_blst::eip_7594::compute_cell_kzg_proofs_rust; // 修正：使用纯 Rust API 版本

// 修正类型导入的路径 (它们通常不是顶层模块的直接 re-export)
use rust_kzg_blst::types::blob::Blob; // 修正：Blob 类型通常在 types::blob 模块下
use rust_kzg_blst::types::kzg_settings::FsKZGSettings; // 修正：FsKZGSettings 类型
use rust_kzg_blst::types::proof::KzgProof; // 修正：KzgProof 类型

use rayon::prelude::*;
use hex::encode;

// 定义在 Rust 侧保存可信设置的结构体
#[napi]
pub struct KzgWrapper {
    settings: FsKZGSettings,
}

// 帮助函数：将 KzgProof 转换为 hex 字符串
fn proof_to_hex(proof: &KzgProof) -> String {
    encode(proof.to_bytes())
}

#[napi]
impl KzgWrapper {
    // Factory 函数用于从 Node.js 加载可信设置
    #[napi(factory)]
    pub fn load_trusted_setup(
        g1_monomial: Uint8Array,
        g1_lagrange: Uint8Array,
        g2_monomial: Uint8Array,
    ) -> Result<Self> {
        // 使用修正后的函数名 load_trusted_setup_rust
        let settings = load_trusted_setup_rust(
            &g1_monomial,
            &g1_lagrange,
            &g2_monomial,
        ).map_err(|e| Error::new(Status::GenericFailure, format!("加载可信设置失败: {:?}", e)))?;

        Ok(Self { settings })
    }

    // 单个 Blob 的 Cell Proofs 生成
    #[napi]
    pub fn compute_cell_proofs(&self, blob_bytes: Uint8Array) -> Result<Vec<String>> {
        let blob = Blob::from_bytes(&blob_bytes)
            .map_err(|e| Error::new(Status::GenericFailure, format!("Blob 转换失败: {:?}", e)))?;

        // 使用修正后的函数名 compute_cell_kzg_proofs_rust
        let proofs = compute_cell_kzg_proofs_rust(&self.settings, &blob)
            .map_err(|e| Error::new(Status::GenericFailure, format!("生成 proofs 失败: {:?}", e)))?;

        Ok(proofs.iter().map(proof_to_hex).collect())
    }

    // 批量 Cell Proofs 生成（高性能并行化 + 异步非阻塞）
    #[napi]
    pub async fn compute_cell_proofs_batch(&self, blobs_bytes: Vec<Uint8Array>) -> Result<Vec<Vec<String>>> {
        // 克隆 settings，以便在独立的 tokio 线程中使用
        let settings = self.settings.clone();

        // 使用 tokio::task::spawn_blocking 避免阻塞 Node.js 主线程
        let handle = task::spawn_blocking(move || {
            // 1. 将所有 Uint8Array 转换为 Blob
            let blobs: Result<Vec<Blob>> = blobs_bytes.into_iter()
                // Uint8Array 实现了 Deref<Target = [u8]>，可以直接传递给 from_bytes
                .map(|b| Blob::from_bytes(&b).map_err(|e| Error::new(Status::GenericFailure, format!("Blob 转换失败: {:?}", e))))
                .collect();

            let blobs = blobs?;

            // 2. 使用 rayon 并行处理所有 Blobs
            let results: Vec<Vec<String>> = blobs.par_iter()
                .map(|blob| {
                    // 使用修正后的函数名 compute_cell_kzg_proofs_rust
                    let proofs = compute_cell_kzg_proofs_rust(&settings, blob)
                        .map_err(|e| Error::new(Status::GenericFailure, format!("生成 proofs 失败: {:?}", e)))?;

                    Ok(proofs.iter().map(proof_to_hex).collect())
                })
                .collect::<Result<Vec<Vec<String>>>>()?;

            Ok(results)
        });

        // 等待阻塞任务完成
        handle.await.map_err(|e| Error::new(Status::GenericFailure, format!("异步任务失败: {:?}", e)))?
    }
}
