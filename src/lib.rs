use napi_derive::napi;
use napi::{bindgen_prelude::*, Error, Status};
use tokio::task;

use rust_kzg_blst::{
    eip_4844::{
        load_trusted_setup, // 公共加载函数 (无 _rust 后缀)
        Blob,               // Blob 类型
    },
    eip_7594::compute_cell_kzg_proofs, // 公共 Cell Proofs 函数 (无 _rust 后缀)
    types::FsKZGSettings, // KZG 设置类型
    types::KzgProof, // KzgProof 类型用于返回的 proof 字节
};

use rayon::prelude::*;
use hex::encode;

#[napi]
pub struct KzgWrapper {
    settings: FsKZGSettings,
}

// 帮助函数：将 Vec<u8> 转换为 hex 字符串
fn proof_to_hex(proof: &KzgProof) -> String {
    encode(proof.to_bytes())
}

#[napi]
impl KzgWrapper {
    /// 加载可信设置（输入：三个 JsUint8Array）
    #[napi(factory)]
    pub fn load_trusted_setup(
        g1_monomial: Uint8Array,
        g1_lagrange: Uint8Array,
        g2_monomial: Uint8Array,
    ) -> Result<Self> {
        let settings = load_trusted_setup(
            &g1_monomial,
            &g1_lagrange,
            &g2_monomial,
        ).map_err(|e| Error::new(Status::GenericFailure, format!("加载可信设置失败: {:?}", e)))?;

        Ok(Self { settings })
    }

    // 单个 Blob 的 Cell Proofs 生成（CPU 密集型，但在异步批处理中会更好）
    #[napi]
    pub fn compute_cell_proofs(&self, blob_bytes: Uint8Array) -> Result<Vec<String>> {
        let blob = Blob::from_bytes(&blob_bytes)
            .map_err(|e| Error::new(Status::GenericFailure, format!("Blob 转换失败: {:?}", e)))?;

        // 使用公共函数 compute_cell_kzg_proofs
        let proofs = compute_cell_kzg_proofs(&self.settings, &blob)
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
                .map(|b| Blob::from_bytes(&b).map_err(|e| Error::new(Status::GenericFailure, format!("Blob 转换失败: {:?}", e))))
                .collect();

            let blobs = blobs?;

            // 2. 使用 rayon 并行处理所有 Blobs
            let results: Vec<Vec<String>> = blobs.par_iter()
                .map(|blob| {
                    // 使用公共函数 compute_cell_kzg_proofs
                    let proofs = compute_cell_kzg_proofs(&settings, blob)
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
