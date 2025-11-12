use napi_derive::napi;
use napi::bindgen_prelude::*;  // 包含 JsUint8Array（napi 3.x 标准类型）

// 关键修正：从依赖名 rust_kzg_blst 开始逐级导入内部模块/函数
use rust_kzg_blst::{
    eip_4844::load_trusted_setup_rust,  // 可信设置加载函数
    eip_7594::compute_cell_kzg_proofs_rust,  // Cell Proofs 生成函数
    types::{
        Blob,  // Blob 类型
        kzg_settings::FsKZGSettings  // KZG 配置类型（根据仓库实际结构调整）
    }
};

use rayon::prelude::*;
use hex::encode;

#[napi]
pub struct KzgWrapper {
    settings: FsKZGSettings,
}

#[napi]
impl KzgWrapper {
    /// 加载可信设置（输入：三个 JsUint8Array）
    #[napi(factory)]
    pub fn load_trusted_setup(
        g1_monomial: JsUint8Array,
        g1_lagrange: JsUint8Array,
        g2_monomial: JsUint8Array,
    ) -> Result<Self> {
        // 转换 JsUint8Array 为 Rust Vec<u8>
        let g1_monomial_vec = g1_monomial.into_value()?;
        let g1_lagrange_vec = g1_lagrange.into_value()?;
        let g2_monomial_vec = g2_monomial.into_value()?;

        // 调用 rust-kzg-blst 的加载函数
        let settings = load_trusted_setup_rust(
            &g1_monomial_vec,
            &g1_lagrange_vec,
            &g2_monomial_vec,
        ).map_err(|e| Error::from_reason(format!("加载可信设置失败: {:?}", e)))?;

        Ok(Self { settings })
    }

    /// 单个 Blob 生成 Cell Proofs
    #[napi]
    pub fn compute_cell_proofs(&self, blob_bytes: JsUint8Array) -> Result<Vec<String>> {
        let blob_vec = blob_bytes.into_value()?;

        // 验证 Blob 长度（128KB，EIP-7594 要求）
        if blob_vec.len() != 128 * 1024 {
            return Err(Error::from_reason("Blob 长度必须为 128KB".to_string()));
        }

        // 转换为 rust-kzg-blst 的 Blob 类型
        let blob = Blob::from_bytes(&blob_vec)
            .map_err(|e| Error::from_reason(format!("Blob 转换失败: {:?}", e)))?;

        // 生成 Proofs
        let proofs = compute_cell_proofs_rust(&self.settings, &blob)
            .map_err(|e| Error::from_reason(format!("生成 proofs 失败: {:?}", e)))?;

        // 转换为 Hex 字符串返回
        Ok(proofs.iter().map(|p| encode(p.to_bytes())).collect())
    }

    /// 批量 Blob 并行生成 Cell Proofs
    #[napi]
    pub fn compute_cell_proofs_batch(&self, blobs_bytes: Vec<JsUint8Array>) -> Result<Vec<Vec<String>>> {
        // 转换并验证所有 Blob
        let blobs: Result<Vec<Blob>> = blobs_bytes.into_iter()
            .map(|js_blob| {
                let blob_vec = js_blob.into_value()?;
                if blob_vec.len() != 128 * 1024 {
                    return Err(Error::from_reason("Blob 长度必须为 128KB".to_string()));
                }
                Blob::from_bytes(&blob_vec).map_err(|e| Error::from_reason(format!("Blob 转换失败: {:?}", e)))
            })
            .collect();

        let blobs = blobs?;

        // 并行处理每个 Blob
        let batch_results = blobs.par_iter()
            .map(|blob| {
                let proofs = compute_cell_proofs_rust(&self.settings, blob)
                    .map_err(|e| Error::from_reason(format!("生成 proofs 失败: {:?}", e)))?;
                Ok(proofs.iter().map(|p| encode(p.to_bytes())).collect())
            })
            .collect::<Result<Vec<_>>>();

        batch_results
    }
}
