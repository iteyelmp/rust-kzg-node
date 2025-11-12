// 1. 导入 napi 核心类型和属性宏
use napi_derive::napi;  // 必须导入，否则 #[napi] 无法识别
use napi::bindgen_prelude::*;  // 包含 JsUint8Array 等类型

// 2. 修正 rust-kzg-blst 模块导入（根据仓库实际结构）
use rust_kzg_blst::{
    eip_7594::compute_cell_kzg_proofs,  // EIP-7594 证明生成函数
    eip_4844::load_trusted_setup,       // 公共的可信设置加载函数（替代私有函数）
    types::{
        blob::Blob,                     // Blob 类型（实际路径）
        kzg_settings::FsKZGSettings     // KZG 配置类型
    }
};

// 3. 并行处理依赖
use rayon::prelude::*;
use hex::encode;

/// KZG 工具类（封装可信设置和证明生成）
#[napi]
pub struct KzgWrapper {
    settings: FsKZGSettings,
}

#[napi]
impl KzgWrapper {
    /// 从内存加载可信设置（g1_monomial, g1_lagrange, g2_monomial）
    #[napi(factory)]
    pub fn load_trusted_setup(
        g1_monomial: JsUint8Array,
        g1_lagrange: JsUint8Array,
        g2_monomial: JsUint8Array,
    ) -> Result<Self> {
        let g1_monomial_bytes = g1_monomial.into_value()?;
        let g1_lagrange_bytes = g1_lagrange.into_value()?;
        let g2_monomial_bytes = g2_monomial.into_value()?;

        if g1_monomial_bytes.len() != 48 * 4096 * 2 {
            return Err(Error::from_reason("g1_monomial 长度应为 48*4096*2 字节".to_string()));
        }
        if g1_lagrange_bytes.len() != 48 * 4096 * 2 {
            return Err(Error::from_reason("g1_lagrange 长度应为 48*4096*2 字节".to_string()));
        }
        if g2_monomial_bytes.len() != 65 * 96 * 2 {
            return Err(Error::from_reason("g2_monomial 长度应为 65*96*2 字节".to_string()));
        }

        // 加载可信设置（使用公共 API）
        let settings = load_trusted_setup(
            &g1_monomial_bytes,
            &g1_lagrange_bytes,
            &g2_monomial_bytes,
        ).map_err(|e| Error::from_reason(format!("加载可信设置失败: {:?}", e)))?;

        Ok(Self { settings })
    }

    /// 生成单个 Blob 的 Cell Proofs
    #[napi]
    pub fn compute_cell_proofs(&self, blob_bytes: JsUint8Array) -> Result<Vec<String>> {
        let blob_vec = blob_bytes.into_value()?;

        // 校验 Blob 长度（128KB）
        if blob_vec.len() != 128 * 1024 {
            return Err(Error::from_reason("Blob 长度必须为 128KB".to_string()));
        }

        // 转换为 Blob 类型
        let blob = Blob::from_bytes(&blob_vec)
            .map_err(|e| Error::from_reason(format!("Blob 转换失败: {:?}", e)))?;

        // 生成证明
        let proofs = compute_cell_kzg_proofs(&self.settings, &blob)
            .map_err(|e| Error::from_reason(format!("生成 proofs 失败: {:?}", e)))?;

        // 转换为 hex 字符串返回
        Ok(proofs.iter().map(|p| encode(p.to_bytes())).collect())
    }

    /// 批量生成多个 Blob 的 Cell Proofs（并行处理）
    #[napi]
    pub fn compute_cell_proofs_batch(&self, blobs_bytes: Vec<JsUint8Array>) -> Result<Vec<Vec<String>>> {
        let blobs: Result<Vec<Vec<u8>>> = blobs_bytes.into_iter()
            .map(|js_blob| {
                let blob_vec = js_blob.into_value()?;
                if blob_vec.len() != 128 * 1024 {
                    return Err(Error::from_reason("Blob 长度必须为 128KB".to_string()));
                }
                Ok(blob_vec)
            })
            .collect();
        let blobs = blobs?;

        // 并行处理每个 Blob
        let batch_results = blobs.par_iter()
            .map(|blob_vec| {
                let blob = Blob::from_bytes(blob_vec)
                    .map_err(|e| Error::from_reason(format!("Blob 转换失败: {:?}", e)))?;

                let proofs = compute_cell_kzg_proofs(&self.settings, &blob)
                    .map_err(|e| Error::from_reason(format!("生成 proofs 失败: {:?}", e)))?;

                Ok(proofs.iter().map(|p| encode(p.to_bytes())).collect())
            })
            .collect::<Result<Vec<_>>>();

        batch_results
    }
}
