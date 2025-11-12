use napi::{bindgen_prelude::*, JsUint8Array};
use rust_kzg_blst::{
    kzg::Blob,
    eip_7594::compute_cell_kzg_proofs,
    eip_4844::load_trusted_setup_rust,
    types::kzg_settings::FsKZGSettings,
};
use rayon::prelude::*;
use hex;

#[napi]
pub struct KzgWrapper {
    settings: FsKZGSettings,
}

#[napi]
impl KzgWrapper {
    /// 从内存加载 trusted setup（g1_monomial, g1_lagrange, g2_monomial 三个 Uint8Array）
    #[napi(factory)]
    pub fn load_trusted_setup (
        g1_monomial: JsUint8Array,
        g1_lagrange: JsUint8Array,
        g2_monomial: JsUint8Array,
    ) -> Result<Self> {
        let g1_monomial_bytes = g1_monomial.into_value()?;
        let g1_lagrange_bytes = g1_lagrange.into_value()?;
        let g2_monomial_bytes = g2_monomial.into_value()?;

        // 可选长度校验
        if g1_monomial_bytes.len() != 48 * 4096 * 2 {
            return Err(Error::from_reason("g1_monomial 长度错误".to_string()));
        }
        if g1_lagrange_bytes.len() != 48 * 4096 * 2 {
            return Err(Error::from_reason("g1_lagrange 长度错误".to_string()));
        }
        if g2_monomial_bytes.len() != 65 * 96 * 2 {
            return Err(Error::from_reason("g2_monomial 长度错误".to_string()));
        }

        let settings = load_trusted_setup_rust(
            &g1_monomial_bytes,
            &g1_lagrange_bytes,
            &g2_monomial_bytes,
        ).map_err(|e| Error::from_reason(format!("加载 trusted setup 失败: {:?}", e)))?;

        Ok(Self { settings })
    }

    /// 单个 blob 的 cell proofs
    #[napi]
    pub fn compute_cell_proofs(&self, blob_bytes: JsUint8Array) -> Result<Vec<String>> {
        let blob_vec = blob_bytes.into_value()?;
        if blob_vec.len() != 128 * 1024 {
            return Err(Error::from_reason("Blob 长度必须为 128KB".to_string()));
        }

        let blob = Blob::from_bytes(&blob_vec)
            .map_err(|e| Error::from_reason(format!("Blob 转换失败: {:?}", e)))?;

        let proofs = compute_cell_kzg_proofs(&self.settings, &blob)
            .map_err(|e| Error::from_reason(format!("生成 proofs 失败: {:?}", e)))?;

        Ok(proofs.iter().map(|p| hex::encode(p.to_bytes())).collect())
    }

    /// 批量 blob 并行处理
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

        let pool = rayon::ThreadPoolBuilder::new().num_threads(6).build().unwrap();
        let batch_results = pool.install(|| {
            blobs.par_iter()
                .map(|blob_vec| {
                    let blob = Blob::from_bytes(blob_vec)
                        .map_err(|e| Error::from_reason(format!("Blob 转换失败: {:?}", e)))?;

                    let proofs = compute_cell_kzg_proofs(&self.settings, &blob)
                        .map_err(|e| Error::from_reason(format!("生成 proofs 失败: {:?}", e)))?;

                    Ok(proofs.iter().map(|p| hex::encode(p.to_bytes())).collect())
                })
                .collect::<Result<Vec<_>>>()
        });

        batch_results
    }
}
