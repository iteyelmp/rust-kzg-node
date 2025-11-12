use napi_derive::napi;
use napi::bindgen_prelude::*; // 包含 Uint8Array

use rust_kzg_blst::{
    eip_7594::compute_cell_kzg_proofs_rust,   // 注意 _rust
    eip_4844::load_trusted_setup_rust,        // 注意 _rust
    types::blob::Blob,
    types::kzg_settings::FsKZGSettings,
};
use rayon::prelude::*;
use hex::encode;

#[napi]
pub struct KzgWrapper {
    settings: FsKZGSettings,
}

#[napi]
impl KzgWrapper {
    #[napi(factory)]
    pub fn load_trusted_setup(
        g1_monomial: Uint8Array,
        g1_lagrange: Uint8Array,
        g2_monomial: Uint8Array,
    ) -> Result<Self> {
        let g1_bytes = g1_monomial.to_vec();
        let g1_lagrange_bytes = g1_lagrange.to_vec();
        let g2_bytes = g2_monomial.to_vec();

        let settings = load_trusted_setup_rust(&g1_bytes, &g1_lagrange_bytes, &g2_bytes)
            .map_err(|e| Error::from_reason(format!("加载可信设置失败: {:?}", e)))?;

        Ok(Self { settings })
    }

    #[napi]
    pub fn compute_cell_proofs(&self, blob_bytes: Uint8Array) -> Result<Vec<String>> {
        let blob_vec = blob_bytes.to_vec();
        if blob_vec.len() != 128 * 1024 {
            return Err(Error::from_reason("Blob 长度必须为 128KB".to_string()));
        }

        let blob = Blob::from_bytes(&blob_vec)
            .map_err(|e| Error::from_reason(format!("Blob 转换失败: {:?}", e)))?;

        let proofs = compute_cell_kzg_proofs_rust(&self.settings, &blob)
            .map_err(|e| Error::from_reason(format!("生成 proofs 失败: {:?}", e)))?;

        Ok(proofs.iter().map(|p| encode(p.to_bytes())).collect())
    }

    #[napi]
    pub fn compute_cell_proofs_batch(&self, blobs_bytes: Vec<Uint8Array>) -> Result<Vec<Vec<String>>> {
        let blobs: Result<Vec<Vec<u8>>> = blobs_bytes.into_iter()
            .map(|b| {
                let v = b.to_vec();
                if v.len() != 128 * 1024 {
                    return Err(Error::from_reason("Blob 长度必须为 128KB".to_string()));
                }
                Ok(v)
            })
            .collect();
        let blobs = blobs?;

        let batch_results = blobs.par_iter()
            .map(|blob_vec| {
                let blob = Blob::from_bytes(blob_vec)
                    .map_err(|e| Error::from_reason(format!("Blob 转换失败: {:?}", e)))?;

                let proofs = compute_cell_kzg_proofs_rust(&self.settings, &blob)
                    .map_err(|e| Error::from_reason(format!("生成 proofs 失败: {:?}", e)))?;

                Ok(proofs.iter().map(|p| encode(p.to_bytes())).collect())
            })
            .collect::<Result<Vec<_>>>();

        batch_results
    }
}
