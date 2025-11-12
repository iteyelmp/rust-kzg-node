// src/lib.rs
use napi_derive::napi;
use napi::bindgen_prelude::*;

use kzg::eip_4844::{load_trusted_setup_rust, blob_to_kzg_commitment_rust, bytes_to_blob};
use kzg::eip_7594::compute_cell_kzg_proofs_rust;
use kzg::types::{Blob, FsKZGSettings};

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
        let settings = load_trusted_setup_rust(
            &g1_monomial.to_vec(),
            &g1_lagrange.to_vec(),
            &g2_monomial.to_vec(),
        ).map_err(|e| Error::from_reason(format!("加载可信设置失败: {:?}", e)))?;

        Ok(Self { settings })
    }

    #[napi]
    pub fn compute_cell_proofs(&self, blob_bytes: Uint8Array) -> Result<Vec<String>> {
        let blob = Blob::from_bytes(&blob_bytes.to_vec())
            .map_err(|e| Error::from_reason(format!("Blob 转换失败: {:?}", e)))?;

        let proofs = compute_cell_kzg_proofs_rust(&self.settings, &blob)
            .map_err(|e| Error::from_reason(format!("生成 proofs 失败: {:?}", e)))?;

        Ok(proofs.iter().map(|p| encode(p.to_bytes())).collect())
    }

    #[napi]
    pub fn compute_cell_proofs_batch(&self, blobs_bytes: Vec<Uint8Array>) -> Result<Vec<Vec<String>>> {
        let blobs: Result<Vec<Blob>> = blobs_bytes.into_iter()
            .map(|b| Blob::from_bytes(&b.to_vec()).map_err(|e| Error::from_reason(format!("{:?}", e))))
            .collect();

        let blobs = blobs?;

        let results: Vec<Vec<String>> = blobs.par_iter()
            .map(|blob| {
                let proofs = compute_cell_kzg_proofs_rust(&self.settings, blob)
                    .map_err(|e| Error::from_reason(format!("生成 proofs 失败: {:?}", e)))?;
                Ok(proofs.iter().map(|p| encode(p.to_bytes())).collect())
            })
            .collect::<Result<_>>()?;

        Ok(results)
    }
}
