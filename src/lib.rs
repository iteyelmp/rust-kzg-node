use napi_derive::napi;
use napi::{bindgen_prelude::*, Error, Status};
use tokio::task;
use rayon::prelude::*;
use hex::encode;
use core::mem;

// 仅导入必要的公开类型
use kzg::eth::c_bindings::{
    Blob, KZGProof, CKzgRet, Cell, CKZGSettings,
};
use kzg::eip_4844::load_trusted_setup_rust;
use rust_kzg_blst::{
    eip_7594::compute_cells_and_kzg_proofs,
    types::kzg_settings::FsKZGSettings,
};

// 仅保留必要的常量（根据实际使用情况）
const CELLS_PER_EXT_BLOB: usize = 32;  // 用到了：初始化cells/proofs数量
const BYTES_PER_G1: usize = 48;        // 用到了：验证G1字节长度
const BYTES_PER_BLOB: usize = 4096 * 32;  // 用到了：验证Blob长度

// 辅助函数
fn proof_to_hex(proof: &KZGProof) -> String {
    encode(&proof.bytes)
}

fn check_c_kzg_ret(ret: CKzgRet, context: &str) -> Result<()> {
    if ret == CKzgRet::Ok {
        Ok(())
    } else {
        Err(Error::new(Status::GenericFailure, format!(
            "{}失败：错误码 {:?}", context, ret
        )))
    }
}

fn uint8array_to_blob(bytes: &Uint8Array) -> Result<Blob> {
    let slice = bytes.as_ref();
    if slice.len() != BYTES_PER_BLOB {
        return Err(Error::new(Status::InvalidArg, format!(
            "Blob长度错误：需{}字节，实际{}字节", BYTES_PER_BLOB, slice.len()
        )));
    }
    let mut blob = unsafe { mem::zeroed::<Blob>() };
    blob.bytes.copy_from_slice(slice);
    Ok(blob)
}

// 核心结构体
#[napi]
pub struct KzgWrapper {
    settings: FsKZGSettings,
}

#[napi]
impl KzgWrapper {
    #[napi(factory)]
    pub fn load_trusted_setup(
        g1_monomial_bytes: Uint8Array,
        g1_lagrange_bytes: Uint8Array,
        g2_monomial_bytes: Uint8Array,
    ) -> Result<Self> {
        // 验证G1/G2字节长度
        if g1_monomial_bytes.len() % BYTES_PER_G1 != 0 {
            return Err(Error::new(Status::InvalidArg, format!(
                "G1字节长度必须是{}的倍数", BYTES_PER_G1
            )));
        }
        const BYTES_PER_G2: usize = 96;  // G2点固定96字节
        if g2_monomial_bytes.len() % BYTES_PER_G2 != 0 {
            return Err(Error::new(Status::InvalidArg, format!(
                "G2字节长度必须是{}的倍数", BYTES_PER_G2
            )));
        }

        let settings = load_trusted_setup_rust(
            g1_monomial_bytes.as_ref(),
            g1_lagrange_bytes.as_ref(),
            g2_monomial_bytes.as_ref(),
        ).map_err(|e| Error::new(Status::GenericFailure, format!(
            "加载可信设置失败：{}", e
        )))?;

        Ok(Self { settings })
    }

    #[napi]
    pub async fn compute_cell_proofs_batch(&self, blobs_bytes: Vec<Uint8Array>) -> Result<Vec<Vec<String>>> {
        let rust_settings = self.settings.clone();

        let handle = task::spawn_blocking(move || {
            let blobs: Result<Vec<Blob>> = blobs_bytes.into_iter()
                .map(|bytes| uint8array_to_blob(&bytes))
                .collect();
            let blobs = blobs?;

            let results: Vec<Vec<String>> = blobs.par_iter()
                .map(|blob| {
                    // 初始化cells（无Clone依赖）
                    let mut cells = Vec::with_capacity(CELLS_PER_EXT_BLOB);
                    for _ in 0..CELLS_PER_EXT_BLOB {
                        cells.push(unsafe { mem::zeroed::<Cell>() });
                    }

                    // 初始化proofs
                    let mut proofs = Vec::with_capacity(CELLS_PER_EXT_BLOB);
                    for _ in 0..CELLS_PER_EXT_BLOB {
                        proofs.push(unsafe { mem::zeroed::<KZGProof>() });
                    }

                    // 转换设置为C侧指针（无多余unsafe）
                    let c_settings = &rust_settings as *const FsKZGSettings as *const CKZGSettings;

                    // 调用C绑定函数生成proofs
                    let ret = unsafe {
                        compute_cells_and_kzg_proofs(
                            cells.as_mut_ptr(),
                            proofs.as_mut_ptr(),
                            blob as *const Blob,
                            c_settings,
                        )
                    };

                    check_c_kzg_ret(ret, "生成Cell Proofs")?;

                    Ok(proofs.iter().map(proof_to_hex).collect())
                })
                .collect::<Result<Vec<Vec<String>>>>()?;

            Ok(results)
        });

        handle.await.map_err(|e| Error::new(Status::GenericFailure, format!(
            "异步任务失败：{}", e
        )))?
    }
}
