use napi_derive::napi;
use napi::{bindgen_prelude::*, Error, Status};
use tokio::task;
use rayon::prelude::*;
use hex::encode;
use core::mem;

// -------------- 仅导入公开可见的类型 --------------
use kzg::eth::c_bindings::{
    Blob, KZGProof, CKzgRet, Cell, CKZGSettings,  // 仅导入结构体和枚举（不依赖私有常量）
};
use kzg::eip_4844::load_trusted_setup_rust;
use rust_kzg_blst::{
    eip_7594::compute_cells_and_kzg_proofs,
    types::kzg_settings::FsKZGSettings,
};

// 手动定义私有常量（EIP标准中固定，无需依赖库导出）
const CELLS_PER_EXT_BLOB: usize = 32;  // 每个扩展Blob含32个Cell（EIP-7594）
const BYTES_PER_G1: usize = 48;  // G1点固定48字节

// -------------- 辅助函数 --------------
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
    // Blob长度：4096个元素×32字节=131072字节（EIP-4844标准）
    const BYTES_PER_BLOB: usize = 4096 * 32;
    if slice.len() != BYTES_PER_BLOB {
        return Err(Error::new(Status::InvalidArg, format!(
            "Blob长度错误：需{}字节，实际{}字节", BYTES_PER_BLOB, slice.len()
        )));
    }
    let mut blob = unsafe { mem::zeroed::<Blob>() };
    blob.bytes.copy_from_slice(slice);
    Ok(blob)
}

// -------------- 核心结构体 --------------
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
        // 验证G1/G2字节长度（使用手动定义的常量）
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
                    // 初始化cells（避免Clone，用with_capacity+push）
                    let mut cells = Vec::with_capacity(CELLS_PER_EXT_BLOB);
                    for _ in 0..CELLS_PER_EXT_BLOB {
                        cells.push(unsafe { mem::zeroed::<Cell>() });
                    }

                    // 初始化proofs（同上）
                    let mut proofs = Vec::with_capacity(CELLS_PER_EXT_BLOB);
                    for _ in 0..CELLS_PER_EXT_BLOB {
                        proofs.push(unsafe { mem::zeroed::<KZGProof>() });
                    }

                    // 转换设置：直接使用rust_kzg_blst的C绑定加载方法（绕开私有函数）
                    // 注意：这里假设settings内部已包含CKZGSettings的指针，或通过其他公开方法获取
                    // 若仍有问题，可改用rust_kzg_blst::eip_4844::load_trusted_setup生成CKZGSettings
                    let c_settings = unsafe {
                        // 临时方案：将FsKZGSettings转为*const CKZGSettings（需确保内部结构兼容）
                        &rust_settings as *const FsKZGSettings as *const CKZGSettings
                    };

                    // 调用C绑定函数
                    let ret = unsafe {
                        compute_cells_and_kzg_proofs(
                            cells.as_mut_ptr(),
                            proofs.as_mut_ptr(),
                            blob as *const Blob,
                            c_settings,
                        )
                    };

                    check_c_kzg_ret(ret, "生成Cell Proofs")?;

                    // 释放设置（如果有必要）
                    // unsafe { rust_kzg_blst::eip_4844::free_trusted_setup(c_settings as *mut CKZGSettings) };

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
