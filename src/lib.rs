use napi_derive::napi;
use napi::{bindgen_prelude::*, Error, Status};
use tokio::task;
use std::slice;

// 核心修正：使用 C FFI 公共接口名称，并修正类型路径
// 类型修正：使用最可能在 types 模块下直接 re-export 的路径
use rust_kzg_blst::types::{Blob, FsKZGSettings, KzgProof};

// 函数修正：使用 C FFI 公共函数 (无 _rust 后缀)，这些函数需要 c_bindings feature 暴露
use rust_kzg_blst::eip_4844::load_trusted_setup;
use rust_kzg_blst::eip_7594::compute_cell_kzg_proofs;
use rust_kzg_blst::types::C_KZG_RET;
use rust_kzg_blst::consts::{BYTES_PER_G1_POINT, BYTES_PER_G2_POINT};


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

// 帮助函数：将 C_KZG_RET 转换为 Result
fn check_c_kzg_ret(ret: C_KZG_RET, context: &str) -> Result<()> {
    // 0 is C_KZG_RET::C_KZG_OK
    if ret as u32 == 0 {
        Ok(())
    } else {
        Err(Error::new(Status::GenericFailure, format!("{}: KZG C FFI调用失败, 错误码: {}", context, ret)))
    }
}

#[napi]
impl KzgWrapper {
    // Factory 函数用于从 Node.js 加载可信设置
    // 必须使用 unsafe 调用 C FFI 函数
    #[napi(factory)]
    pub fn load_trusted_setup(
        g1_monomial_bytes: Uint8Array,
        g1_lagrange_bytes: Uint8Array,
        g2_monomial_bytes: Uint8Array,
    ) -> Result<Self> {
        if g1_monomial_bytes.len() % BYTES_PER_G1_POINT != 0 ||
            g2_monomial_bytes.len() % BYTES_PER_G2_POINT != 0 {
            return Err(Error::new(Status::InvalidArg, "G1或G2点字节长度错误"));
        }

        let mut settings = FsKZGSettings::default();

        let ret = unsafe {
            load_trusted_setup(
                g1_monomial_bytes.as_ptr(),
                g1_lagrange_bytes.as_ptr(),
                g2_monomial_bytes.as_ptr(),
                g1_monomial_bytes.len() / BYTES_PER_G1_POINT,
                g2_monomial_bytes.len() / BYTES_PER_G2_POINT,
                &mut settings
            )
        };

        check_c_kzg_ret(ret, "加载可信设置")?;

        Ok(Self { settings })
    }

    // 单个 Blob 的 Cell Proofs 生成
    #[napi]
    pub fn compute_cell_proofs(&self, blob_bytes: Uint8Array) -> Result<Vec<String>> {
        let blob = Blob::from_bytes(&blob_bytes)
            .map_err(|e| Error::new(Status::GenericFailure, format!("Blob 转换失败: {:?}", e)))?;

        let cell_count = 32; // EIP-7594: 32 cells per blob
        let mut proofs: Vec<KzgProof> = vec![KzgProof::default(); cell_count];

        // 必须使用 unsafe 调用 C FFI 函数
        let ret = unsafe {
            compute_cell_kzg_proofs(
                proofs.as_mut_ptr(),
                blob.as_ref().as_ptr(),
                &self.settings
            )
        };

        check_c_kzg_ret(ret, "生成 proofs")?;

        // 将生成的 proof 转换为 Vec<String>
        Ok(proofs.iter().map(proof_to_hex).collect())
    }

    // 批量 Cell Proofs 生成（高性能并行化 + 异步非阻塞）
    #[napi]
    pub async fn compute_cell_proofs_batch(&self, blobs_bytes: Vec<Uint8Array>) -> Result<Vec<Vec<String>>> {
        let settings = self.settings.clone();

        // 使用 tokio::task::spawn_blocking 确保 CPU 密集型任务在单独线程中执行
        let handle = task::spawn_blocking(move || {
            let cell_count = 32;

            // 1. 将所有 Uint8Array 转换为 Blob
            let blobs: Result<Vec<Blob>> = blobs_bytes.into_iter()
                .map(|b| Blob::from_bytes(&b).map_err(|e| Error::new(Status::GenericFailure, format!("Blob 转换失败: {:?}", e))))
                .collect();

            let blobs = blobs?;

            // 2. 使用 rayon 并行处理所有 Blobs
            let results: Vec<Vec<String>> = blobs.par_iter()
                .map(|blob| {
                    let mut proofs: Vec<KzgProof> = vec![KzgProof::default(); cell_count];

                    // 必须使用 unsafe 调用 C FFI 函数
                    let ret = unsafe {
                        compute_cell_kzg_proofs(
                            proofs.as_mut_ptr(),
                            blob.as_ref().as_ptr(),
                            &settings
                        )
                    };

                    // 处理 C FFI 错误码
                    check_c_kzg_ret(ret, "生成 proofs 批量处理")?;

                    Ok(proofs.iter().map(proof_to_hex).collect())
                })
                .collect::<Result<Vec<Vec<String>>>>()?;

            Ok(results)
        });

        // 等待阻塞任务完成
        handle.await.map_err(|e| Error::new(Status::GenericFailure, format!("异步任务失败: {:?}", e)))?
    }
}
