use napi_derive::napi;
use napi::{bindgen_prelude::*, Error, Status};
use tokio::task;

// --- 核心修正：导入策略 ---
// 1. 直接导入 C FFI 函数 (它们通常在 eip_4844 和 eip_7594 模块的顶层)
use rust_kzg_blst::eip_4844::load_trusted_setup;
use rust_kzg_blst::eip_7594::compute_cell_kzg_proofs;

// 2. 将所有 C FFI 相关的类型、常量和返回码从 `c_bindings` 模块导入
// 这是解决 E0432 错误的必要措施，因为这些符号未被正确地 re-export 到 types 模块
use rust_kzg_blst::c_bindings::{
    Blob, FsKZGSettings, KzgProof, C_KZG_RET,
    BYTES_PER_G1_POINT, BYTES_PER_G2_POINT,
};

use rayon::prelude::*;
use hex::encode;

// 定义在 Rust 侧保存可信设置的结构体
#[napi]
pub struct KzgWrapper {
    settings: FsKZGSettings,
}

// 帮助函数：将 KzgProof 转换为 hex 字符串
fn proof_to_hex(proof: &KzgProof) -> String {
    // KzgProof::to_bytes() is a method on the type
    encode(proof.to_bytes())
}

// 帮助函数：将 C_KZG_RET 转换为 Result
fn check_c_kzg_ret(ret: C_KZG_RET, context: &str) -> Result<()> {
    // C_KZG_RET::C_KZG_OK 总是 0
    if ret as u32 == 0 {
        Ok(())
    } else {
        Err(Error::new(Status::GenericFailure, format!("{}: KZG C FFI调用失败, 错误码: {}", context, ret)))
    }
}

#[napi]
impl KzgWrapper {
    // Factory 函数用于从 Node.js 加载可信设置
    #[napi(factory)]
    pub fn load_trusted_setup(
        g1_monomial_bytes: Uint8Array,
        g1_lagrange_bytes: Uint8Array,
        g2_monomial_bytes: Uint8Array,
    ) -> Result<Self> {

        let num_g1_monomial = g1_monomial_bytes.len() / BYTES_PER_G1_POINT;
        let num_g2_monomial = g2_monomial_bytes.len() / BYTES_PER_G2_POINT;

        if g1_monomial_bytes.len() % BYTES_PER_G1_POINT != 0 ||
            g2_monomial_bytes.len() % BYTES_PER_G2_POINT != 0 {
            return Err(Error::new(Status::InvalidArg, "G1或G2点字节长度错误"));
        }

        let mut settings = FsKZGSettings::default();

        // --- 修正 E0308 错误：采用已知的 8 参数 C FFI 签名 ---
        // 传递三个可信设置字节数组和各自的长度，并让 settings_out 接收结果
        let ret = unsafe {
            load_trusted_setup(
                g1_monomial_bytes.as_ptr(), // 1. g1_monomial_ptr
                num_g1_monomial as u64,     // 2. num_g1_monomial
                g1_lagrange_bytes.as_ptr(), // 3. g1_lagrange_ptr
                num_g1_monomial as u64,     // 4. num_g1_lagrange (与 g1_monomial 数量相同)
                g2_monomial_bytes.as_ptr(), // 5. g2_monomial_ptr
                num_g2_monomial as u64,     // 6. num_g2_monomial
                &mut settings,              // 7. &mut settings output
                num_g2_monomial as u64      // 8. num_g2_lagrange (与 g2_monomial 数量相同)
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

        let cell_count = 32;
        let mut proofs: Vec<KzgProof> = vec![KzgProof::default(); cell_count];

        // C FFI 签名: (proofs_ptr, blob_ptr, settings_ptr)
        let ret = unsafe {
            compute_cell_kzg_proofs(
                proofs.as_mut_ptr(),
                blob.as_ref().as_ptr(),
                &self.settings
            )
        };

        check_c_kzg_ret(ret, "生成 proofs")?;

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

                    // C FFI 签名: (proofs_ptr, blob_ptr, settings_ptr)
                    let ret = unsafe {
                        compute_cell_kzg_proofs(
                            proofs.as_mut_ptr(),
                            blob.as_ref().as_ptr(),
                            &settings
                        )
                    };

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
