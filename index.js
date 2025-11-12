import { KzgWrapper } from "./index.js";
import fs from "fs";

// 假设 trusted setup 在文件中
const g1 = fs.readFileSync("./trusted_setup_g1_monomial.bin");
const g1L = fs.readFileSync("./trusted_setup_g1_lagrange.bin");
const g2 = fs.readFileSync("./trusted_setup_g2_monomial.bin");

const wrapper = KzgWrapper.from_trusted_setup(g1, g1L, g2);

// 单个 blob
const blobBytes = fs.readFileSync("./blob_128kb.bin");
const proofs = wrapper.compute_cell_proofs(blobBytes);
console.log("proofs", proofs);

// 批量 blob
const blobs = [blobBytes, blobBytes];
const batchProofs = wrapper.compute_cell_proofs_batch(blobs);
console.log("batch proofs", batchProofs);
