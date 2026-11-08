#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::{metrics::ScoringParamsV0, util};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuneReportV0 {
    pub version: u32,
    pub count: u64,
    pub params: ScoringParamsV0,
}

pub fn tune_dir(dir: &Path) -> Result<TuneReportV0> {
    let files = util::list_files_recursive(dir)?;
    let mut count = 0u64;

    let mut sum_entropy = 0u128;
    let mut sum_comp = 0u128;
    let mut sum_mad = 0u128;

    for p in files {
        let data = std::fs::read(&p).with_context(|| format!("read {}", p.display()))?;
        if data.is_empty() {
            continue;
        }
        count += 1;

        let entropy_q32 = {
            let mut freq = [0u32; 256];
            for &b in &data {
                freq[b as usize] += 1;
            }
            let n = data.len() as f64;
            let mut h = 0.0_f64;
            for &c in &freq {
                if c == 0 {
                    continue;
                }
                let pr = (c as f64) / n;
                h -= pr * pr.log2();
            }
            let normalized = (h / 8.0).clamp(0.0, 1.0);
            (normalized * (u32::MAX as f64)) as u64
        };

        let compression_ppm = {
            let mut runs = 0u64;
            let mut last = data[0];
            for &b in &data[1..] {
                if b == last {
                    runs += 1;
                }
                last = b;
            }
            let n = data.len() as u64;
            let denom = n.saturating_sub(1).max(1);
            let compressible = (runs as f64) / (denom as f64);
            let ratio = (1.0 - compressible).clamp(0.0, 1.0);
            (ratio * 1_000_000.0) as u64
        };

        let mad_q32 = {
            let n = data.len() as f64;
            let mean = data.iter().map(|&b| b as f64).sum::<f64>() / n;
            let mad = data.iter().map(|&b| (b as f64 - mean).abs()).sum::<f64>() / n;
            let norm = (mad / 128.0).clamp(0.0, 1.0);
            (norm * (u32::MAX as f64)) as u64
        };

        sum_entropy += entropy_q32 as u128;
        sum_comp += compression_ppm as u128;
        sum_mad += mad_q32 as u128;
    }

    let params = if count == 0 {
        ScoringParamsV0::default()
    } else {
        ScoringParamsV0 {
            entropy_target_q32: (sum_entropy / (count as u128)) as u64,
            compression_target_ppm: (sum_comp / (count as u128)) as u64,
            mad_target_q32: (sum_mad / (count as u128)) as u64,
        }
    };

    Ok(TuneReportV0 {
        version: 0,
        count,
        params,
    })
}
