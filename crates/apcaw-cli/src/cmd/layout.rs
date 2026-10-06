// SPDX-License-Identifier: BSD-2-Clause
//! `apcaw layout`: the key-derived phase bin order and magnitude pair order.

use serde_json::{Map, Value};

use apcaw::{layout_seed, Layout, Profile};

use crate::cli::{LayoutArgs, VerifyProfile};
use crate::cmd::Ctx;
use crate::errors::{CliError, CliResult, EXIT_OK};
use crate::keyfile::{self, KeyArg};
use crate::report::to_py_json;

/// A seed from `--seed`, range-checked like the reference.
pub fn check_seed(seed: i128) -> CliResult<u32> {
    u32::try_from(seed).map_err(|_| CliError::usage("seed must be in [0, 2**32)"))
}

/// `{"seed": s, "wb": {"phase_bins": [..], "mag_pairs": [..]}, "nb": {..}}`
/// (the reference's JSON), for `profiles`.
pub fn report(seed: u32, profiles: &[Profile]) -> (Value, Vec<Layout>) {
    let mut m = Map::new();
    m.insert("seed".into(), seed.into());
    let mut layouts = Vec::new();
    for p in profiles {
        let l = Layout::from_seed(seed, p);
        let mut e = Map::new();
        e.insert("phase_bins".into(), serde_json::to_value(&l.phase_bins).expect("serializes"));
        e.insert("mag_pairs".into(), serde_json::to_value(&l.mag_pairs).expect("serializes"));
        m.insert(p.id.into(), Value::Object(e));
        layouts.push(l);
    }
    (Value::Object(m), layouts)
}

/// Profiles selected by `--profile` (`auto` / none: both).
pub fn profiles(p: Option<VerifyProfile>) -> Vec<Profile> {
    VerifyProfile::profile(p).map_or_else(|| Profile::ALL.to_vec(), |p| vec![p])
}

pub fn run(ctx: &Ctx, a: &LayoutArgs) -> CliResult<i32> {
    let seed = match (&a.public_key, a.seed) {
        (Some(p), _) => layout_seed(keyfile::public(&KeyArg::File(p.clone()))?.as_bytes()),
        (None, Some(s)) => check_seed(s)?,
        (None, None) => return Err(CliError::usage("one of --public-key / --seed is required")),
    };
    let (rep, layouts) = report(seed, &profiles(a.profile));
    if ctx.ui.json {
        // the reference prints this one compactly
        ctx.ui.line(&to_py_json(&rep, None));
        return Ok(EXIT_OK);
    }
    ctx.ui.line(&format!("seed {seed}"));
    for l in &layouts {
        if ctx.ui.verbose > 0 {
            ctx.ui.line(&format!("  {} Kp {:?}", l.profile, l.phase_bins));
            ctx.ui.line(&format!("  {} pairs {:?}", l.profile, l.mag_pairs));
        } else {
            ctx.ui.line(&format!(
                "  {} Kp[:8] {:?}  pairs[:4] {:?}",
                l.profile,
                &l.phase_bins[..l.phase_bins.len().min(8)],
                &l.mag_pairs[..l.mag_pairs.len().min(4)]
            ));
        }
    }
    Ok(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_range() {
        assert_eq!(check_seed(0).unwrap(), 0);
        assert_eq!(check_seed(4_294_967_295).unwrap(), u32::MAX);
        assert_eq!(check_seed(-1).unwrap_err().code(), 2);
        assert_eq!(check_seed(1 << 32).unwrap_err().message(), "seed must be in [0, 2**32)");
    }

    #[test]
    fn json_keys_in_reference_order() {
        let (v, _) = report(42, &Profile::ALL);
        let s = to_py_json(&v, None);
        assert!(s.starts_with("{\"seed\": 42, \"wb\": {\"phase_bins\": ["), "{}", &s[..60]);
        assert!(s.contains("]]}, \"nb\": {\"phase_bins\": ["));
    }
}
