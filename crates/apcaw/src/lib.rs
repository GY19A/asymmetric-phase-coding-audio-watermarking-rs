// SPDX-License-Identifier: BSD-2-Clause
//! Asymmetric Phase Coding audio watermarking, format `apcaw-v1`.
//!
//! A byte-exact port of the Python reference implementation of the format in
//! Appendix A of the paper. The core works on mono `f64` samples at
//! 44100 Hz and does no I/O; WAV helpers live behind the `wav` feature.
//!
//! ```
//! use apcaw::{keygen_from_seed, sign, verify, Options, Profile};
//! let kp = keygen_from_seed([7u8; 32]);
//! // 10 s of white noise at -20 dBFS (any 44.1 kHz mono signal works)
//! let mut s = 1u32;
//! let x: Vec<f64> = (0..441_000)
//!     .map(|_| {
//!         s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
//!         (s as f64 / 4_294_967_296.0 - 0.5) * 0.2
//!     })
//!     .collect();
//! let y = sign(&x, 44_100, &kp.secret, b"hello", &Profile::WB, &Options::v1()).unwrap();
//! let r = verify(&y, 44_100, &kp.public, None, &Options::v1(), false);
//! assert!(r.verified);
//! assert_eq!(r.message.as_deref(), Some(&b"hello"[..]));
//! ```

#![deny(missing_docs)]

pub mod embed;
pub mod error;
pub mod ffi;
pub mod inspect;
pub mod keys;
pub mod layout;
pub mod mt19937;
pub mod params;
pub mod payload;
pub mod resync;
pub mod rs;
pub mod segment;
pub mod stft;
pub mod verify;
#[cfg(feature = "wav")]
pub mod wav;

pub use embed::{sign, sign_detailed, SignInfo};
pub use error::{Error, Result};
pub use inspect::{inspect, InspectReport};
pub use keys::{keygen, keygen_from_seed, Keypair, PublicKey, SecretKey};
pub use layout::{layout, layout_seed, Layout};
pub use params::{Channel, Options, Profile, Tail, Verifier, SAMPLE_RATE};
pub use segment::{scan, sign_segmented, ScanReport, SegmentInfo};
pub use verify::{read_soft, try_verify, verify, Path, Soft, VerifyReport};
