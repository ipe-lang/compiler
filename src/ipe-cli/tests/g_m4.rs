//! Consolidated golden binary for the `m4` theme.
//! Each `mod` below is one original `golden_*.rs`; test identity is
//! preserved as `<module>::<fn>`. Merged to cut per-file link cost.

mod support;

#[path = "g_m4/golden_codec_auto_multimodule.rs"]
mod golden_codec_auto_multimodule;
#[path = "g_m4/golden_codec_roundtrip.rs"]
mod golden_codec_roundtrip;
#[path = "g_m4/golden_codec_shape.rs"]
mod golden_codec_shape;
#[path = "g_m4/golden_db_codec_bridge.rs"]
mod golden_db_codec_bridge;
#[path = "g_m4/golden_m4a.rs"]
mod golden_m4a;
#[path = "g_m4/golden_m4a_fns.rs"]
mod golden_m4a_fns;
#[path = "g_m4/golden_m4a_patterns.rs"]
mod golden_m4a_patterns;
#[path = "g_m4/golden_m4b_string.rs"]
mod golden_m4b_string;
#[path = "g_m4/golden_m4c_math.rs"]
mod golden_m4c_math;
#[path = "g_m4/golden_m4c_math_gate.rs"]
mod golden_m4c_math_gate;
#[path = "g_m4/golden_m4d.rs"]
mod golden_m4d;
#[path = "g_m4/golden_m4d_gate.rs"]
mod golden_m4d_gate;
#[path = "g_m4/golden_m4e.rs"]
mod golden_m4e;
#[path = "g_m4/golden_m4e_sort_by_gate.rs"]
mod golden_m4e_sort_by_gate;
#[path = "g_m4/golden_m4f_encoding.rs"]
mod golden_m4f_encoding;
#[path = "g_m4/golden_m4g_json_enc.rs"]
mod golden_m4g_json_enc;
#[path = "g_m4/golden_m4h_json_dec.rs"]
mod golden_m4h_json_dec;
