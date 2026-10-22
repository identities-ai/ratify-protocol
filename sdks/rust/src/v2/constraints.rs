//! Protocol v2 closed constraint registry (SPEC-v2 §5.2, Go
//! `constraints_v2.go`).
//!
//! The registered types and their exact wire members are `time_window`
//! (`end`, `start`, `tz`), `max_amount` (`currency`, `max_amount_micros`),
//! `max_rate` (`count`, `window_s`), `resource_path` (`resource_id`, optional
//! `path_prefix`) and `ratify.receiver_audience` (`params`). Every other type,
//! including the v1 geo and speed types, is unregistered: it may carry only
//! `type` and an optional `params` object and evaluates as
//! `constraint_unknown`. No v2 constraint member is a floating-point number.

use std::collections::BTreeMap;

use super::errors::{plain, V2Error, V2Result};
use super::json::{canonical, obj, parse_json, JNode, CJ, JV};
use super::limits::{V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS, V2_MAX_RATE_WINDOW_SECONDS};
use crate::canonical::wire_int::MAX_SAFE_INTEGER;
use crate::resource_path::validate_params_value;
use crate::types::{ParamsValue, MAX_IDENTIFIER_LENGTH_BYTES};

pub const CONSTRAINT_TIME_WINDOW: &str = "time_window";
pub const CONSTRAINT_MAX_AMOUNT: &str = "max_amount";
pub const CONSTRAINT_MAX_RATE: &str = "max_rate";
pub const CONSTRAINT_RESOURCE_PATH: &str = "resource_path";
/// Constraint type of the v2 receiver-audience constraint.
pub const CONSTRAINT_RECEIVER_AUDIENCE: &str = "ratify.receiver_audience";
/// Bound on each receiver-audience ID array.
pub const MAX_AUDIENCE_IDS_V2: usize = 64;

/// One entry of a v2 delegation certificate's `constraints` array. Only the
/// members of the registered schema for `kind` are encoded; an empty
/// `path_prefix` is absent.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConstraintV2 {
    pub kind: String,
    // time_window
    pub start: String,
    pub end: String,
    pub tz: String,
    // max_amount
    pub currency: String,
    pub max_amount_micros: i64,
    // max_rate
    pub count: i64,
    pub window_s: i64,
    // resource_path
    pub resource_id: String,
    pub path_prefix: String,
    /// `ratify.receiver_audience` and unregistered types.
    pub params: Option<BTreeMap<String, ParamsValue>>,
}

/// Verifier-authenticated action inputs that registered v2 constraints and
/// extension evaluator profiles read. `requested_amount_micros` uses the same
/// 10^-6 major-unit scale as `max_amount_micros`. Callers apply every decoding
/// and normalization step to resource inputs first; the verifier compares
/// bytes exactly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConstraintContextV2 {
    pub requested_amount_micros: i64,
    pub requested_currency: String,
    pub has_amount: bool,
    pub requested_resource_id: String,
    pub requested_path: String,
    pub has_resource: bool,
    /// Authenticated named quantities for extension evaluator profiles.
    pub extension_counts: BTreeMap<String, i64>,
    /// Authenticated named exact values for extension evaluator profiles.
    pub extension_values: BTreeMap<String, String>,
}

fn is_registered_structured(kind: &str) -> bool {
    matches!(
        kind,
        CONSTRAINT_TIME_WINDOW | CONSTRAINT_MAX_AMOUNT | CONSTRAINT_MAX_RATE | CONSTRAINT_RESOURCE_PATH
    )
}

/// Whether `kind` is in the closed v2 registry.
pub fn is_registered_constraint_type_v2(kind: &str) -> bool {
    is_registered_structured(kind) || kind == CONSTRAINT_RECEIVER_AUDIENCE
}

pub(crate) fn params_cj(value: &ParamsValue) -> CJ {
    match value {
        ParamsValue::Null => CJ::Null,
        ParamsValue::Bool(b) => CJ::Bool(*b),
        ParamsValue::Int(n) => CJ::Int(*n),
        ParamsValue::Str(s) => CJ::Str(s.clone()),
        ParamsValue::Array(items) => CJ::Arr(items.iter().map(params_cj).collect()),
        ParamsValue::Object(map) => CJ::Obj(
            map.iter()
                .map(|(k, v)| (k.clone(), params_cj(v)))
                .collect(),
        ),
    }
}

pub(crate) fn params_map_cj(map: &BTreeMap<String, ParamsValue>) -> CJ {
    CJ::Obj(map.iter().map(|(k, v)| (k.clone(), params_cj(v))).collect())
}

fn node_to_params(node: &JNode) -> V2Result<ParamsValue> {
    Ok(match &node.v {
        JV::Null => ParamsValue::Null,
        JV::Bool(b) => ParamsValue::Bool(*b),
        JV::Num(t) => ParamsValue::Int(
            t.parse::<i64>()
                .map_err(|_| V2Error::plain("params values must be safe integers"))?,
        ),
        JV::Str(s) => ParamsValue::Str(s.clone()),
        JV::Arr(items) => {
            ParamsValue::Array(items.iter().map(node_to_params).collect::<V2Result<_>>()?)
        }
        JV::Obj(fields) => {
            let mut map = BTreeMap::new();
            for (k, v) in fields {
                map.insert(k.clone(), node_to_params(v)?);
            }
            ParamsValue::Object(map)
        }
    })
}

fn params_object(node: &JNode) -> V2Result<Option<BTreeMap<String, ParamsValue>>> {
    match node_to_params(node)? {
        ParamsValue::Object(map) => Ok(Some(map)),
        _ => Ok(None),
    }
}

impl ConstraintV2 {
    /// The canonical JSON value of this constraint (Go `MarshalJSON`):
    /// exactly the registered members for its type, validated against the
    /// closed registry.
    pub(crate) fn to_cj(&self) -> V2Result<CJ> {
        let mut fields: Vec<(&str, CJ)> = vec![("type", CJ::s(&self.kind))];
        match self.kind.as_str() {
            CONSTRAINT_TIME_WINDOW => {
                fields.push(("start", CJ::s(&self.start)));
                fields.push(("end", CJ::s(&self.end)));
                fields.push(("tz", CJ::s(&self.tz)));
            }
            CONSTRAINT_MAX_AMOUNT => {
                fields.push(("currency", CJ::s(&self.currency)));
                fields.push(("max_amount_micros", CJ::Int(self.max_amount_micros)));
            }
            CONSTRAINT_MAX_RATE => {
                fields.push(("count", CJ::Int(self.count)));
                fields.push(("window_s", CJ::Int(self.window_s)));
            }
            CONSTRAINT_RESOURCE_PATH => {
                fields.push(("resource_id", CJ::s(&self.resource_id)));
                if !self.path_prefix.is_empty() {
                    fields.push(("path_prefix", CJ::s(&self.path_prefix)));
                }
            }
            _ => {
                if let Some(params) = &self.params {
                    fields.push(("params", params_map_cj(params)));
                }
            }
        }
        if self.params.is_some() && is_registered_structured(&self.kind) {
            return plain(format!("v2 constraint type {:?} must not carry params", self.kind));
        }
        let value = CJ::obj(fields);
        let encoded = canonical(&value)?;
        validate_v2_constraint_fields(&parse_json(&encoded)?)?;
        Ok(value)
    }

    /// Canonical JSON bytes of this constraint.
    pub fn canonical_json(&self) -> V2Result<Vec<u8>> {
        canonical(&self.to_cj()?)
    }

    /// Decode one constraint that already passed
    /// [`validate_v2_constraint_fields`] (Go `UnmarshalJSON`).
    pub(crate) fn from_node(node: &JNode) -> V2Result<ConstraintV2> {
        validate_v2_constraint_fields(node)?;
        let o = obj(node)?;
        let mut out = ConstraintV2 {
            kind: o.str("type")?,
            ..ConstraintV2::default()
        };
        match out.kind.as_str() {
            CONSTRAINT_TIME_WINDOW => {
                out.start = o.str("start")?;
                out.end = o.str("end")?;
                out.tz = o.str("tz")?;
            }
            CONSTRAINT_MAX_AMOUNT => {
                out.currency = o.str("currency")?;
                out.max_amount_micros = o.i64("max_amount_micros")?;
            }
            CONSTRAINT_MAX_RATE => {
                out.count = o.i64("count")?;
                out.window_s = o.i64("window_s")?;
            }
            CONSTRAINT_RESOURCE_PATH => {
                out.resource_id = o.str("resource_id")?;
                out.path_prefix = o.str("path_prefix")?;
            }
            _ => {
                if let Some(raw) = o.get("params") {
                    out.params = params_object(raw)?;
                }
            }
        }
        Ok(out)
    }

    /// Strictly decode one constraint object from JSON bytes.
    pub fn decode(data: &[u8]) -> V2Result<ConstraintV2> {
        ConstraintV2::from_node(&parse_json(data)?)
            .map_err(|e| e.classify(super::errors::V2ErrorClass::Malformed))
    }
}

fn check_v2_nulls(node: &JNode) -> V2Result<()> {
    match &node.v {
        JV::Null => plain("null is not allowed in this v2 object"),
        JV::Obj(fields) => {
            for (k, v) in fields {
                if k != "params" {
                    check_v2_nulls(v)?;
                }
            }
            Ok(())
        }
        JV::Arr(items) => items.iter().try_for_each(check_v2_nulls),
        _ => Ok(()),
    }
}

/// Go `v2IntegerField`: a JSON integer token in the safe-integer range.
pub(crate) fn v2_integer_field(node: &JNode) -> V2Result<i64> {
    let JV::Num(token) = &node.v else {
        return plain("integer is required");
    };
    let digits = token.strip_prefix('-').unwrap_or(token);
    if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
        return plain(format!("integer {token:?} is not canonical"));
    }
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return plain(format!("integer {token:?} is not a JSON integer"));
    }
    if token == "-0" {
        return plain("negative zero is not a canonical integer");
    }
    match token.parse::<i64>() {
        Ok(n) if (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&n) => Ok(n),
        _ => plain(format!("integer {token:?} is outside the safe-integer range")),
    }
}

/// Go `v2StringField`.
pub(crate) fn v2_string_field(node: &JNode) -> V2Result<String> {
    match &node.v {
        JV::Str(s) => Ok(s.clone()),
        _ => plain("string is required"),
    }
}

pub(crate) fn valid_iso4217_alpha_v2(code: &str) -> bool {
    code.len() == 3 && code.bytes().all(|b| b.is_ascii_uppercase())
}

/// SPEC-v2 §5.2 `tz` shape: 1 to 64 ASCII bytes of `/`-separated segments of
/// `[A-Za-z0-9_+-]`, with no empty, `.` or `..` segment.
pub(crate) fn valid_time_zone_id_v2(tz: &str) -> bool {
    if tz.is_empty() || tz.len() > 64 {
        return false;
    }
    tz.split('/').all(|segment| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'+' || c == b'-')
    })
}

/// Exactly `HH:MM` with hours 00..23 and minutes 00..59; the minute of day.
pub(crate) fn parse_hhmm_v2(s: &str) -> V2Result<i64> {
    let b = s.as_bytes();
    if b.len() != 5 || b[2] != b':' || ![0, 1, 3, 4].iter().all(|&i| b[i].is_ascii_digit()) {
        return plain(format!("expected HH:MM, got {s:?}"));
    }
    let h = i64::from(b[0] - b'0') * 10 + i64::from(b[1] - b'0');
    let m = i64::from(b[3] - b'0') * 10 + i64::from(b[4] - b'0');
    if h > 23 || m > 59 {
        return plain(format!("out-of-range HH:MM {s:?}"));
    }
    Ok(h * 60 + m)
}

/// Enforce the closed v2 constraint registry on one parsed constraint
/// object (Go `validateV2ConstraintFields`).
pub(crate) fn validate_v2_constraint_fields(node: &JNode) -> V2Result<()> {
    check_v2_nulls(node)?;
    let JV::Obj(fields) = &node.v else {
        return plain("constraint must be an object");
    };
    let get = |name: &str| fields.iter().find(|(k, _)| k == name).map(|(_, v)| v);
    let kind = match get("type").map(|v| &v.v) {
        Some(JV::Str(s)) if !s.is_empty() => s.clone(),
        _ => return plain("constraint type must be a non-empty string"),
    };
    let exact = |required: &[&str], optional: &[&str]| -> V2Result<()> {
        for (key, _) in fields {
            if key != "type" && !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
                return plain(format!("field {key:?} is not allowed for constraint type {kind:?}"));
            }
        }
        for name in required {
            if get(name).is_none() {
                return plain(format!("constraint type {kind:?} requires field {name:?}"));
            }
        }
        Ok(())
    };
    let required_node = |name: &str| -> V2Result<&JNode> {
        get(name).ok_or_else(|| V2Error::plain(format!("constraint requires field {name:?}")))
    };
    match kind.as_str() {
        CONSTRAINT_TIME_WINDOW => {
            exact(&["start", "end", "tz"], &[])?;
            for name in ["start", "end"] {
                let value = v2_string_field(required_node(name)?)
                    .map_err(|_| V2Error::plain(format!("time_window {name} must be a string")))?;
                parse_hhmm_v2(&value).map_err(|e| e.context(format!("time_window {name}")))?;
            }
            match v2_string_field(required_node("tz")?) {
                Ok(tz) if valid_time_zone_id_v2(&tz) => {}
                _ => {
                    return plain(
                        "time_window tz must be 1 to 64 bytes of /-separated [A-Za-z0-9_+-] segments",
                    )
                }
            }
        }
        CONSTRAINT_MAX_AMOUNT => {
            exact(&["currency", "max_amount_micros"], &[])?;
            match v2_string_field(required_node("currency")?) {
                Ok(c) if valid_iso4217_alpha_v2(&c) => {}
                _ => return plain("max_amount currency must be an ISO-4217 alphabetic code"),
            }
            match v2_integer_field(required_node("max_amount_micros")?) {
                Ok(n) if n >= 0 => {}
                _ => return plain("max_amount_micros must be a nonnegative safe integer"),
            }
        }
        CONSTRAINT_MAX_RATE => {
            exact(&["count", "window_s"], &[])?;
            match v2_integer_field(required_node("count")?) {
                Ok(n) if n > 0 => {}
                _ => return plain("max_rate count must be a positive safe integer"),
            }
            match v2_integer_field(required_node("window_s")?) {
                Ok(n) if n > 0 && n <= V2_MAX_RATE_WINDOW_SECONDS => {}
                _ => {
                    return plain(format!(
                        "max_rate window_s must be an integer in 1..{V2_MAX_RATE_WINDOW_SECONDS}"
                    ))
                }
            }
        }
        CONSTRAINT_RESOURCE_PATH => {
            exact(&["resource_id"], &["path_prefix"])?;
            match v2_string_field(required_node("resource_id")?) {
                Ok(id) if !id.is_empty() && id.len() <= MAX_IDENTIFIER_LENGTH_BYTES => {}
                _ => return plain(
                    "resource_path resource_id must be a non-empty string within MAX_IDENTIFIER_LENGTH_BYTES",
                ),
            }
            if let Some(raw) = get("path_prefix") {
                match v2_string_field(raw) {
                    Ok(p) if !p.is_empty() => {}
                    _ => return plain("resource_path path_prefix must be a non-empty string when present"),
                }
            }
        }
        CONSTRAINT_RECEIVER_AUDIENCE => {
            exact(&["params"], &[])?;
            return validate_v2_receiver_audience(required_node("params")?);
        }
        _ => {
            if kind.len() > MAX_IDENTIFIER_LENGTH_BYTES {
                return plain("unregistered constraint type exceeds MAX_IDENTIFIER_LENGTH_BYTES");
            }
            exact(&[], &["params"])?;
            if let Some(raw) = get("params") {
                let Some(params) = params_object(raw)? else {
                    return plain("unregistered constraint params must be an object");
                };
                validate_params_value(&ParamsValue::Object(params), 0).map_err(V2Error::plain)?;
            }
        }
    }
    Ok(())
}

fn string_array(node: Option<&JNode>) -> Option<Vec<String>> {
    match node.map(|n| &n.v) {
        Some(JV::Arr(items)) => items
            .iter()
            .map(|i| match &i.v {
                JV::Str(s) => Some(s.clone()),
                // Go decodes a null element of []string as "".
                JV::Null => Some(String::new()),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

fn validate_v2_receiver_audience(raw: &JNode) -> V2Result<()> {
    let JV::Obj(params) = &raw.v else {
        return plain("receiver audience requires params object");
    };
    for (key, _) in params {
        if !["exact_receiver_ids", "trust_domain_ids", "max_membership_age_seconds"].contains(&key.as_str()) {
            return plain(format!("unknown receiver audience parameter {key:?}"));
        }
    }
    let get = |name: &str| params.iter().find(|(k, _)| k == name).map(|(_, v)| v);
    let (Some(exact), Some(domains)) = (
        string_array(get("exact_receiver_ids")),
        string_array(get("trust_domain_ids")),
    ) else {
        return plain("receiver audience requires exact_receiver_ids and trust_domain_ids arrays");
    };
    if exact.len() + domains.len() == 0 {
        return plain("receiver audience must name an exact receiver or trust domain");
    }
    for values in [&exact, &domains] {
        if values.len() > MAX_AUDIENCE_IDS_V2 {
            return plain(format!("receiver audience arrays hold at most {MAX_AUDIENCE_IDS_V2} IDs"));
        }
        for (i, v) in values.iter().enumerate() {
            if v.is_empty() || v.len() > MAX_IDENTIFIER_LENGTH_BYTES || values[..i].contains(v) {
                return plain(format!(
                    "receiver audience IDs must be unique and 1 to {MAX_IDENTIFIER_LENGTH_BYTES} bytes"
                ));
            }
        }
    }
    let age = get("max_membership_age_seconds");
    if !domains.is_empty() && age.is_none_or(|a| a.is_null()) {
        return plain("receiver audience trust domains require max_membership_age_seconds");
    }
    if let Some(a) = age {
        match v2_integer_field(a) {
            Ok(n) if n > 0 && n <= V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS => {}
            _ => {
                return plain(format!(
                    "max_membership_age_seconds must be an integer in 1..{V2_MAX_AUDIENCE_MEMBERSHIP_AGE_SECONDS}"
                ))
            }
        }
    }
    if domains.is_empty() && age.is_some() {
        return plain("receiver audience without trust domains must omit max_membership_age_seconds");
    }
    Ok(())
}

/// Receiver-audience parameters of a constraint: exact IDs, domain IDs, and
/// the membership age (0 when absent).
pub(crate) fn audience_params(c: &ConstraintV2) -> (Vec<String>, Vec<String>, i64) {
    let list = |key: &str| -> Vec<String> {
        match c.params.as_ref().and_then(|p| p.get(key)) {
            Some(ParamsValue::Array(items)) => items
                .iter()
                .filter_map(|i| match i {
                    ParamsValue::Str(s) => Some(s.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    };
    let age = match c.params.as_ref().and_then(|p| p.get("max_membership_age_seconds")) {
        Some(ParamsValue::Int(n)) => *n,
        _ => 0,
    };
    (list("exact_receiver_ids"), list("trust_domain_ids"), age)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(s: &str) -> V2Result<ConstraintV2> {
        ConstraintV2::decode(s.as_bytes())
    }

    #[test]
    fn registered_shapes_round_trip_canonically() {
        for doc in [
            r#"{"end":"17:00","start":"09:00","type":"time_window","tz":"America/New_York"}"#,
            r#"{"currency":"USD","max_amount_micros":5000000,"type":"max_amount"}"#,
            r#"{"count":3,"type":"max_rate","window_s":60}"#,
            r#"{"path_prefix":"/a","resource_id":"r","type":"resource_path"}"#,
            r#"{"resource_id":"r","type":"resource_path"}"#,
            r#"{"params":{"exact_receiver_ids":["x"],"trust_domain_ids":[]},"type":"ratify.receiver_audience"}"#,
            r#"{"params":{"a":[1,null,{"b":true}]},"type":"com.example.thing"}"#,
            r#"{"type":"geo_circle"}"#,
        ] {
            let c = decode(doc).unwrap_or_else(|e| panic!("{doc}: {e}"));
            assert_eq!(String::from_utf8(c.canonical_json().expect("encode")).expect("utf8"), doc);
        }
    }

    #[test]
    fn closed_registry_rejections() {
        for doc in [
            r#"{"end":"24:00","start":"09:00","type":"time_window","tz":"UTC"}"#,
            r#"{"end":"9:00","start":"09:00","type":"time_window","tz":"UTC"}"#,
            r#"{"end":"17:00","start":"09:00","type":"time_window","tz":"../etc"}"#,
            r#"{"currency":"usd","max_amount_micros":1,"type":"max_amount"}"#,
            r#"{"currency":"USD","max_amount":1,"type":"max_amount"}"#,
            r#"{"currency":"USD","max_amount_micros":-1,"type":"max_amount"}"#,
            r#"{"count":0,"type":"max_rate","window_s":60}"#,
            r#"{"count":1,"type":"max_rate","window_s":86401}"#,
            r#"{"path_prefix":"","resource_id":"r","type":"resource_path"}"#,
            r#"{"path_prefix":null,"resource_id":"r","type":"resource_path"}"#,
            r#"{"lat":1,"type":"geo_circle"}"#,
            r#"{"params":null,"type":"com.example.thing"}"#,
            r#"{"params":[],"type":"com.example.thing"}"#,
            r#"{"params":{"exact_receiver_ids":[],"trust_domain_ids":[]},"type":"ratify.receiver_audience"}"#,
            r#"{"params":{"exact_receiver_ids":[],"trust_domain_ids":["d"]},"type":"ratify.receiver_audience"}"#,
            r#"{"params":{"exact_receiver_ids":["x"],"max_membership_age_seconds":5,"trust_domain_ids":[]},"type":"ratify.receiver_audience"}"#,
            r#"{"type":""}"#,
        ] {
            assert!(decode(doc).is_err(), "{doc} must be rejected");
        }
    }
}
