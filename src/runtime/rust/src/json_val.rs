//! The Ipê JSON value (`Json.Encode.Value`): an owned tree whose every walk is
//! an explicit worklist.
//!
//! A program builds a value of any depth in constant stack (a self-tail call is
//! a loop), so no operation over a [`JsonVal`] recurses the native stack: drop,
//! clone, equality, hash, `Debug`, `Display`, the encoder, the key sort, the
//! depth measure and the conversions each loop over a heap stack whose length
//! is bounded by the node count the program already paid for.
//!
//! The two crossings into serde's recursive machinery, a generic `Serializer`
//! and a generic `Deserializer`, refuse a value nested past
//! [`JSON_SERDE_NESTING_BACKSTOP`] through serde's own error channel.

use std::fmt::{self, Write as _};
use std::hash::{Hash, Hasher};
use std::mem;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::ser::{self, SerializeMap, SerializeSeq};

/// A JSON object: entries keep insertion order in every build model.
///
/// The map is `indexmap::IndexMap` whatever `serde_json`'s features are, so an
/// object built as `b, a` encodes, prints and re-parses as `b, a` in the
/// dependency, vendored and wasm builds alike.
pub type JsonMap = indexmap::IndexMap<String, JsonVal>;

/// One JSON node.
#[derive(Default)]
pub enum JsonVal {
    #[default]
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Self>),
    Object(JsonMap),
}

/// Most containers a value may nest when it crosses a generic serde
/// `Serializer` or `Deserializer`, the one ceiling both directions share.
///
/// Depth is counted as [`json_depth`] counts it: a scalar is one level and a
/// container one more than its deepest child.
pub const JSON_SERDE_NESTING_BACKSTOP: usize = 256;

/// Most containers `serde_json` nests before it refuses with its own recursion
/// error: its deserializer starts with a remaining depth of 128 and refuses the
/// container that brings it to 0.
pub const SERDE_CONTAINER_FLOOR: usize = 127;

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a document `serde_json` parses could pass the backstop [ledger #boundary]
const _: () = assert!(JSON_SERDE_NESTING_BACKSTOP >= SERDE_CONTAINER_FLOOR);

/// The error text a serde crossing past the backstop carries.
pub const BACKSTOP_REFUSAL: &str = "JSON value nests deeper than the serde backstop";

/// The widest pretty-print indent; a wider request saturates to it.
pub const MAX_JSON_INDENT: usize = 16;

/// One indent unit at the widest width, sliced to the requested width.
const INDENT: &str = "                ";

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the indent slice is narrower than the widest indent [ledger #boundary]
const _: () = assert!(INDENT.len() == MAX_JSON_INDENT);

impl Drop for JsonVal {
    // Children move onto a heap stack before their parent's storage frees, so
    // each node drops with no children left and the drop never recurses.
    fn drop(&mut self) {
        let mut pending: Vec<Self> = match self {
            Self::Array(items) if !items.is_empty() => mem::take(items),
            Self::Object(map) if !map.is_empty() => mem::take(map).into_values().collect(),
            _ => return,
        };
        while let Some(mut node) = pending.pop() {
            match &mut node {
                Self::Array(items) => pending.append(items),
                Self::Object(map) => pending.extend(mem::take(map).into_values()),
                Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) => {}
            }
        }
    }
}

impl From<f64> for JsonVal {
    /// A finite float as a number; NaN and the infinities as `null`.
    fn from(f: f64) -> Self {
        serde_json::Number::from_f64(f).map_or(Self::Null, Self::Number)
    }
}

/// A scalar node, borrowed.
enum Scalar<'a> {
    Null,
    Bool(bool),
    Number(&'a serde_json::Number),
    String(&'a str),
}

/// A node classified as a scalar or a container, borrowed.
enum Node<'a> {
    Scalar(Scalar<'a>),
    Array(&'a [JsonVal]),
    Object(&'a JsonMap),
}

impl JsonVal {
    fn node(&self) -> Node<'_> {
        match self {
            Self::Null => Node::Scalar(Scalar::Null),
            Self::Bool(b) => Node::Scalar(Scalar::Bool(*b)),
            Self::Number(n) => Node::Scalar(Scalar::Number(n)),
            Self::String(s) => Node::Scalar(Scalar::String(s)),
            Self::Array(items) => Node::Array(items),
            Self::Object(map) => Node::Object(map),
        }
    }

    /// The member `index` names: an object key or an array position.
    pub fn get<I: JsonIndex>(&self, index: I) -> Option<&Self> {
        index.index_into(self)
    }

    /// The member `index` names, mutably.
    pub fn get_mut<I: JsonIndex>(&mut self, index: I) -> Option<&mut Self> {
        index.index_into_mut(self)
    }

    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    pub const fn is_boolean(&self) -> bool {
        matches!(self, Self::Bool(_))
    }

    pub const fn is_number(&self) -> bool {
        matches!(self, Self::Number(_))
    }

    pub const fn is_string(&self) -> bool {
        matches!(self, Self::String(_))
    }

    pub const fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }

    pub const fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }

    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(n) => n.as_i64(),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(n) => n.as_u64(),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(n) => n.as_f64(),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    pub const fn as_array(&self) -> Option<&Vec<Self>> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    pub const fn as_array_mut(&mut self) -> Option<&mut Vec<Self>> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    pub const fn as_object(&self) -> Option<&JsonMap> {
        match self {
            Self::Object(map) => Some(map),
            _ => None,
        }
    }

    pub const fn as_object_mut(&mut self) -> Option<&mut JsonMap> {
        match self {
            Self::Object(map) => Some(map),
            _ => None,
        }
    }

    /// The value, leaving `null` in its place.
    pub fn take(&mut self) -> Self {
        mem::take(self)
    }

    /// The items of an array; `None` for any other node.
    pub fn into_array(mut self) -> Option<Vec<Self>> {
        match &mut self {
            Self::Array(items) => Some(mem::take(items)),
            _ => None,
        }
    }

    /// The entries of an object; `None` for any other node.
    pub fn into_object(mut self) -> Option<JsonMap> {
        match &mut self {
            Self::Object(map) => Some(mem::take(map)),
            _ => None,
        }
    }

    /// The text of a string; `None` for any other node.
    pub fn into_string(mut self) -> Option<String> {
        match &mut self {
            Self::String(s) => Some(mem::take(s)),
            _ => None,
        }
    }

    /// The same tree as an owned value of this type.
    ///
    /// The input drops recursively after the copy; every `serde_json::Value`
    /// the runtime holds came from a depth-bounded parse.
    pub fn from_serde(root: serde_json::Value) -> Self {
        from_serde_tree(root)
    }

    /// The same tree as a `serde_json::Value`, refused past the backstop.
    ///
    /// # Errors
    /// A [`crate::error::LimitRefusal`] when the value nests deeper than
    /// [`JSON_SERDE_NESTING_BACKSTOP`], since the returned value's own walks
    /// recurse.
    pub fn to_serde(&self) -> Result<serde_json::Value, crate::error::LimitRefusal> {
        if json_depth(self) > JSON_SERDE_NESTING_BACKSTOP {
            return Err(crate::error::LimitRefusal::new(BACKSTOP_REFUSAL));
        }
        Ok(rebuild::<SerdeTree>(self))
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for usize {}
    impl Sealed for str {}
    impl Sealed for String {}
    impl<T: ?Sized + Sealed> Sealed for &T {}
}

/// A key into a [`JsonVal`]: a string names an object member, a `usize` an
/// array position.
pub trait JsonIndex: sealed::Sealed {
    fn index_into<'v>(&self, v: &'v JsonVal) -> Option<&'v JsonVal>;
    fn index_into_mut<'v>(&self, v: &'v mut JsonVal) -> Option<&'v mut JsonVal>;
}

impl JsonIndex for usize {
    fn index_into<'v>(&self, v: &'v JsonVal) -> Option<&'v JsonVal> {
        v.as_array().and_then(|items| items.get(*self))
    }
    fn index_into_mut<'v>(&self, v: &'v mut JsonVal) -> Option<&'v mut JsonVal> {
        v.as_array_mut().and_then(|items| items.get_mut(*self))
    }
}

impl JsonIndex for str {
    fn index_into<'v>(&self, v: &'v JsonVal) -> Option<&'v JsonVal> {
        v.as_object().and_then(|map| map.get(self))
    }
    fn index_into_mut<'v>(&self, v: &'v mut JsonVal) -> Option<&'v mut JsonVal> {
        v.as_object_mut().and_then(|map| map.get_mut(self))
    }
}

impl JsonIndex for String {
    fn index_into<'v>(&self, v: &'v JsonVal) -> Option<&'v JsonVal> {
        self.as_str().index_into(v)
    }
    fn index_into_mut<'v>(&self, v: &'v mut JsonVal) -> Option<&'v mut JsonVal> {
        self.as_str().index_into_mut(v)
    }
}

impl<T: ?Sized + JsonIndex> JsonIndex for &T {
    fn index_into<'v>(&self, v: &'v JsonVal) -> Option<&'v JsonVal> {
        (**self).index_into(v)
    }
    fn index_into_mut<'v>(&self, v: &'v mut JsonVal) -> Option<&'v mut JsonVal> {
        (**self).index_into_mut(v)
    }
}

/// Structural nesting depth: a scalar is depth 1, a container 1 + its deepest
/// child (an empty container is depth 1).
pub fn json_depth(root: &JsonVal) -> usize {
    let mut stack: Vec<(&JsonVal, usize)> = vec![(root, 1)];
    let mut max_depth = 0usize;
    while let Some((node, depth)) = stack.pop() {
        max_depth = max_depth.max(depth);
        let child = depth.saturating_add(1);
        match node {
            JsonVal::Array(items) => stack.extend(items.iter().map(|item| (item, child))),
            JsonVal::Object(map) => stack.extend(map.values().map(|item| (item, child))),
            JsonVal::Null | JsonVal::Bool(_) | JsonVal::Number(_) | JsonVal::String(_) => {}
        }
    }
    max_depth
}

// ─── Post-order rebuild ──────────────────────────────────────────────────────

/// A target tree a [`JsonVal`] is rebuilt into, bottom-up.
trait Rebuild<'a> {
    type Out;
    type Map;
    fn scalar(s: Scalar<'a>) -> Self::Out;
    /// The entries of an object in the order the rebuilt object holds them.
    fn entries(map: &'a JsonMap) -> Vec<(&'a String, &'a JsonVal)>;
    fn new_map(len: usize) -> Self::Map;
    fn insert(map: &mut Self::Map, key: String, value: Self::Out);
    fn array(items: Vec<Self::Out>) -> Self::Out;
    fn object(map: Self::Map) -> Self::Out;
}

/// An open container in a rebuild: its unvisited children and its rebuilt ones.
enum Frame<'a, R: Rebuild<'a>> {
    Array {
        rest: std::slice::Iter<'a, JsonVal>,
        done: Vec<R::Out>,
    },
    Object {
        rest: std::vec::IntoIter<(&'a String, &'a JsonVal)>,
        key: String,
        done: R::Map,
    },
}

enum Opened<'a, R: Rebuild<'a>> {
    Leaf(R::Out),
    Frame(Frame<'a, R>),
}

impl<'a, R: Rebuild<'a>> Frame<'a, R> {
    fn open(v: &'a JsonVal) -> Opened<'a, R> {
        match v.node() {
            Node::Scalar(s) => Opened::Leaf(R::scalar(s)),
            Node::Array(items) => Opened::Frame(Self::Array {
                rest: items.iter(),
                done: Vec::with_capacity(items.len()),
            }),
            Node::Object(map) => Opened::Frame(Self::Object {
                rest: R::entries(map).into_iter(),
                key: String::new(),
                done: R::new_map(map.len()),
            }),
        }
    }

    fn next_child(&mut self) -> Option<&'a JsonVal> {
        match self {
            Self::Array { rest, .. } => rest.next(),
            Self::Object { rest, key, .. } => rest.next().map(|(k, v)| {
                k.clone_into(key);
                v
            }),
        }
    }

    fn push(&mut self, out: R::Out) {
        match self {
            Self::Array { done, .. } => done.push(out),
            Self::Object { key, done, .. } => R::insert(done, mem::take(key), out),
        }
    }

    fn finish(self) -> R::Out {
        match self {
            Self::Array { done, .. } => R::array(done),
            Self::Object { done, .. } => R::object(done),
        }
    }
}

fn rebuild<'a, R: Rebuild<'a>>(root: &'a JsonVal) -> R::Out {
    let mut top = match Frame::<R>::open(root) {
        Opened::Leaf(out) => return out,
        Opened::Frame(frame) => frame,
    };
    let mut parents: Vec<Frame<'a, R>> = Vec::new();
    loop {
        match top.next_child() {
            Some(child) => match Frame::<R>::open(child) {
                Opened::Leaf(out) => top.push(out),
                Opened::Frame(frame) => parents.push(mem::replace(&mut top, frame)),
            },
            None => {
                let done = top.finish();
                match parents.pop() {
                    Some(parent) => {
                        top = parent;
                        top.push(done);
                    }
                    None => return done,
                }
            }
        }
    }
}

fn own_scalar(s: Scalar<'_>) -> JsonVal {
    match s {
        Scalar::Null => JsonVal::Null,
        Scalar::Bool(b) => JsonVal::Bool(b),
        Scalar::Number(n) => JsonVal::Number(n.clone()),
        Scalar::String(s) => JsonVal::String(s.to_owned()),
    }
}

/// A copy with every object in its own order.
struct CloneTree;

impl<'a> Rebuild<'a> for CloneTree {
    type Out = JsonVal;
    type Map = JsonMap;
    fn scalar(s: Scalar<'a>) -> JsonVal {
        own_scalar(s)
    }
    fn entries(map: &'a JsonMap) -> Vec<(&'a String, &'a JsonVal)> {
        map.iter().collect()
    }
    fn new_map(len: usize) -> JsonMap {
        JsonMap::with_capacity(len)
    }
    fn insert(map: &mut JsonMap, key: String, value: JsonVal) {
        map.insert(key, value);
    }
    fn array(items: Vec<JsonVal>) -> JsonVal {
        JsonVal::Array(items)
    }
    fn object(map: JsonMap) -> JsonVal {
        JsonVal::Object(map)
    }
}

/// A copy with every object's keys in ascending order.
struct SortedTree;

impl<'a> Rebuild<'a> for SortedTree {
    type Out = JsonVal;
    type Map = JsonMap;
    fn scalar(s: Scalar<'a>) -> JsonVal {
        own_scalar(s)
    }
    fn entries(map: &'a JsonMap) -> Vec<(&'a String, &'a JsonVal)> {
        let mut entries: Vec<_> = map.iter().collect();
        entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
        entries
    }
    fn new_map(len: usize) -> JsonMap {
        JsonMap::with_capacity(len)
    }
    fn insert(map: &mut JsonMap, key: String, value: JsonVal) {
        map.insert(key, value);
    }
    fn array(items: Vec<JsonVal>) -> JsonVal {
        JsonVal::Array(items)
    }
    fn object(map: JsonMap) -> JsonVal {
        JsonVal::Object(map)
    }
}

/// The same tree as a `serde_json::Value`.
struct SerdeTree;

impl<'a> Rebuild<'a> for SerdeTree {
    type Out = serde_json::Value;
    type Map = serde_json::Map<String, serde_json::Value>;
    fn scalar(s: Scalar<'a>) -> serde_json::Value {
        match s {
            Scalar::Null => serde_json::Value::Null,
            Scalar::Bool(b) => serde_json::Value::Bool(b),
            Scalar::Number(n) => serde_json::Value::Number(n.clone()),
            Scalar::String(s) => serde_json::Value::String(s.to_owned()),
        }
    }
    fn entries(map: &'a JsonMap) -> Vec<(&'a String, &'a JsonVal)> {
        map.iter().collect()
    }
    fn new_map(len: usize) -> Self::Map {
        serde_json::Map::with_capacity(len)
    }
    fn insert(map: &mut Self::Map, key: String, value: serde_json::Value) {
        map.insert(key, value);
    }
    fn array(items: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::Value::Array(items)
    }
    fn object(map: Self::Map) -> serde_json::Value {
        serde_json::Value::Object(map)
    }
}

/// A copy of `val` with every object's keys in ascending order at every depth.
pub fn sorted_keys(val: &JsonVal) -> JsonVal {
    rebuild::<SortedTree>(val)
}

/// An open `serde_json` container in [`from_serde_tree`].
enum SerdeFrame {
    Array {
        rest: std::vec::IntoIter<serde_json::Value>,
        done: Vec<JsonVal>,
    },
    Object {
        rest: serde_json::map::IntoIter,
        key: String,
        done: JsonMap,
    },
}

enum SerdeOpened {
    Leaf(JsonVal),
    Frame(SerdeFrame),
}

impl SerdeFrame {
    fn open(v: serde_json::Value) -> SerdeOpened {
        match v {
            serde_json::Value::Null => SerdeOpened::Leaf(JsonVal::Null),
            serde_json::Value::Bool(b) => SerdeOpened::Leaf(JsonVal::Bool(b)),
            serde_json::Value::Number(n) => SerdeOpened::Leaf(JsonVal::Number(n)),
            serde_json::Value::String(s) => SerdeOpened::Leaf(JsonVal::String(s)),
            serde_json::Value::Array(items) => SerdeOpened::Frame(Self::Array {
                done: Vec::with_capacity(items.len()),
                rest: items.into_iter(),
            }),
            serde_json::Value::Object(map) => SerdeOpened::Frame(Self::Object {
                done: JsonMap::with_capacity(map.len()),
                rest: map.into_iter(),
                key: String::new(),
            }),
        }
    }

    fn next_child(&mut self) -> Option<serde_json::Value> {
        match self {
            Self::Array { rest, .. } => rest.next(),
            Self::Object { rest, key, .. } => rest.next().map(|(k, v)| {
                *key = k;
                v
            }),
        }
    }

    fn push(&mut self, out: JsonVal) {
        match self {
            Self::Array { done, .. } => done.push(out),
            Self::Object { key, done, .. } => {
                done.insert(mem::take(key), out);
            }
        }
    }

    fn finish(self) -> JsonVal {
        match self {
            Self::Array { done, .. } => JsonVal::Array(done),
            Self::Object { done, .. } => JsonVal::Object(done),
        }
    }
}

fn from_serde_tree(root: serde_json::Value) -> JsonVal {
    let mut top = match SerdeFrame::open(root) {
        SerdeOpened::Leaf(out) => return out,
        SerdeOpened::Frame(frame) => frame,
    };
    let mut parents: Vec<SerdeFrame> = Vec::new();
    loop {
        match top.next_child() {
            Some(child) => match SerdeFrame::open(child) {
                SerdeOpened::Leaf(out) => top.push(out),
                SerdeOpened::Frame(frame) => parents.push(mem::replace(&mut top, frame)),
            },
            None => {
                let done = top.finish();
                match parents.pop() {
                    Some(parent) => {
                        top = parent;
                        top.push(done);
                    }
                    None => return done,
                }
            }
        }
    }
}

impl Clone for JsonVal {
    fn clone(&self) -> Self {
        rebuild::<CloneTree>(self)
    }
}

impl PartialEq for JsonVal {
    // Objects compare as sets of entries: same length, every key's value equal.
    fn eq(&self, other: &Self) -> bool {
        let mut pending: Vec<(&Self, &Self)> = vec![(self, other)];
        while let Some(pair) = pending.pop() {
            match pair {
                (Self::Null, Self::Null) => {}
                (Self::Bool(a), Self::Bool(b)) if a == b => {}
                (Self::Number(a), Self::Number(b)) if a == b => {}
                (Self::String(a), Self::String(b)) if a == b => {}
                (Self::Array(a), Self::Array(b)) if a.len() == b.len() => {
                    pending.extend(a.iter().zip(b));
                }
                (Self::Object(a), Self::Object(b)) if a.len() == b.len() => {
                    for (key, value) in a {
                        match b.get(key) {
                            Some(other_value) => pending.push((value, other_value)),
                            None => return false,
                        }
                    }
                }
                _ => return false,
            }
        }
        true
    }
}

impl Eq for JsonVal {}

impl Hash for JsonVal {
    // An object hashes its entries in key order, so two equal objects hash
    // alike whatever their insertion order.
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut pending: Vec<&Self> = vec![self];
        while let Some(node) = pending.pop() {
            mem::discriminant(node).hash(state);
            match node {
                Self::Null => {}
                Self::Bool(b) => b.hash(state),
                Self::Number(n) => n.hash(state),
                Self::String(s) => s.hash(state),
                Self::Array(items) => {
                    items.len().hash(state);
                    pending.extend(items.iter().rev());
                }
                Self::Object(map) => {
                    let mut entries: Vec<(&String, &Self)> = map.iter().collect();
                    entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
                    entries.len().hash(state);
                    for (key, _) in &entries {
                        key.hash(state);
                    }
                    pending.extend(entries.iter().rev().map(|(_, value)| *value));
                }
            }
        }
    }
}

/// An open container in a writer: its unwritten children and whether one was
/// written yet.
enum WriteFrame<'a> {
    Array {
        rest: std::slice::Iter<'a, JsonVal>,
        first: bool,
    },
    Object {
        rest: indexmap::map::Iter<'a, String, JsonVal>,
        first: bool,
    },
}

impl fmt::Debug for JsonVal {
    // The text matches `serde_json::Value`'s `{:?}` byte for byte. The
    // alternate form `{:#?}` renders the same compact text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut stack: Vec<WriteFrame<'_>> = Vec::new();
        let mut next = Some(self);
        loop {
            if let Some(value) = next.take() {
                match value.node() {
                    Node::Scalar(Scalar::Null) => f.write_str("Null")?,
                    Node::Scalar(Scalar::Bool(b)) => write!(f, "Bool({b})")?,
                    Node::Scalar(Scalar::Number(n)) => write!(f, "Number({n})")?,
                    Node::Scalar(Scalar::String(s)) => write!(f, "String({s:?})")?,
                    Node::Array(items) => {
                        f.write_str("Array [")?;
                        stack.push(WriteFrame::Array {
                            rest: items.iter(),
                            first: true,
                        });
                    }
                    Node::Object(map) => {
                        f.write_str("Object {")?;
                        stack.push(WriteFrame::Object {
                            rest: map.iter(),
                            first: true,
                        });
                    }
                }
            }
            let Some(top) = stack.last_mut() else {
                return Ok(());
            };
            match top {
                WriteFrame::Array { rest, first } => match rest.next() {
                    Some(item) => {
                        if !mem::replace(first, false) {
                            f.write_str(", ")?;
                        }
                        next = Some(item);
                    }
                    None => {
                        stack.pop();
                        f.write_str("]")?;
                    }
                },
                WriteFrame::Object { rest, first } => match rest.next() {
                    Some((key, item)) => {
                        if !mem::replace(first, false) {
                            f.write_str(", ")?;
                        }
                        write!(f, "{key:?}: ")?;
                        next = Some(item);
                    }
                    None => {
                        stack.pop();
                        f.write_str("}")?;
                    }
                },
            }
        }
    }
}

impl fmt::Display for JsonVal {
    // Compact JSON text, as `serde_json::Value`'s `Display`; the alternate form
    // `{:#}` is two-space pretty JSON.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let layout = if f.alternate() {
            Layout::Pretty(2)
        } else {
            Layout::Compact
        };
        let mut out = String::new();
        write_json(&mut out, self, layout, Policy::Display);
        f.write_str(&out)
    }
}

/// Where a writer breaks lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// No whitespace.
    Compact,
    /// One member per line, indented by the given width per level; a width
    /// past [`MAX_JSON_INDENT`] saturates to it.
    Pretty(usize),
}

/// Which characters and numbers a writer reshapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// `serde_json`'s text: its string escapes and its number form.
    Display,
    /// The `Json.Encode.encode` text: `serde_json`'s escapes plus `<`, `>`,
    /// `&`, U+2028 and U+2029 as `\uXXXX`, and floats in the
    /// [`go_format_f64`] form.
    Encode,
}

/// Append `root` as JSON text to `out`. Infallible.
pub fn write_json(out: &mut String, root: &JsonVal, layout: Layout, policy: Policy) {
    let mut stack: Vec<WriteFrame<'_>> = Vec::new();
    let mut next = Some(root);
    loop {
        if let Some(value) = next.take() {
            match value.node() {
                Node::Scalar(s) => write_scalar(out, &s, policy),
                Node::Array(items) => {
                    out.push('[');
                    stack.push(WriteFrame::Array {
                        rest: items.iter(),
                        first: true,
                    });
                }
                Node::Object(map) => {
                    out.push('{');
                    stack.push(WriteFrame::Object {
                        rest: map.iter(),
                        first: true,
                    });
                }
            }
        }
        let level = stack.len();
        let Some(top) = stack.last_mut() else {
            return;
        };
        match top {
            WriteFrame::Array { rest, first } => match rest.next() {
                Some(item) => {
                    if !mem::replace(first, false) {
                        out.push(',');
                    }
                    break_line(out, layout, level);
                    next = Some(item);
                }
                None => {
                    let empty = *first;
                    stack.pop();
                    if !empty {
                        break_line(out, layout, level.saturating_sub(1));
                    }
                    out.push(']');
                }
            },
            WriteFrame::Object { rest, first } => match rest.next() {
                Some((key, item)) => {
                    if !mem::replace(first, false) {
                        out.push(',');
                    }
                    break_line(out, layout, level);
                    write_string(out, key, policy);
                    out.push(':');
                    if matches!(layout, Layout::Pretty(_)) {
                        out.push(' ');
                    }
                    next = Some(item);
                }
                None => {
                    let empty = *first;
                    stack.pop();
                    if !empty {
                        break_line(out, layout, level.saturating_sub(1));
                    }
                    out.push('}');
                }
            },
        }
    }
}

/// A newline and `level` indent units in the pretty layout; nothing compact.
fn break_line(out: &mut String, layout: Layout, level: usize) {
    if let Layout::Pretty(width) = layout {
        out.push('\n');
        let unit = INDENT.get(..width).unwrap_or(INDENT);
        for _ in 0..level {
            out.push_str(unit);
        }
    }
}

fn write_scalar(out: &mut String, s: &Scalar<'_>, policy: Policy) {
    match s {
        Scalar::Null => out.push_str("null"),
        Scalar::Bool(true) => out.push_str("true"),
        Scalar::Bool(false) => out.push_str("false"),
        Scalar::Number(n) => match (policy, n.is_f64().then(|| n.as_f64()).flatten()) {
            (Policy::Encode, Some(f)) => out.push_str(&go_format_f64(f)),
            _ => {
                // Writing into a `String` never fails.
                let _ = write!(out, "{n}");
            }
        },
        Scalar::String(text) => write_string(out, text, policy),
    }
}

/// The escape `serde_json` writes for `c`, or under [`Policy::Encode`] the
/// HTML-safe one; `None` when `c` is written as itself.
const fn short_escape(c: char, policy: Policy) -> Option<&'static str> {
    match c {
        '"' => Some("\\\""),
        '\\' => Some("\\\\"),
        '\u{8}' => Some("\\b"),
        '\u{c}' => Some("\\f"),
        '\n' => Some("\\n"),
        '\r' => Some("\\r"),
        '\t' => Some("\\t"),
        '<' if matches!(policy, Policy::Encode) => Some("\\u003c"),
        '>' if matches!(policy, Policy::Encode) => Some("\\u003e"),
        '&' if matches!(policy, Policy::Encode) => Some("\\u0026"),
        '\u{2028}' if matches!(policy, Policy::Encode) => Some("\\u2028"),
        '\u{2029}' if matches!(policy, Policy::Encode) => Some("\\u2029"),
        _ => None,
    }
}

/// Append `text` as a quoted JSON string.
fn write_string(out: &mut String, text: &str, policy: Policy) {
    out.push('"');
    let mut start = 0usize;
    for (i, c) in text.char_indices() {
        let escape = short_escape(c, policy);
        let control = u32::from(c) < 0x20;
        if escape.is_none() && !control {
            continue;
        }
        out.push_str(text.get(start..i).unwrap_or_default());
        match escape {
            Some(e) => out.push_str(e),
            None => {
                // Any other C0 control as `\u00XX`, lowercase hex.
                let code = u32::from(c);
                out.push_str("\\u00");
                out.push(char::from_digit(code >> 4, 16).unwrap_or('0'));
                out.push(char::from_digit(code & 0xf, 16).unwrap_or('0'));
            }
        }
        start = i + c.len_utf8();
    }
    out.push_str(text.get(start..).unwrap_or_default());
    out.push('"');
}

/// Format an `f64` for JSON serialisation: exponent ('e') form only when the
/// magnitude is `< 1e-6` or `>= 1e21`; every other finite value uses plain
/// decimal ('f') form. Both forms use the shortest round-tripping digit sequence.
///   * 'f' form: `format!("{f}")` — Rust Display never emits an exponent.
///   * 'e' form: reshape `format!("{f:e}")` into `e±NN` exponent (`+`/`-` sign
///     always present; positive exponents zero-padded to ≥2 digits; negative
///     exponents use minimum digits — `e-0N` → `e-N`).
pub fn go_format_f64(f: f64) -> String {
    if !f.is_finite() {
        // A `serde_json::Number` never holds a non-finite float; the finite
        // fallback keeps the helper total regardless.
        return "0".to_string();
    }
    let abs = f.abs();
    // Exponent form when `abs < 1e-6 || abs >= 1e21`; `!(1e-6..1e21).contains`
    // is the half-open complement (clippy-preferred spelling).
    let use_exp = abs != 0.0 && !(1e-6..1e21).contains(&abs);
    if !use_exp {
        return format!("{f}");
    }
    let rust_e = format!("{f:e}");
    match rust_e.split_once('e') {
        Some((mantissa, exp)) => match exp.parse::<i32>() {
            Ok(e) if e < 0 => format!("{mantissa}e-{}", -e),
            Ok(e) => format!("{mantissa}e+{e:02}"),
            // Unreachable: `{:e}` always emits a parseable integer exponent.
            Err(_) => rust_e,
        },
        // Unreachable: `{:e}` always contains an 'e'.
        None => rust_e,
    }
}

// ─── serde crossings ─────────────────────────────────────────────────────────

impl serde::Serialize for JsonVal {
    // The depth is measured once at the root; the children serialize through
    // `Checked`, which does not measure again.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if json_depth(self) > JSON_SERDE_NESTING_BACKSTOP {
            return Err(ser::Error::custom(BACKSTOP_REFUSAL));
        }
        Checked(self).serialize(serializer)
    }
}

/// A value whose depth is already within the backstop.
struct Checked<'a>(&'a JsonVal);

impl serde::Serialize for Checked<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            JsonVal::Null => serializer.serialize_unit(),
            JsonVal::Bool(b) => serializer.serialize_bool(*b),
            JsonVal::Number(n) => n.serialize(serializer),
            JsonVal::String(s) => serializer.serialize_str(s),
            JsonVal::Array(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(&Checked(item))?;
                }
                seq.end()
            }
            JsonVal::Object(map) => {
                let mut entries = serializer.serialize_map(Some(map.len()))?;
                for (key, item) in map {
                    entries.serialize_entry(key, &Checked(item))?;
                }
                entries.end()
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for JsonVal {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Nested {
            remaining: JSON_SERDE_NESTING_BACKSTOP,
        }
        .deserialize(deserializer)
    }
}

/// A value read at a nesting level that leaves `remaining` levels, itself
/// included; at 0 the value is refused before it is read.
#[derive(Clone, Copy)]
struct Nested {
    remaining: usize,
}

impl<'de> DeserializeSeed<'de> for Nested {
    type Value = JsonVal;

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<JsonVal, D::Error> {
        if self.remaining == 0 {
            return Err(de::Error::custom(BACKSTOP_REFUSAL));
        }
        deserializer.deserialize_any(NestedVisitor { level: self })
    }
}

/// `serde_json`'s `ValueVisitor`, arm for arm, with the children of a container
/// read one level down.
struct NestedVisitor {
    level: Nested,
}

impl NestedVisitor {
    const fn children(&self) -> Nested {
        Nested {
            remaining: self.level.remaining.saturating_sub(1),
        }
    }
}

impl<'de> Visitor<'de> for NestedVisitor {
    type Value = JsonVal;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any valid JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<JsonVal, E> {
        Ok(JsonVal::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<JsonVal, E> {
        Ok(JsonVal::Number(value.into()))
    }

    fn visit_i128<E: de::Error>(self, value: i128) -> Result<JsonVal, E> {
        let de = serde::de::value::I128Deserializer::new(value);
        <serde_json::Number as serde::Deserialize>::deserialize(de).map(JsonVal::Number)
    }

    fn visit_u64<E>(self, value: u64) -> Result<JsonVal, E> {
        Ok(JsonVal::Number(value.into()))
    }

    fn visit_u128<E: de::Error>(self, value: u128) -> Result<JsonVal, E> {
        let de = serde::de::value::U128Deserializer::new(value);
        <serde_json::Number as serde::Deserialize>::deserialize(de).map(JsonVal::Number)
    }

    fn visit_f64<E>(self, value: f64) -> Result<JsonVal, E> {
        Ok(serde_json::Number::from_f64(value).map_or(JsonVal::Null, JsonVal::Number))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<JsonVal, E> {
        Ok(JsonVal::String(String::from(value)))
    }

    fn visit_string<E>(self, value: String) -> Result<JsonVal, E> {
        Ok(JsonVal::String(value))
    }

    fn visit_none<E>(self) -> Result<JsonVal, E> {
        Ok(JsonVal::Null)
    }

    fn visit_some<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<JsonVal, D::Error> {
        self.level.deserialize(deserializer)
    }

    fn visit_unit<E>(self) -> Result<JsonVal, E> {
        Ok(JsonVal::Null)
    }

    fn visit_seq<V: SeqAccess<'de>>(self, mut visitor: V) -> Result<JsonVal, V::Error> {
        let children = self.children();
        let mut vec = Vec::new();
        while let Some(elem) = visitor.next_element_seed(children)? {
            vec.push(elem);
        }
        Ok(JsonVal::Array(vec))
    }

    fn visit_map<V: MapAccess<'de>>(self, mut visitor: V) -> Result<JsonVal, V::Error> {
        let children = self.children();
        match visitor.next_key_seed(KeyClassifier)? {
            Some(first_key) => {
                let mut values = JsonMap::new();
                values.insert(first_key, visitor.next_value_seed(children)?);
                while let Some(key) = visitor.next_key::<String>()? {
                    let value = visitor.next_value_seed(children)?;
                    values.insert(key, value);
                }
                Ok(JsonVal::Object(values))
            }
            None => Ok(JsonVal::Object(JsonMap::new())),
        }
    }
}

/// An object's first key, read as `serde_json` reads it (`deserialize_str`).
struct KeyClassifier;

impl<'de> DeserializeSeed<'de> for KeyClassifier {
    type Value = String;

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<String, D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl Visitor<'_> for KeyClassifier {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string key")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<String, E> {
        Ok(s.to_owned())
    }

    fn visit_string<E: de::Error>(self, s: String) -> Result<String, E> {
        Ok(s)
    }
}

/// Builds a [`JsonVal`] from `serde_json::json!` syntax.
#[cfg(test)]
macro_rules! json_val {
    ($($json:tt)+) => {
        $crate::json_val::JsonVal::from_serde(::serde_json::json!($($json)+))
    };
}
#[cfg(test)]
pub(crate) use json_val;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    fn hash_of(v: &JsonVal) -> u64 {
        let mut h = DefaultHasher::new();
        v.hash(&mut h);
        h.finish()
    }

    #[test]
    fn object_eq_and_hash_ignore_order() {
        let ab = json_val!({ "a": 1, "b": [true, null] });
        let ba = json_val!({ "b": [true, null], "a": 1 });
        assert_eq!(ab, ba);
        assert_eq!(hash_of(&ab), hash_of(&ba));
        assert_ne!(ab, json_val!({ "a": 1, "b": [true] }));
        assert_ne!(ab, json_val!({ "a": 1, "c": [true, null] }));
    }

    #[test]
    fn debug_matches_serde_json() {
        let src = serde_json::json!({ "b": [1, 2.5, "x\"y", null, true], "a": {}, "c": [] });
        let ours = JsonVal::from_serde(src.clone());
        assert_eq!(format!("{ours:?}"), format!("{src:?}"));
    }

    #[test]
    fn display_matches_serde_json() {
        let src = serde_json::json!({ "b": [1, 2.5, "<\u{1}\u{2028}>", null], "a": { "k": [] } });
        let ours = JsonVal::from_serde(src.clone());
        assert_eq!(ours.to_string(), src.to_string());
        assert_eq!(format!("{ours:#}"), format!("{src:#}"));
    }

    #[test]
    fn serde_round_trip_keeps_document_order() {
        let parsed: Result<JsonVal, _> = serde_json::from_str(r#"{"b":1,"a":{"d":2,"c":3}}"#);
        let Ok(parsed) = parsed else {
            return assert!(parsed.is_ok());
        };
        assert_eq!(parsed.to_string(), r#"{"b":1,"a":{"d":2,"c":3}}"#);
        let to_serde = parsed.to_serde().map(|v| v.to_string());
        assert_eq!(
            to_serde.ok().as_deref(),
            Some(r#"{"b":1,"a":{"d":2,"c":3}}"#)
        );
        assert_eq!(
            serde_json::to_string(&parsed).ok().as_deref(),
            Some(r#"{"b":1,"a":{"d":2,"c":3}}"#)
        );
    }

    #[test]
    fn sorted_keys_sorts_every_level() {
        let v = json_val!({ "b": { "z": 1, "y": 2 }, "a": [{ "d": 1, "c": 2 }] });
        assert_eq!(
            sorted_keys(&v).to_string(),
            r#"{"a":[{"c":2,"d":1}],"b":{"y":2,"z":1}}"#
        );
    }

    #[test]
    fn accessors_never_index_out() {
        let v = json_val!({ "a": [10, 20] });
        assert_eq!(
            v.get("a").and_then(|a| a.get(1)).and_then(JsonVal::as_i64),
            Some(20)
        );
        assert!(v.get("a").and_then(|a| a.get(2)).is_none());
        assert!(v.get("missing").is_none());
        assert!(v.get(0).is_none());
        assert_eq!(v.clone().into_object().map(|m| m.len()), Some(1));
        assert!(v.into_array().is_none());
    }
}
