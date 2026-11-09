//! What the traversal records before resolution: declared symbols and
//! pending facts whose names are not resolved yet.

use shorwatch_core::ir::{ArgValue, FactKind, Location, ScopeId};

/// What the file says about a name declared in some scope.
#[derive(Debug, Default)]
pub(crate) struct Symbol {
    /// Declared (or, for `var`, inferred) type as written.
    pub(crate) ty: Option<String>,
    /// Literal initializer of a `final` declaration, or the property injected
    /// by `@Value("${...}")`.
    pub(crate) constant: Option<ArgValue>,
    /// Arguments of the factory call that initialized it:
    /// `KeyGenerator.getInstance("AES")` -> `["AES"]`.
    pub(crate) origin: Option<Vec<PendingArg>>,
    /// The call that initialized it when no type is written (`var p =
    /// keys.provider()`, Kotlin `val p = ...`): a [`Receiver::Call`] that
    /// `link` types from the method's declared return type.
    pub(crate) call: Option<Receiver>,
}

#[derive(Debug, Clone)]
pub(crate) enum Receiver {
    /// `x.m()`: a variable or a type name.
    Name(String),
    /// `a.b.C.m()` or `this.x.m()`.
    Path(String),
    /// A type known from the syntax, such as the implicit receiver inside
    /// Kotlin's `KeyGenerator.getInstance("AES").apply { init(128) }`, with the
    /// arguments of the factory that created it when known.
    Type {
        ty: String,
        origin: Option<Vec<PendingArg>>,
    },
    /// `owner.method(...)` with `arity` arguments, or `method(...)` on this
    /// type when `owner` is `None`: typed later from the method's declared
    /// return type, which may be in another file.
    Call {
        owner: Option<Box<Receiver>>,
        method: String,
        arity: usize,
    },
}

#[derive(Debug, Clone)]
pub(crate) enum ArgSource {
    Value(ArgValue),
    /// `m(NAME)`.
    Name(String),
    /// `m(Owner.NAME)`, or `m(this.name)` with owner `this`.
    Member {
        owner: String,
        name: String,
    },
    /// `a + b`, `"$a/ECB"`: the parts, all of which must be known.
    Concat(Vec<PendingArg>),
    /// `c ? a : b`, `switch`, `if` and `when` expressions: any branch.
    Choice(Vec<PendingArg>),
    /// `m(...)` or `this.m(...)`: what a method of this file returns.
    Call {
        method: String,
        args: Vec<PendingArg>,
    },
    /// `x.m(...)` or `Type.m(...)`: what another type's method returns.
    MemberCall {
        receiver: Receiver,
        method: String,
        args: Vec<PendingArg>,
    },
}

/// `name = value` (an initializer included), or `this.name = value` when
/// `field`.
#[derive(Debug)]
pub(crate) struct Assignment {
    pub(crate) scope: ScopeId,
    pub(crate) name: String,
    pub(crate) field: bool,
    pub(crate) value: PendingArg,
    pub(crate) location: Location,
}

/// A call to a method that may be declared in this file: no receiver, or
/// `this`.
#[derive(Debug)]
pub(crate) struct LocalCall {
    pub(crate) scope: ScopeId,
    pub(crate) method: String,
    pub(crate) args: Vec<PendingArg>,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingArg {
    pub(crate) source: ArgSource,
    pub(crate) raw: String,
    pub(crate) location: Location,
}

#[derive(Debug)]
pub(crate) enum Pending {
    Call {
        receiver: Option<Receiver>,
        method: String,
        args: Vec<PendingArg>,
        /// Methods called on the result later in the chain, nearest first.
        chain: Vec<String>,
    },
    Construct {
        ty: String,
        args: Vec<PendingArg>,
    },
    /// `Owner.NAME`, where `Owner` may turn out to be a variable, not a type.
    Field {
        owner: String,
        name: String,
        calls: Vec<String>,
    },
    /// A bare name that a static import may refer to, unless shadowed.
    StaticMember(String),
    Ready(FactKind),
}
