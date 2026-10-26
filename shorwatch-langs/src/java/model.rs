//! What the traversal records before resolution: declared symbols and
//! pending facts whose names are not resolved yet.

use shorwatch_core::ir::{ArgValue, FactKind, Location};

/// What the file says about a name declared in some scope.
#[derive(Debug, Default)]
pub(super) struct Symbol {
    /// Declared (or, for `var`, inferred) type as written.
    pub(super) ty: Option<String>,
    /// Literal initializer of a `final` declaration, or the property injected
    /// by `@Value("${...}")`.
    pub(super) constant: Option<ArgValue>,
}

#[derive(Debug)]
pub(super) enum Receiver {
    /// `x.m()`: a variable or a type name.
    Name(String),
    /// `a.b.C.m()` or `this.x.m()`.
    Path(String),
}

#[derive(Debug)]
pub(super) enum ArgSource {
    Value(ArgValue),
    /// `m(NAME)`.
    Name(String),
    /// `m(Owner.NAME)`.
    Member {
        owner: String,
        name: String,
    },
}

#[derive(Debug)]
pub(super) struct PendingArg {
    pub(super) source: ArgSource,
    pub(super) raw: String,
    pub(super) location: Location,
}

#[derive(Debug)]
pub(super) enum Pending {
    Call {
        receiver: Option<Receiver>,
        method: String,
        args: Vec<PendingArg>,
    },
    Construct {
        ty: String,
        args: Vec<PendingArg>,
    },
    /// `Owner.NAME`, where `Owner` may turn out to be a variable, not a type.
    Field {
        owner: String,
        name: String,
    },
    /// A bare name that a static import may refer to, unless shadowed.
    StaticMember(String),
    Ready(FactKind),
}
