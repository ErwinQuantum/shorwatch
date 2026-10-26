//! What the traversal records before resolution: declared symbols and
//! pending facts whose names are not resolved yet.

use shorwatch_core::ir::{ArgValue, FactKind, Location};

/// What the file says about a name declared in some scope.
#[derive(Debug, Default)]
pub(crate) struct Symbol {
    /// Declared (or, for `var`, inferred) type as written.
    pub(crate) ty: Option<String>,
    /// Literal initializer of a `final` declaration, or the property injected
    /// by `@Value("${...}")`.
    pub(crate) constant: Option<ArgValue>,
}

#[derive(Debug)]
pub(crate) enum Receiver {
    /// `x.m()`: a variable or a type name.
    Name(String),
    /// `a.b.C.m()` or `this.x.m()`.
    Path(String),
}

#[derive(Debug)]
pub(crate) enum ArgSource {
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
