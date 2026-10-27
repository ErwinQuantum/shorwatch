use super::*;

/// A class file with the given declarations, assembled by hand: the tests
/// need no JDK and no binary fixtures.
fn class(
    access: u16,
    name: &str,
    superclass: &str,
    interfaces: &[&str],
    methods: &[(u16, &str, &str)],
) -> Vec<u8> {
    let mut pool: Vec<Vec<u8>> = Vec::new();
    let mut utf8 = |pool: &mut Vec<Vec<u8>>, s: &str| -> u16 {
        let mut entry = vec![1];
        entry.extend(u16::try_from(s.len()).unwrap().to_be_bytes());
        entry.extend(s.as_bytes());
        pool.push(entry);
        u16::try_from(pool.len()).unwrap()
    };
    let class_ref =
        |pool: &mut Vec<Vec<u8>>, utf8: &mut dyn FnMut(&mut Vec<Vec<u8>>, &str) -> u16, s: &str| {
            let name = utf8(pool, s);
            let mut entry = vec![7];
            entry.extend(name.to_be_bytes());
            pool.push(entry);
            u16::try_from(pool.len()).unwrap()
        };
    let this = class_ref(&mut pool, &mut utf8, name);
    let sup = class_ref(&mut pool, &mut utf8, superclass);
    let ifaces: Vec<u16> = interfaces
        .iter()
        .map(|i| class_ref(&mut pool, &mut utf8, i))
        .collect();
    // A long takes two entries: the parser must skip the second.
    pool.push([5].into_iter().chain(42u64.to_be_bytes()).collect());
    pool.push(Vec::new());
    let methods: Vec<(u16, u16, u16)> = methods
        .iter()
        .map(|(access, n, d)| (*access, utf8(&mut pool, n), utf8(&mut pool, d)))
        .collect();

    let mut out = 0xCAFE_BABE_u32.to_be_bytes().to_vec();
    out.extend([0, 0, 0, 65]);
    out.extend((u16::try_from(pool.len()).unwrap() + 1).to_be_bytes());
    for entry in &pool {
        out.extend(entry);
    }
    out.extend(access.to_be_bytes());
    out.extend(this.to_be_bytes());
    out.extend(sup.to_be_bytes());
    out.extend(u16::try_from(ifaces.len()).unwrap().to_be_bytes());
    for i in ifaces {
        out.extend(i.to_be_bytes());
    }
    out.extend([0, 0]); // fields
    out.extend(u16::try_from(methods.len()).unwrap().to_be_bytes());
    for (access, n, d) in methods {
        out.extend(access.to_be_bytes());
        out.extend(n.to_be_bytes());
        out.extend(d.to_be_bytes());
        // One attribute, skipped by length.
        out.extend([0, 1, 0, 1, 0, 0, 0, 2, 0xAB, 0xCD]);
    }
    out.extend([0, 0]); // attributes
    out
}

#[test]
fn reads_supertypes_and_methods_returning_types() {
    let bytes = class(
        ACC_PUBLIC,
        "com/jcraft/jsch/JSch",
        "java/lang/Object",
        &["java/io/Closeable"],
        &[
            (
                ACC_PUBLIC,
                "getSession",
                "(Ljava/lang/String;Ljava/lang/String;I)Lcom/jcraft/jsch/Session;",
            ),
            (ACC_PUBLIC, "<init>", "()V"),
            (
                ACC_PUBLIC,
                "getConfig",
                "(Ljava/lang/String;)Ljava/lang/String;",
            ),
            (ACC_PUBLIC, "setKnownHosts", "(Ljava/lang/String;)V"),
            (0x0002, "hidden", "()Lcom/jcraft/jsch/Session;"),
            (
                ACC_PUBLIC | ACC_BRIDGE,
                "bridge",
                "()Lcom/jcraft/jsch/Session;",
            ),
            (
                ACC_PROTECTED,
                "identities",
                "([[I[Ljava/lang/String;J)Lcom/jcraft/jsch/IdentityRepository;",
            ),
        ],
    );
    let library = read_class(&bytes).unwrap();
    assert_eq!(library.types.len(), 1);
    assert_eq!(library.types[0].name, "com.jcraft.jsch.JSch");
    let supertypes: Vec<_> = library.types[0]
        .supertypes
        .iter()
        .map(|s| s.qualified.as_deref().unwrap())
        .collect();
    assert_eq!(supertypes, ["java.io.Closeable"]);
    let methods: Vec<_> = library
        .methods
        .iter()
        .map(|m| {
            (
                m.owner.as_str(),
                m.name.as_str(),
                m.arity,
                m.return_type
                    .as_ref()
                    .unwrap()
                    .qualified
                    .as_deref()
                    .unwrap(),
            )
        })
        .collect();
    assert_eq!(
        methods,
        [
            (
                "com.jcraft.jsch.JSch",
                "getSession",
                3,
                "com.jcraft.jsch.Session"
            ),
            (
                "com.jcraft.jsch.JSch",
                "identities",
                3,
                "com.jcraft.jsch.IdentityRepository"
            ),
        ]
    );
}

#[test]
fn nested_and_companion_classes_are_named_like_the_sources() {
    let bytes = class(
        ACC_PUBLIC,
        "com/example/Keys$Companion",
        "java/lang/Object",
        &[],
        &[(ACC_PUBLIC, "provider", "()Lcom/example/Keys$Provider;")],
    );
    let library = read_class(&bytes).unwrap();
    assert_eq!(library.types[0].name, "com.example.Keys.Companion");
    assert_eq!(library.methods[0].owner, "com.example.Keys");
    let ret = library.methods[0].return_type.as_ref().unwrap();
    assert_eq!(ret.qualified.as_deref(), Some("com.example.Keys.Provider"));
}

#[test]
fn anonymous_synthetic_and_info_classes_declare_nothing() {
    for (access, name) in [
        (ACC_PUBLIC, "com/example/Keys$1"),
        (ACC_PUBLIC, "com/example/Keys$2Local"),
        (ACC_PUBLIC | ACC_SYNTHETIC, "com/example/Keys$Lambda"),
        (ACC_PUBLIC, "com/example/package-info"),
        (ACC_MODULE, "module-info"),
    ] {
        let bytes = class(
            access,
            name,
            "java/lang/Object",
            &[],
            &[(ACC_PUBLIC, "m", "()Ljava/util/List;")],
        );
        assert!(read_class(&bytes).unwrap().is_empty(), "{name}");
    }
}

#[test]
fn malformed_class_files_are_errors() {
    assert!(read_class(b"PK\x03\x04").is_err());
    let mut bytes = class(ACC_PUBLIC, "a/B", "java/lang/Object", &[], &[]);
    bytes.truncate(bytes.len() - 5);
    assert!(read_class(&bytes).is_err());
}

#[test]
fn descriptors_give_arity_and_class_return_types() {
    use classfile::signature;
    assert_eq!(signature("()V"), Some((0, None)));
    assert_eq!(signature("(IJ[Ljava/lang/String;)[B"), Some((3, None)));
    assert_eq!(
        signature("(Ljava/util/Map;)Ljava/util/Set;"),
        Some((1, Some("java/util/Set")))
    );
    assert_eq!(signature("broken"), None);
}
