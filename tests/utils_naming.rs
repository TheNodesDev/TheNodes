use thenodes::utils::to_kebab_ascii_strict as kebab;

#[test]
fn kebab_basic_ascii() {
    assert_eq!(kebab("My Cool Realm"), "my-cool-realm");
    assert_eq!(kebab("hello_world"), "hello-world");
    assert_eq!(kebab("Foo-Bar"), "foo-bar");
}

#[test]
fn kebab_collapses_and_trims() {
    assert_eq!(kebab("--Hello__World--"), "hello-world");
    assert_eq!(kebab("  A   B  C  "), "a-b-c");
}

#[test]
fn kebab_non_ascii_maps_to_dashes() {
    // Non-ASCII letters transliterate; symbols become separators
    assert_eq!(kebab("こんにちは"), "default"); // deunicode -> empty/invalid -> default after cleanup
    assert_eq!(kebab("Déjà Vu!"), "deja-vu");
}

#[test]
fn kebab_empty_defaults() {
    assert_eq!(kebab(""), "default");
}

#[test]
fn kebab_swedish_letters_transliterate() {
    // Å, Ä, Ö => A, A, O ; å, ä, ö => a, a, o
    assert_eq!(kebab("ÅÄÖ"), "aao"); // "AAO" lowercased -> "aao"
    assert_eq!(kebab("åäö"), "aao");
    assert_eq!(kebab("Smörgåsbord"), "smorgasbord");
    assert_eq!(kebab("BRÄNNVIN"), "brannvin");
    assert_eq!(kebab("für"), "fuer");
}
