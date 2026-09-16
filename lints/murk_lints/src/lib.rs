#![feature(rustc_private)]
#![warn(unused_extern_crates)]

// A list of available compiler crates can be found here:
// https://doc.rust-lang.org/nightly/nightly-rustc/
extern crate rustc_hir;
extern crate rustc_lint;
extern crate rustc_middle;
extern crate rustc_session;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use clippy_utils::ty::implements_trait;
use dylint_internal::match_def_path;
use rustc_hir::def::{DefKind, Res};
use rustc_hir::def_id::DefId;
use rustc_hir::{
    Expr, ExprKind, Item, ItemKind, QPath, UnOp,
    intravisit::{self, Visitor},
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_middle::ty::{self, Ty};
use rustc_session::{declare_lint, declare_lint_pass};
use rustc_span::{Span, Symbol, sym};

dylint_linting::dylint_library!();

#[unsafe(no_mangle)]
pub fn register_lints(sess: &rustc_session::Session, lint_store: &mut rustc_lint::LintStore) {
    dylint_linting::init_config(sess);
    lint_store.register_lints(&[
        SECRET_FIELD_MISSING_ZEROIZE,
        SECRET_DEBUG_LEAK,
        SECRET_UNCONTROLLED_ESCAPE,
    ]);
    lint_store.register_late_pass(|_| Box::new(MurkSecretLints));
}

// ---------------------------------------------------------------------------
// Marker strategy (full writeup in lints/murk_lints/README.md):
//
// - "Correctly wrapped" means the *resolved* type (post type-check, so
//   aliases/generics/associated types are already normalized away) is, or
//   contains, `zeroize::Zeroizing<_>`, `age::secrecy::SecretString`, or any
//   type that itself implements `zeroize::ZeroizeOnDrop` — checked with real
//   trait resolution (`clippy_utils::ty::implements_trait`), not name
//   matching. `ZeroizeOnDrop` (not plain `Zeroize`) is the correct bound:
//   `String`/`Vec<u8>` implement `Zeroize` (you *can* call `.zeroize()` on
//   them) but not `ZeroizeOnDrop` — nothing wipes them automatically, which
//   is exactly the bug this lint exists to catch. `Zeroizing<Z>` implements
//   `ZeroizeOnDrop` for any `Z: Zeroize`.
// - Lint (a) checks a *verified allowlist* of (type path, field name) pairs
//   — the crate's own known secret-holding fields, identified by reading the
//   source — rather than guessing at "looks like a secret" from field names.
//   It is a regression guard for known-sensitive fields; it does not
//   discover *new* secret-holding fields on its own (documented limitation:
//   there is no marker trait/attribute in murk_cli today that would let a
//   lint infer "this new field holds a secret" without either guessing from
//   names or an allowlist — see the bead notes).
// - Lint (b) is fully general: any struct/enum with a field that resolves
//   (through containers) to a wrapper/ZeroizeOnDrop-implementing type is
//   "secret-bearing" by that same real type check — no allowlist needed.
// ---------------------------------------------------------------------------

/// (type path, field name) pairs known — from reading the murk_cli source —
/// to hold decrypted plaintext. Extend this list when a new field is added
/// to hold decrypted secret material.
const SECRET_FIELDS: &[(&[&str], &str)] = &[
    (&["murk_cli", "types", "Murk"], "values"),
    (&["murk_cli", "types", "Murk"], "private"),
    (&["murk_cli", "types", "Murk"], "grouped"),
    (&["murk_cli", "crypto", "MurkIdentity"], "pem"),
    (&["murk_cli", "export", "DiffEntry"], "old_value"),
    (&["murk_cli", "export", "DiffEntry"], "new_value"),
];

const ZEROIZING_PATH: &[&str] = &["zeroize", "Zeroizing"];
// `age::secrecy::SecretString` is `pub type SecretString = SecretBox<str>;` —
// a type alias, not its own ADT. The real, originating item (what
// `match_def_path` actually sees) is `secrecy::SecretBox`, defined in the
// `secrecy` crate that `age` depends on and re-exports.
const SECRET_STRING_PATH: &[&str] = &["secrecy", "SecretBox"];

declare_lint! {
    /// ### What it does
    /// Checks that the murk codebase's known plaintext-secret-holding fields
    /// (see `SECRET_FIELDS` in this lint's source) resolve to
    /// `zeroize::Zeroizing`, `age::secrecy::SecretString`, or a type that
    /// itself implements `zeroize::ZeroizeOnDrop` — possibly nested inside
    /// `HashMap`/`BTreeMap`/`Option`/`Vec`.
    ///
    /// ### Why is this bad?
    /// An unwrapped `String`/`Vec<u8>` holding decrypted secret material is
    /// never zeroized on drop, so plaintext can linger in freed heap memory.
    ///
    /// ### Known problems
    /// This is a verified-allowlist regression guard, not a discovery tool:
    /// it only covers the fields listed in `SECRET_FIELDS`. A brand new
    /// secret-holding field on a type this lint doesn't already know about
    /// will not be flagged until it is added to the list.
    pub SECRET_FIELD_MISSING_ZEROIZE,
    Warn,
    "a known plaintext secret-holding field does not wrap Zeroizing/SecretString or implement ZeroizeOnDrop"
}

declare_lint! {
    /// ### What it does
    /// Checks that no `Debug` impl (derived or manual) prints the plaintext
    /// contents of a field whose resolved type is, or contains,
    /// `zeroize::Zeroizing<_>`, or another type implementing
    /// `zeroize::ZeroizeOnDrop` that (like `Zeroizing`) does not redact its
    /// own `Debug` output. `age::secrecy::SecretString` is deliberately
    /// *not* one of these markers — see "Why is this bad?" below.
    ///
    /// ### Why is this bad?
    /// `Zeroizing<T>` is `#[derive(Debug)]` itself and forwards `Debug`
    /// transparently to `T`, so a derived `Debug` on a struct containing one
    /// prints the raw secret. A manual impl that still passes the field
    /// straight through `.field(name, &self.field)` has the same problem.
    /// (`age::secrecy::SecretString` is the opposite: its `Debug` impl
    /// always prints `SecretBox<str>([REDACTED])`, so deriving `Debug` over
    /// a `SecretString` field is already safe and is not flagged.)
    ///
    /// ### Known problems
    /// The manual-impl check only recognizes the standard
    /// `Formatter::debug_struct(..).field(name, value)` builder pattern. A
    /// manual impl that leaks a secret field via `write!`/`format!`
    /// interpolation instead is not analyzed — reliably matching a macro's
    /// desugared argument sinks is fragile across compiler versions, so it
    /// is out of scope here. Every manual `Debug` impl in the murk codebase
    /// today uses the builder pattern or does not reference secret fields at
    /// all, so this covers every real call site at the time this lint was
    /// written.
    pub SECRET_DEBUG_LEAK,
    Warn,
    "a Debug impl exposes a plaintext secret field"
}

declare_lint! {
    /// ### What it does
    /// Checks for `.clone()` or `.to_string()` calls that escape a
    /// `zeroize::Zeroizing<_>`/`age::secrecy::SecretString` wrapper into a
    /// plain, never-zeroized `String`/`Vec<u8>` — i.e. `(*v).clone()` or
    /// `v.to_string()` where `v` is a secret wrapper.
    ///
    /// ### Why is this bad?
    /// The whole point of the wrapper is that the plaintext is zeroized on
    /// drop. Deref'ing past it and cloning/stringifying the inner value
    /// produces a copy with no such guarantee.
    ///
    /// ### Known problems
    /// Cloning the wrapper itself (`v.clone()` where `v: Zeroizing<String>`)
    /// is fine — `Zeroizing<Z: Clone>` implements `Clone` directly and
    /// returns another `Zeroizing`; this lint does not fire on that call
    /// because the call never goes through the wrapper's `Deref`. Use
    /// `#[allow(secret_uncontrolled_escape)]` at documented boundaries
    /// (e.g. handing plaintext to a child process's environment).
    pub SECRET_UNCONTROLLED_ESCAPE,
    Warn,
    "a `.clone()`/`.to_string()` call escapes a secret wrapper into an unzeroized value"
}

declare_lint_pass!(MurkSecretLints => [
    SECRET_FIELD_MISSING_ZEROIZE,
    SECRET_DEBUG_LEAK,
    SECRET_UNCONTROLLED_ESCAPE,
]);

/// Find `zeroize::ZeroizeOnDrop`'s `DefId` by walking the `zeroize` crate's
/// root module. Returns `None` if the crate isn't a dependency of whatever
/// is being linted (in which case none of these lints have anything to
/// check).
///
/// `ZeroizeOnDrop` — not plain `Zeroize` — is the trait that actually
/// matters here: `String`/`Vec<u8>` implement `Zeroize` (you can call
/// `.zeroize()` yourself) but have no `Drop` impl that does so, so treating
/// bare `Zeroize` as "safe" would let an unwrapped `String` field pass this
/// lint despite never being zeroized automatically.
fn zeroize_on_drop_trait_def_id(cx: &LateContext<'_>) -> Option<DefId> {
    cx.tcx.crates(()).iter().find_map(|&krate| {
        if cx.tcx.crate_name(krate).as_str() != "zeroize" {
            return None;
        }
        let root = DefId {
            krate,
            index: rustc_hir::def_id::CRATE_DEF_INDEX,
        };
        cx.tcx
            .module_children(root)
            .iter()
            .find(|child| child.ident.name.as_str() == "ZeroizeOnDrop")
            .and_then(|child| child.res.opt_def_id())
    })
}

/// Does `ty` — possibly nested inside container/ref/tuple generics — resolve
/// to `zeroize::Zeroizing<_>`, `age::secrecy::SecretString`, or a type that
/// itself implements `zeroize::ZeroizeOnDrop`?
fn is_secret_wrapper_ty<'tcx>(
    cx: &LateContext<'tcx>,
    ty: Ty<'tcx>,
    zeroize_on_drop_trait: Option<DefId>,
) -> bool {
    match ty.kind() {
        ty::Adt(adt_def, args) => {
            let did = adt_def.did();
            if match_def_path(cx, did, ZEROIZING_PATH) || match_def_path(cx, did, SECRET_STRING_PATH) {
                return true;
            }
            if let Some(trait_id) = zeroize_on_drop_trait
                && implements_trait(cx, ty, trait_id, &[])
            {
                return true;
            }
            args.types()
                .any(|inner| is_secret_wrapper_ty(cx, inner, zeroize_on_drop_trait))
        }
        ty::Ref(_, inner, _) => is_secret_wrapper_ty(cx, *inner, zeroize_on_drop_trait),
        ty::Tuple(tys) => tys
            .iter()
            .any(|inner| is_secret_wrapper_ty(cx, inner, zeroize_on_drop_trait)),
        ty::Slice(inner) | ty::Array(inner, _) => {
            is_secret_wrapper_ty(cx, *inner, zeroize_on_drop_trait)
        }
        _ => false,
    }
}

/// Does `ty` — possibly nested inside container/ref/tuple generics — resolve
/// to a type whose `Debug` impl *forwards the plaintext transparently*?
///
/// This is a narrower check than [`is_secret_wrapper_ty`], used only by lint
/// (b). `zeroize::Zeroizing<Z>` is `#[derive(Debug)]` itself and forwards to
/// `Z`'s `Debug` — unsafe to derive over. `age::secrecy::SecretString`
/// (`SecretBox<str>`) is different: its own `Debug` impl always prints
/// `SecretBox<str>([REDACTED])` (verified in the `secrecy` crate source), so
/// a struct that only contains a `SecretString` field is safe to derive
/// `Debug` on — explicitly excluded here, even though `SecretBox` also
/// implements `ZeroizeOnDrop` (which would otherwise match the generic
/// fallback below). A custom type that implements `ZeroizeOnDrop` *and*
/// redacts its own `Debug` (like `SecretBox`) but isn't `SecretString`
/// itself would still false-positive here; no such type exists in murk_cli
/// today.
fn is_debug_leaking_wrapper_ty<'tcx>(
    cx: &LateContext<'tcx>,
    ty: Ty<'tcx>,
    zeroize_on_drop_trait: Option<DefId>,
) -> bool {
    match ty.kind() {
        ty::Adt(adt_def, args) => {
            let did = adt_def.did();
            if match_def_path(cx, did, SECRET_STRING_PATH) {
                return false;
            }
            if match_def_path(cx, did, ZEROIZING_PATH) {
                return true;
            }
            if let Some(trait_id) = zeroize_on_drop_trait
                && implements_trait(cx, ty, trait_id, &[])
            {
                return true;
            }
            args.types()
                .any(|inner| is_debug_leaking_wrapper_ty(cx, inner, zeroize_on_drop_trait))
        }
        ty::Ref(_, inner, _) => is_debug_leaking_wrapper_ty(cx, *inner, zeroize_on_drop_trait),
        ty::Tuple(tys) => tys
            .iter()
            .any(|inner| is_debug_leaking_wrapper_ty(cx, inner, zeroize_on_drop_trait)),
        ty::Slice(inner) | ty::Array(inner, _) => {
            is_debug_leaking_wrapper_ty(cx, *inner, zeroize_on_drop_trait)
        }
        _ => false,
    }
}

/// Resolved field types of every field across every variant of a local
/// struct/enum `DefId` (unit variants contribute nothing), instantiated at
/// the given generic args.
fn resolved_field_types<'tcx>(
    cx: &LateContext<'tcx>,
    adt_def_id: DefId,
    args: ty::GenericArgsRef<'tcx>,
) -> Vec<(Symbol, Ty<'tcx>)> {
    let adt_def = cx.tcx.adt_def(adt_def_id);
    adt_def
        .all_fields()
        .map(|field| {
            let ty = cx
                .tcx
                .type_of(field.did)
                .instantiate(cx.tcx, args)
                .skip_norm_wip();
            (field.name, ty)
        })
        .collect()
}

impl<'tcx> LateLintPass<'tcx> for MurkSecretLints {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        match &item.kind {
            ItemKind::Struct(..) | ItemKind::Enum(..) => {
                check_secret_field_allowlist(cx, item);
            }
            ItemKind::Impl(imp) => {
                check_debug_impl(cx, item, imp);
            }
            _ => {}
        }
    }

    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        check_uncontrolled_escape(cx, expr);
    }
}

/// Lint (a): verified allowlist of known secret-holding fields.
fn check_secret_field_allowlist<'tcx>(cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
    let item_def_id = item.owner_id.to_def_id();
    if !SECRET_FIELDS
        .iter()
        .any(|(type_path, _)| match_def_path(cx, item_def_id, type_path))
    {
        return;
    }
    let zeroize_trait = zeroize_on_drop_trait_def_id(cx);
    let identity_args = ty::GenericArgs::identity_for_item(cx.tcx, item_def_id);
    let fields = resolved_field_types(cx, item_def_id, identity_args);

    for (type_path, field_name) in SECRET_FIELDS {
        if !match_def_path(cx, item_def_id, type_path) {
            continue;
        }
        let Some((_, ty)) = fields.iter().find(|(name, _)| name.as_str() == *field_name) else {
            continue;
        };
        if !is_secret_wrapper_ty(cx, *ty, zeroize_trait) {
            span_lint_and_help(
                cx,
                SECRET_FIELD_MISSING_ZEROIZE,
                item.span,
                format!(
                    "`{}::{field_name}` is a known plaintext secret field but its type (`{ty}`) \
                     no longer wraps `Zeroizing`/`SecretString` and does not implement \
                     `ZeroizeOnDrop`",
                    type_path.join("::"),
                ),
                None,
                "wrap the value in `zeroize::Zeroizing` (or `age::secrecy::SecretString`) so it \
                 is wiped from memory on drop",
            );
        }
    }
}

/// Lint (b): no `Debug` impl (derived or the common manual builder pattern)
/// may print a secret-wrapper field's plaintext.
fn check_debug_impl<'tcx>(
    cx: &LateContext<'tcx>,
    item: &'tcx Item<'tcx>,
    imp: &rustc_hir::Impl<'tcx>,
) {
    let Some(of_trait) = imp.of_trait else {
        return;
    };
    let Res::Def(DefKind::Trait, trait_def_id) = of_trait.trait_ref.path.res else {
        return;
    };
    if !match_def_path(cx, trait_def_id, &["core", "fmt", "Debug"]) {
        return;
    }
    let rustc_hir::TyKind::Path(QPath::Resolved(_, self_path)) = &imp.self_ty.kind else {
        return;
    };
    let Res::Def(DefKind::Struct | DefKind::Enum, self_def_id) = self_path.res else {
        return;
    };

    let zeroize_trait = zeroize_on_drop_trait_def_id(cx);
    let identity_args = ty::GenericArgs::identity_for_item(cx.tcx, self_def_id);
    let secret_fields: Vec<Symbol> = resolved_field_types(cx, self_def_id, identity_args)
        .into_iter()
        .filter(|(_, ty)| is_debug_leaking_wrapper_ty(cx, *ty, zeroize_trait))
        .map(|(name, _)| name)
        .collect();
    if secret_fields.is_empty() {
        return;
    }

    let is_derived = rustc_hir::find_attr!(cx.tcx, item.owner_id.def_id, AutomaticallyDerived);
    if is_derived {
        // `span_lint_and_help`/`span_lint_and_then` compute the lint level
        // from the *span*, and by default suppress diagnostics whose span
        // lands inside a standard-library macro expansion — which is
        // exactly where a `#[derive(Debug)]`-generated impl lives. Use the
        // `_hir` variant instead: it computes the level from `hir_id`
        // (here, the struct/enum item itself — real, user-written code), so
        // the warning isn't silently dropped.
        let self_item = cx.tcx.hir_expect_item(
            self_def_id
                .as_local()
                .expect("Struct/Enum Res::Def always resolves to a local item here"),
        );
        let name = cx.tcx.item_name(self_def_id);
        clippy_utils::diagnostics::span_lint_hir_and_then(
            cx,
            SECRET_DEBUG_LEAK,
            self_item.hir_id(),
            self_item.span,
            format!(
                "derived `Debug` on `{name}` exposes plaintext secret field(s): {}",
                secret_fields
                    .iter()
                    .map(Symbol::as_str)
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            |diag| {
                diag.help(
                    "`Zeroizing` forwards `Debug` transparently; write a manual \
                     `impl Debug` that redacts these fields instead of deriving it",
                );
            },
        );
        return;
    }

    // Manual impl: look for `.field(name, &self.<secret_field>)` in `fmt`.
    for impl_item_id in imp.items {
        let impl_item = cx.tcx.hir_impl_item(*impl_item_id);
        if impl_item.ident.name != sym::fmt {
            continue;
        }
        let rustc_hir::ImplItemKind::Fn(_, body_id) = impl_item.kind else {
            continue;
        };
        let body = cx.tcx.hir_body(body_id);
        let mut visitor = DebugFieldCallVisitor {
            secret_fields: &secret_fields,
            hits: Vec::new(),
        };
        visitor.visit_body(body);
        for (span, field) in visitor.hits {
            span_lint_and_help(
                cx,
                SECRET_DEBUG_LEAK,
                span,
                format!("manual `Debug` impl exposes plaintext secret field `{field}` directly"),
                None,
                "pass a redacted placeholder (e.g. a `<redacted>` marker, or just the map's \
                 keys) instead of the field itself",
            );
        }
    }
}

struct DebugFieldCallVisitor<'a> {
    secret_fields: &'a [Symbol],
    hits: Vec<(Span, Symbol)>,
}

fn is_self_ident(expr: &Expr<'_>) -> bool {
    matches!(
        &expr.kind,
        ExprKind::Path(QPath::Resolved(None, path))
            if path.segments.len() == 1
                && path.segments[0].ident.name == rustc_span::symbol::kw::SelfLower
    )
}

fn peel_ref<'e, 'tcx>(expr: &'e Expr<'tcx>) -> &'e Expr<'tcx> {
    match &expr.kind {
        ExprKind::AddrOf(_, _, inner) => peel_ref(inner),
        _ => expr,
    }
}

impl<'tcx> Visitor<'tcx> for DebugFieldCallVisitor<'_> {
    fn visit_expr(&mut self, ex: &'tcx Expr<'tcx>) {
        if let ExprKind::MethodCall(seg, _receiver, args, _) = ex.kind
            && seg.ident.name.as_str() == "field"
            && args.len() == 2
        {
            let value = peel_ref(&args[1]);
            if let ExprKind::Field(base, field_ident) = value.kind
                && is_self_ident(base)
                && self.secret_fields.contains(&field_ident.name)
            {
                self.hits.push((args[1].span, field_ident.name));
            }
        }
        intravisit::walk_expr(self, ex);
    }
}

/// Lint (c): `.clone()`/`.to_string()` that escapes a secret wrapper into an
/// unwrapped plain value (explicit `(*v).clone()`, or `.to_string()` on a
/// wrapper — `to_string` always returns a bare `String`).
///
/// This checks the *result* type of the call rather than typeck adjustments:
/// `v.clone()` where `v: &Zeroizing<String>` resolves through a `Deref`
/// adjustment too (autoref/autoderef probing lands on `Zeroizing::clone`
/// rather than the blanket `impl<T> Clone for &T`), but it still returns
/// `Zeroizing<String>` — safe. Gating on "did the call's output lose the
/// wrapper" avoids that false positive while still catching the two real
/// escape shapes.
fn check_uncontrolled_escape<'tcx>(cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
    let ExprKind::MethodCall(seg, receiver, _args, span) = expr.kind else {
        return;
    };
    let name = seg.ident.name.as_str();
    if name != "clone" && name != "to_string" {
        return;
    }

    // If the call still returns a wrapper (e.g. `Zeroizing::clone`), plaintext
    // never escaped — nothing to flag, regardless of how the receiver got here.
    let result_ty = cx.typeck_results().expr_ty(expr);
    if is_wrapper_adt(cx, result_ty) {
        return;
    }

    // Explicit `(*v).clone()` / `(*v).to_string()`.
    if let ExprKind::Unary(UnOp::Deref, inner) = receiver.kind {
        let inner_ty = cx.typeck_results().expr_ty(inner);
        if is_wrapper_adt(cx, inner_ty) {
            emit_escape_lint(cx, span, name);
            return;
        }
    }

    // `v.to_string()` where `v` (or `&v`) is a wrapper — `to_string` always
    // returns a bare `String`, so reaching here means it just escaped.
    let receiver_ty = cx.typeck_results().expr_ty(receiver);
    if is_wrapper_adt(cx, receiver_ty) {
        emit_escape_lint(cx, span, name);
    }
}

/// Top-level (non-recursive) wrapper check for lint (c): the receiver must
/// *be* the wrapper, not merely contain one somewhere in a generic arg.
fn is_wrapper_adt<'tcx>(cx: &LateContext<'tcx>, ty: Ty<'tcx>) -> bool {
    match ty.peel_refs().kind() {
        ty::Adt(adt_def, _) => {
            let did = adt_def.did();
            match_def_path(cx, did, ZEROIZING_PATH) || match_def_path(cx, did, SECRET_STRING_PATH)
        }
        _ => false,
    }
}

fn emit_escape_lint(cx: &LateContext<'_>, span: Span, method: &str) {
    span_lint_and_help(
        cx,
        SECRET_UNCONTROLLED_ESCAPE,
        span,
        format!(
            "`.{method}()` escapes a secret wrapper (`Zeroizing`/`SecretString`) into a plain, \
             never-zeroized value"
        ),
        None,
        "keep the value wrapped end-to-end, or if this is a documented boundary (e.g. handing \
         plaintext to a child process env), annotate the call site with \
         `#[allow(secret_uncontrolled_escape)]` and explain why",
    );
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
