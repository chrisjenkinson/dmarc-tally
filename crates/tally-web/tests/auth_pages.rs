//! Rendering-only authentication pages. HTTP authorization is a separate step.
use tally_web::auth_pages::{
    render_link_confirmation, render_link_invalid, render_sign_in_form, render_sign_in_requested,
};

#[test]
fn login_form_posts_email_without_exposing_admin_configuration() {
    let html = render_sign_in_form();
    assert!(html.contains("<h2>Sign in</h2>"));
    assert!(html.contains(r#"action="/auth/request""#));
    assert!(html.contains(r#"method="post""#));
    assert!(html.contains(r#"type="email""#));
    assert!(html.contains(r#"name="email""#));
    assert!(html.contains(r#"autocomplete="email""#));
    assert!(html.contains(r#"maxlength="254""#));
    assert!(html.contains(r#"required"#));
    // Native same-origin form POSTs need an Origin header; do not leak URL tokens.
    assert!(html.contains(r#"name="referrer" content="strict-origin""#));
    assert!(!html.contains("@example.com"));
}

#[test]
fn request_acknowledgement_is_generic_and_echoes_no_address() {
    let html = render_sign_in_requested();
    assert!(html.contains("If the address is authorised"));
    assert!(html.contains("sign-in link"));
    assert!(!html.contains(r#"name="email""#));
    assert!(!html.contains("not recognised"));
    assert!(!html.contains("Email sent to"));
}

#[test]
fn magic_link_get_requires_explicit_post_before_redeeming() {
    let token = "abcdef0123456789".repeat(4);
    let html = render_link_confirmation(&token);
    assert!(html.contains("<h2>Confirm sign-in</h2>"));
    assert!(html.contains(r#"action="/auth/confirm""#));
    assert!(html.contains(r#"method="post""#));
    assert!(html.contains(r#"type="hidden""#));
    assert!(html.contains(r#"name="token""#));
    assert!(html.contains(&format!(r#"value="{token}""#)));
    // Browser POST redemption needs a genuine Origin; referrer must omit the token query.
    assert!(html.contains(r#"name="referrer" content="strict-origin""#));
    assert!(!html.contains("<script"));
    assert!(!html.contains("autofocus"));
    assert!(!html.contains("window.location"));
}

#[test]
fn invalid_or_enormous_tokens_are_rejected_without_reflecting_attacker_text() {
    let wrong_alphabet = "Z".repeat(64);
    let too_long = "a".repeat(10_000);
    let unexpected = [
        "<script>alert(1)</script>",
        wrong_alphabet.as_str(),
        too_long.as_str(),
        "",
    ];
    for token in unexpected {
        let html = render_link_confirmation(token);
        assert!(html.contains("invalid or expired"));
        assert!(!html.contains(r#"name="token""#));
        assert!(!html.contains("<script"));
        assert!(!html.contains("alert(1)"));
    }
}

#[test]
fn invalid_link_gives_a_safe_retry_path() {
    let html = render_link_invalid();
    assert!(html.contains("invalid or expired"));
    assert!(html.contains(r#"href="/auth/login""#));
    assert!(!html.contains(r#"name="token""#));
}
