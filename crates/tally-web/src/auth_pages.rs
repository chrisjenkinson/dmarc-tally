//! Presentation-only sign-in pages: no AWS, HTTP server, cookies or sessions.
//!
//! The future HTTP adapter must use `Cache-Control: no-store`, enforce
//! session checks before reporting and only redeem magic links on POST.

use crate::pages::{escape_html, finish_page, start_page};

pub fn render_sign_in_form() -> String {
    let mut html = start_page("Sign in");
    html.push_str(
        r#"<h2>Sign in</h2>
<p>Enter your email address to request a sign-in link.</p>
<form method="post" action="/auth/request">
<div><label for="email">Email address</label>
<input type="email" name="email" id="email" autocomplete="email"
inputmode="email" maxlength="254" required></div>
<button type="submit">Send sign-in link</button>
</form>"#,
    );
    finish_page(html)
}

/// Do not echo the submitted address or reveal whether a link was sent.
pub fn render_sign_in_requested() -> String {
    let mut html = start_page("Check your inbox");
    html.push_str(
        r#"<h2>Check your inbox</h2>
<p>If the address is authorised, a sign-in link will be sent shortly.</p>
<p class="muted">The link can only be used once and expires after 15 minutes.</p>
<p><a href="/auth/login">Request another link</a></p>"#,
    );
    finish_page(html)
}

/// Render an emailed GET as a *non-consuming* confirmation step.
/// Only a subsequent browser POST may redeem the challenge.
pub fn render_link_confirmation(token: &str) -> String {
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return render_link_invalid();
    }
    let mut html = start_page("Confirm sign-in");
    html.push_str(
        r#"<h2>Confirm sign-in</h2>
<p>Select the button to finish signing in to your private reports.</p>
<form method="post" action="/auth/confirm"><input type="hidden" name="token" value=""#,
    );
    html.push_str(&escape_html(token));
    html.push_str(
        r#""><button type="submit">Confirm sign-in</button></form>
<p class="muted">If you did not request this link, you can close this page.</p>"#,
    );
    finish_page(html)
}

pub fn render_link_invalid() -> String {
    let mut html = start_page("Link unavailable");
    html.push_str(
        r#"<h2>Sign-in link unavailable</h2>
<p>This sign-in link is invalid or expired.</p>
<p><a href="/auth/login">Request a new sign-in link</a></p>"#,
    );
    finish_page(html)
}
