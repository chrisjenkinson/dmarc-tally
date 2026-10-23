//! On-demand public DNS checks for the configured DMARC receiving path.
//! No DNS updates, third-party DoH services or user-controlled query names.
//! All resolver queries are bounded and run only after HTTP session checks.

use hickory_resolver::{error::ResolveErrorKind, TokioAsyncResolver};
use std::time::Duration;

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsState {
    Ready,
    ActionRequired,
    NotVerified,
    UnableToCheck,
}

#[derive(Clone, Debug)]
pub struct DnsCheck {
    pub title: &'static str,
    pub state: DnsState,
    pub detail: String,
}

fn check(title: &'static str, state: DnsState, detail: impl Into<String>) -> DnsCheck {
    DnsCheck {
        title,
        state,
        detail: detail.into(),
    }
}

#[derive(Debug)]
enum LookupError {
    NoRecords,
    Unavailable,
}

fn map_error(error: &hickory_resolver::error::ResolveError) -> LookupError {
    match error.kind() {
        ResolveErrorKind::NoRecordsFound { .. } => LookupError::NoRecords,
        _ => LookupError::Unavailable,
    }
}

async fn mx_records(
    resolver: &TokioAsyncResolver,
    host: &str,
) -> Result<Vec<(u16, String)>, LookupError> {
    let lookup = tokio::time::timeout(LOOKUP_TIMEOUT, resolver.mx_lookup(host))
        .await
        .map_err(|_| LookupError::Unavailable)?
        .map_err(|error| map_error(&error))?;
    Ok(lookup
        .iter()
        .map(|mx| (mx.preference(), mx.exchange().to_utf8()))
        .collect())
}

async fn txt_records(
    resolver: &TokioAsyncResolver,
    host: &str,
) -> Result<Vec<String>, LookupError> {
    let lookup = tokio::time::timeout(LOOKUP_TIMEOUT, resolver.txt_lookup(host))
        .await
        .map_err(|_| LookupError::Unavailable)?
        .map_err(|error| map_error(&error))?;
    Ok(lookup
        .iter()
        .map(|txt| {
            txt.txt_data()
                .iter()
                .map(|chunk| String::from_utf8_lossy(chunk))
                .collect::<String>()
        })
        .collect())
}

fn mx_state(records: &[(u16, String)], region: &str) -> DnsState {
    let expected = format!("inbound-smtp.{region}.amazonaws.com.");
    if records.len() == 1 && records[0].0 == 10 && records[0].1.eq_ignore_ascii_case(&expected) {
        DnsState::Ready
    } else {
        DnsState::ActionRequired
    }
}

fn dmarc_records(values: &[String]) -> Vec<&str> {
    values
        .iter()
        .map(String::as_str)
        .filter(|txt| {
            txt.split(';')
                .next()
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("v=DMARC1"))
        })
        .collect()
}

fn rua_state(records: &[String], address: &str) -> DnsState {
    let dmarc = dmarc_records(records);
    if dmarc.len() != 1 {
        return if dmarc.is_empty() {
            DnsState::NotVerified
        } else {
            DnsState::ActionRequired
        };
    }
    let intended = format!("mailto:{address}");
    let matches = dmarc[0]
        .split(';')
        .filter_map(|field| {
            let (key, val) = field.trim().split_once('=')?;
            (key.trim().eq_ignore_ascii_case("rua")).then_some(val)
        })
        .any(|addresses| {
            addresses.split(',').any(|entry| {
                entry
                    .trim()
                    .split('!')
                    .next()
                    .is_some_and(|entry| entry.eq_ignore_ascii_case(&intended))
            })
        });
    if matches {
        DnsState::Ready
    } else {
        DnsState::ActionRequired
    }
}

fn authorization_state(records: &[String]) -> DnsState {
    if records.iter().any(|txt| {
        txt.split(';')
            .next()
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("v=DMARC1"))
    }) {
        DnsState::Ready
    } else {
        DnsState::ActionRequired
    }
}

async fn inspect_domain(
    resolver: TokioAsyncResolver,
    domain: String,
    receiving_address: String,
    receiving_domain: String,
) -> Vec<DnsCheck> {
    let mut checks = Vec::new();
    let name = format!("_dmarc.{domain}.");
    let rua = match txt_records(&resolver, &name).await {
        Ok(records) => {
            let state = rua_state(&records, &receiving_address);
            check("DMARC rua destination", state, format!(
                "{domain}: {}", match state {
                    DnsState::Ready => "Published policy includes the configured reporting mailbox.",
                    DnsState::NotVerified => "No explicit DMARC policy found here; an inherited policy may apply. Verify manually.",
                    _ => "Published DMARC policy is missing the configured reporting mailbox, or multiple policies exist.",
                }))
        }
        Err(LookupError::NoRecords) => check(
            "DMARC rua destination",
            DnsState::NotVerified,
            format!("{domain}: no direct DMARC TXT record; an inherited policy may apply."),
        ),
        Err(LookupError::Unavailable) => check(
            "DMARC rua destination",
            DnsState::UnableToCheck,
            format!("{domain}: DNS TXT query could not be completed."),
        ),
    };
    let matched_rua = rua.state == DnsState::Ready;
    checks.push(rua);

    // A subdomain of the source policy domain shares its reporting
    // organisational context; do not require external authorisation.
    if receiving_domain == domain || receiving_domain.ends_with(&format!(".{domain}")) {
        checks.push(check(
            "External DMARC reporting authorisation",
            DnsState::Ready,
            format!("{domain}: reporting destination is within the policy domain."),
        ));
    } else if matched_rua {
        // DNS alone does not prove organisational-domain equivalence
        // (e.g. sibling hosts or co.nz); missing authorisation is unknown,
        // not conclusive evidence of a broken installation.
        let auth_name = format!("{domain}._report._dmarc.{receiving_domain}.");
        let auth = match txt_records(&resolver, &auth_name).await {
            Ok(records) => {
                let state = authorization_state(&records);
                check("External DMARC reporting authorisation", state,
                    format!("{domain}: {}", if state == DnsState::Ready {
                        "Destination authorisation TXT record is present."
                    } else { "Destination TXT exists but does not authorise DMARC reporting." }))
            }
            Err(LookupError::NoRecords) => check("External DMARC reporting authorisation",
                DnsState::NotVerified, format!("{domain}: no external authorisation TXT found. Confirm whether the destination is in the same organisational domain; otherwise publish the required TXT.")),
            Err(LookupError::Unavailable) => check("External DMARC reporting authorisation",
                DnsState::UnableToCheck, format!("{domain}: external authorisation TXT query failed.")),
        };
        checks.push(auth);
    } else {
        checks.push(check(
            "External DMARC reporting authorisation",
            DnsState::NotVerified,
            format!("{domain}: resolve the DMARC rua destination first."),
        ));
    }
    checks
}

/// At most 30 configured domains, checked concurrently to bound page time.
/// The caller must have authenticated the HTTP request before calling.
pub async fn inspect_dns(
    receiving: Option<&str>,
    domains: Vec<String>,
    region: &str,
) -> Vec<DnsCheck> {
    let Some((_, host)) = receiving.and_then(|a| a.split_once('@')) else {
        return vec![check(
            "Receiving MX",
            DnsState::ActionRequired,
            "Configure a valid receiving mailbox.",
        )];
    };
    if host.is_empty() || region.is_empty() {
        return vec![check(
            "Receiving MX",
            DnsState::UnableToCheck,
            "Receiving domain or AWS region is missing.",
        )];
    }
    let Ok(resolver) = TokioAsyncResolver::tokio_from_system_conf() else {
        return vec![check(
            "Receiving MX",
            DnsState::UnableToCheck,
            "System DNS resolver is unavailable.",
        )];
    };
    let mut checks = Vec::new();
    let mx = match mx_records(&resolver, &format!("{host}.")).await {
        Ok(records) => {
            let state = mx_state(&records, region);
            check(
                "Receiving MX",
                state,
                if state == DnsState::Ready {
                    "MX directs the dedicated receiving domain to the SES inbound endpoint."
                } else {
                    "The receiving-domain MX does not exclusively match the expected regional SES inbound endpoint (priority 10)."
                },
            )
        }
        Err(LookupError::NoRecords) => check(
            "Receiving MX",
            DnsState::ActionRequired,
            "No MX record was found for the receiving domain.",
        ),
        Err(LookupError::Unavailable) => check(
            "Receiving MX",
            DnsState::UnableToCheck,
            "Receiving-domain MX lookup could not be completed.",
        ),
    };
    checks.push(mx);
    let mut tasks = tokio::task::JoinSet::new();
    for domain in domains.into_iter().take(30) {
        tasks.spawn(inspect_domain(
            resolver.clone(),
            domain,
            receiving.unwrap_or_default().to_owned(),
            host.to_owned(),
        ));
    }
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(mut items) => checks.append(&mut items),
            Err(_) => checks.push(check(
                "DMARC DNS",
                DnsState::UnableToCheck,
                "A domain check could not finish.",
            )),
        }
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::{authorization_state, dmarc_records, mx_state, rua_state, DnsState};
    #[test]
    fn expected_mx_is_exact_and_other_routes_require_action() {
        assert_eq!(
            mx_state(
                &[(10, "inbound-smtp.ap-southeast-2.amazonaws.com.".into())],
                "ap-southeast-2"
            ),
            DnsState::Ready
        );
        assert_eq!(
            mx_state(&[(20, "mx.other.example.".into())], "ap-southeast-2"),
            DnsState::ActionRequired
        );
    }
    #[test]
    fn rua_requires_explicit_matching_address_and_one_dmarc_policy() {
        let records =
            vec!["v=DMARC1; p=none; rua=mailto:reports@dmarc.test,mailto:other@test".to_owned()];
        assert_eq!(rua_state(&records, "reports@dmarc.test"), DnsState::Ready);
        assert_eq!(
            rua_state(&records, "unrelated@dmarc.test"),
            DnsState::ActionRequired
        );
        assert_eq!(rua_state(&[], "reports@dmarc.test"), DnsState::NotVerified);
        assert_eq!(dmarc_records(&records).len(), 1);
    }
    #[test]
    fn external_authorization_requires_valid_dmarc_txt() {
        assert_eq!(authorization_state(&["v=DMARC1".into()]), DnsState::Ready);
        assert_eq!(
            authorization_state(&["unrelated=example".into()]),
            DnsState::ActionRequired
        );
    }
}
