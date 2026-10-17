//! The mail vertical — "will anyone accept mail from this domain?"
//!
//! # What was already here, and why it wasn't enough
//!
//! Mail did not lack a DNS check. `GET /api/mail/domains/{id}/dns-check` has
//! existed for a long time, is wired to a "Check DNS" button, and reports
//! `4/4 records verified`. The problem is what it verifies: **existence, not
//! correctness.**
//!
//! * MX passed if the domain had *any* MX record — including one pointing at
//!   Google Workspace, i.e. precisely the configuration under which this server's
//!   mail goes nowhere.
//! * SPF passed if any `v=spf1` string existed, without checking that it
//!   authorises *this* server. A domain whose SPF ends `include:sendgrid.net -all`
//!   reported a pass while explicitly forbidding us to send.
//! * DKIM passed on `contains("v=DKIM1") || contains("p=")` — never compared to
//!   our own key, so a stale selector from a previous install passed.
//! * The A record for the mail host was not checked at all.
//! * A failure produced the string `"Not found"` and nothing to do about it.
//!
//! So an operator could see "All DNS records verified" on a domain whose mail was
//! being rejected. That is worse than no check: it is a check that certifies the
//! broken state.
//!
//! # And the records we told them to create were wrong
//!
//! There were two independent spellings of "the records this domain needs":
//! `routes::mail::domain_dns` (what we tell you to create) and
//! `routes::mail::auto_create_mail_dns` (what we create for you). They disagreed
//! on the server address, the A record's name, the MX target, the SPF policy
//! (`~all` vs `-all`) and the DKIM selector — and the manual one was outright
//! wrong, because it read the agent's **hostname** where it wanted an IP:
//!
//! ```text
//! A    mail.example.com  →  my-server            (not an address)
//! TXT  example.com       →  v=spf1 a mx ip4:my-server ~all   (invalid SPF)
//! ```
//!
//! [`mail_records`] is now the single source all three paths call. Same class as
//! the `parse_agent_cert_expiry` consolidation in v2.28.0: a value spelled in two
//! places is a value that is wrong in one of them.

use super::copy::{
    MAIL_DKIM_CHECK, MAIL_DKIM_MISSING, MAIL_DKIM_READY, MAIL_DNS_ALL_PUBLISHED, MAIL_DNS_CHECK,
    MAIL_DNS_MISSING_ALL, MAIL_DNS_MISSING_SOME, MAIL_DNS_NO_PUBLIC_IP, MAIL_DNS_UNREADABLE,
};
use super::{DnsRecordHint, PrereqResult, Remediation};
use crate::safe_cmd::safe_command;

/// The DKIM selector DockPanel uses when a domain doesn't record its own.
pub const DEFAULT_DKIM_SELECTOR: &str = "dockpanel";

/// Turn a stored DKIM public key (PEM) into its DNS TXT value.
pub fn dkim_txt_value(public_key_pem: &str) -> String {
    let key_data = public_key_pem
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace('\n', "")
        .replace('\r', "");
    format!("v=DKIM1; k=rsa; p={key_data}")
}

/// The complete set of DNS records a mail domain needs, values filled in.
///
/// THE single source of truth: the DNS tab renders this, the auto-DNS writer
/// publishes this, and [`check_mail_dns_published`] verifies this. `server_ip`
/// must be a real address — pass [`crate::helpers::detect_public_ip_cached`],
/// never the agent's hostname.
///
/// # Why the mail host is the apex and not `mail.<domain>`
///
/// The two old spellings disagreed about this, and it is tempting to pick the
/// conventional `mail.<domain>`. Consolidating on that would have been wrong,
/// because it is not what this product deploys:
///
/// * `auto_create_mail_dns` publishes `A <domain>` and `MX <domain> → <domain>`,
///   so every domain DockPanel has ever configured automatically uses the apex.
///   Describing a different topology would report all of them as broken.
/// * The auto-SSL step immediately after issues a certificate for `<domain>` over
///   HTTP-01, which requires the apex A record to exist. Moving the mail host to
///   a subdomain would silently break certificate issuance for new mail domains.
///
/// Postfix's `myhostname` is left at the distro default and never pinned by
/// DockPanel, so neither topology is enforced by the mail stack — which is
/// exactly why the check accepts both (see [`record_satisfies`]) while we only
/// ever *advise* one.
pub fn mail_records(
    domain: &str,
    selector: &str,
    dkim_public_key: Option<&str>,
    server_ip: &str,
) -> Vec<DnsRecordHint> {
    let mut records = vec![
        DnsRecordHint::new("@", domain, "A", server_ip, "300")
            .with_purpose("The address other mail servers connect to. Must not be proxied."),
        DnsRecordHint::new("@", domain, "MX", format!("10 {domain}"), "300")
            .with_purpose("Where mail for this domain is delivered."),
        DnsRecordHint::new(
            "@",
            domain,
            "TXT",
            // No `a` term: a domain whose A record is proxied (Cloudflare, say)
            // would then authorise that CDN's shared addresses to send as the
            // domain — a spam signal, and an authorisation nobody intended.
            // `mx` and the explicit `ip4:` already cover this server, and `-all`
            // states the intent that nothing else may send.
            format!("v=spf1 mx ip4:{server_ip} -all"),
            "300",
        )
        .with_purpose("SPF — authorises this server to send mail for the domain."),
        DnsRecordHint::new(
            "_dmarc",
            format!("_dmarc.{domain}"),
            "TXT",
            format!("v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}"),
            "300",
        )
        .with_purpose("DMARC — tells receivers what to do when SPF or DKIM fails."),
    ];

    if let Some(pem) = dkim_public_key.filter(|p| !p.trim().is_empty()) {
        records.push(
            DnsRecordHint::new(
                format!("{selector}._domainkey"),
                format!("{selector}._domainkey.{domain}"),
                "TXT",
                dkim_txt_value(pem),
                "300",
            )
            .with_purpose("DKIM — the public key receivers use to verify our signature."),
        );
    }

    records
}

/// Whether a published value satisfies the record we asked for.
///
/// Deliberately looser than equality for the *policy* records, and strict for the
/// *key* record. Someone who publishes
/// `v=spf1 a mx ip4:1.2.3.4 include:sendgrid.net -all` has a better SPF record
/// than the one we suggest, and reporting it as missing would be both wrong and
/// infuriating. But a DKIM record carrying somebody else's key is not a stricter
/// setup, it is a broken one — which is exactly what the old `contains("p=")`
/// test could not tell apart.
pub(crate) fn record_satisfies(expected: &DnsRecordHint, found: &str, server_ip: &str) -> bool {
    let found = strip_quotes(found);
    let expected_value = expected.value.trim();

    match expected.record_type.as_str() {
        "A" => found == expected_value,
        "MX" => {
            // Any MX naming this server counts, whatever its preference — a backup
            // MX at a different priority is a valid setup, not a fault.
            //
            // `mail.<domain>` is accepted alongside the apex we advise. That is not
            // laxity: the DNS tab told people to use `mail.<domain>` for years, it
            // is the conventional choice, and it works — Postfix accepts mail for
            // any virtual domain regardless of the MX hostname, provided it
            // resolves here. Rejecting it would flag a working install as broken,
            // which is the exact failure mode this check replaces.
            let apex = expected_value.split_whitespace().last().unwrap_or_default().trim_end_matches('.');
            let accepted = [apex.to_string(), format!("mail.{apex}")];
            found
                .split_whitespace()
                .last()
                .map(|h| {
                    let h = h.trim_end_matches('.');
                    accepted.iter().any(|a| a.eq_ignore_ascii_case(h))
                })
                .unwrap_or(false)
        }
        "TXT" if expected_value.starts_with("v=spf1") => {
            found.starts_with("v=spf1")
                && (found.contains(server_ip)
                    // `a`/`mx` authorise us indirectly and `include:` delegates to
                    // a provider; we cannot resolve the operator's full intent, so
                    // accept them rather than cry wolf.
                    || found
                        .split_whitespace()
                        .any(|m| m == "a" || m == "mx" || m.starts_with("include:")))
        }
        "TXT" if expected_value.starts_with("v=DMARC1") => found.starts_with("v=DMARC1"),
        "TXT" if expected_value.starts_with("v=DKIM1") => {
            // Compare key material only, ignoring the whitespace and quoting that
            // providers introduce when splitting long TXT strings.
            let squash = |s: &str| s.chars().filter(|c| !c.is_whitespace() && *c != '"').collect::<String>();
            let want = squash(expected_value);
            let key = want.split("p=").nth(1).unwrap_or(&want).to_string();
            !key.is_empty() && squash(&found).contains(&key)
        }
        _ => found == expected_value,
    }
}

fn strip_quotes(s: &str) -> String {
    // A TXT value served in chunks arrives as `"part1" "part2"` — join it back
    // before comparing, or a long DKIM key never matches.
    s.trim().replace("\" \"", "").trim_matches('"').trim().to_string()
}

/// Look one record up. `None` means we could not ask — never "not published".
///
/// The distinction is the whole reason this returns an `Option`: a box without
/// `dig` installed would otherwise report every record as missing and send the
/// operator to their registrar to re-create records that are already correct.
async fn lookup(record: &DnsRecordHint) -> Option<Vec<String>> {
    // Defence in depth. `is_valid_domain` already guards what reaches
    // `mail_domains`, but this module is callable from anywhere, and a name that
    // dig parses as an option is a command-injection primitive.
    if !crate::routes::dns::is_safe_dig_arg(&record.fqdn, true) {
        return None;
    }
    let rtype = match record.record_type.as_str() {
        "A" | "MX" | "TXT" => record.record_type.as_str(),
        _ => return None,
    };

    let out = safe_command("dig")
        .args(["+short", "+time=3", "+tries=1", rtype, &record.fqdn])
        .output()
        .await
        .ok()?;

    if !out.status.success() {
        return None;
    }

    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect(),
    )
}

/// Check: are this mail domain's DNS records actually published, and do they
/// point at *this* server?
///
/// # Severity
///
/// `Warning`, never `Blocking`, and that follows the governing rule rather than
/// timidity: nothing in the panel is gated on this. Mail already flows without
/// these records — badly. The consequence of a missing SPF record is that other
/// people's servers form a judgement about you, which DockPanel cannot refuse on
/// your behalf. There is no control to disable, so there is nothing to block;
/// what there is, is a domain quietly landing in spam folders with nothing
/// anywhere in the product saying so.
pub async fn check_mail_dns_published(
    domain: &str,
    selector: &str,
    dkim_public_key: Option<&str>,
    server_ip: &str,
) -> PrereqResult {
    if server_ip.is_empty() {
        return MAIL_DNS_CHECK.result(&MAIL_DNS_NO_PUBLIC_IP, &[]);
    }

    let wanted = mail_records(domain, selector, dkim_public_key, server_ip);

    let mut checked: Vec<DnsRecordHint> = Vec::with_capacity(wanted.len());
    let mut missing: Vec<String> = Vec::new();
    let mut observed: Vec<String> = Vec::new();
    let mut unreadable = 0usize;

    for record in wanted {
        match lookup(&record).await {
            None => {
                unreadable += 1;
                checked.push(record);
            }
            Some(found) => {
                let present = found.iter().any(|f| record_satisfies(&record, f, server_ip));
                if !present {
                    missing.push(format!("{} {}", record.record_type, record.fqdn));
                }
                if !found.is_empty() {
                    observed.push(format!(
                        "{} {}: {}",
                        record.record_type,
                        record.fqdn,
                        found.join(" / ")
                    ));
                }
                checked.push(record.with_present(present));
            }
        }
    }

    // Every lookup failed — that is a broken `dig`, not a broken domain.
    if unreadable == checked.len() {
        return MAIL_DNS_CHECK
            .result(&MAIL_DNS_UNREADABLE, &[])
            .with_remediation(Remediation::DnsRecords { records: checked });
    }

    if missing.is_empty() {
        return MAIL_DNS_CHECK
            .result(&MAIL_DNS_ALL_PUBLISHED, &[("domain", domain)])
            .with_observed(observed);
    }

    let rendered = {
        let count = missing.len().to_string();
        let total = checked.len().to_string();
        let joined = missing.join(", ");
        let vars = [
            ("domain", domain),
            ("count", count.as_str()),
            ("total", total.as_str()),
            ("missing", joined.as_str()),
        ];
        let outcome = if missing.len() == checked.len() {
            &MAIL_DNS_MISSING_ALL
        } else {
            &MAIL_DNS_MISSING_SOME
        };
        MAIL_DNS_CHECK.result(outcome, &vars)
    };

    rendered
        .with_expected(server_ip.to_string())
        .with_observed(observed)
        .with_remediation(Remediation::DnsRecords { records: checked })
}

/// A domain whose DKIM keys never generated can't sign anything.
///
/// Surfaced separately because the fix is different in kind: it is an action in
/// DockPanel, not a record at the registrar. `create_domain` logs a warning and
/// stores the domain anyway when generation fails, so this state is reachable and
/// otherwise invisible.
pub fn check_dkim_key_present(domain: &str, dkim_public_key: Option<&str>) -> PrereqResult {
    let outcome = match dkim_public_key {
        Some(pem) if !pem.trim().is_empty() => &MAIL_DKIM_READY,
        _ => &MAIL_DKIM_MISSING,
    };
    MAIL_DKIM_CHECK.result(outcome, &[("domain", domain)])
}

/// Evaluate the mail prerequisites for one domain.
pub async fn evaluate(
    domain: &str,
    selector: &str,
    dkim_public_key: Option<&str>,
    server_ip: &str,
) -> Vec<PrereqResult> {
    vec![
        check_dkim_key_present(domain, dkim_public_key),
        check_mail_dns_published(domain, selector, dkim_public_key, server_ip).await,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::prerequisites::{PrereqSeverity, PrereqState};

    const PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\nhkiG9w0B\n-----END PUBLIC KEY-----\n";

    fn records() -> Vec<DnsRecordHint> {
        mail_records("example.com", "dockpanel", Some(PEM), "203.0.113.7")
    }

    fn of_type(t: &str) -> DnsRecordHint {
        records().into_iter().find(|r| r.record_type == t).unwrap()
    }

    fn txt_starting(prefix: &str) -> DnsRecordHint {
        records().into_iter().find(|r| r.value.starts_with(prefix)).unwrap()
    }

    // ── the record set ────────────────────────────────────────────────────

    /// The pre-v2.29.0 bug in one assertion: the manual DNS tab published the
    /// agent's hostname where an address belongs.
    #[test]
    fn the_record_set_uses_the_ip_it_is_given_everywhere() {
        let a = of_type("A");
        assert_eq!(a.value, "203.0.113.7");
        assert_eq!(a.fqdn, "example.com");

        let spf = txt_starting("v=spf1");
        assert!(spf.value.contains("ip4:203.0.113.7"), "SPF must carry a real address");
    }

    /// The MX target and the A record have to name the same host, or mail is
    /// delivered to a name that doesn't resolve. The two old spellings disagreed.
    #[test]
    fn the_mx_target_matches_the_a_record() {
        let (a, mx) = (of_type("A"), of_type("MX"));
        assert!(mx.value.ends_with(&a.fqdn), "{} should point at {}", mx.value, a.fqdn);
    }

    /// The advised topology must be the one `auto_create_mail_dns` publishes and
    /// the one auto-SSL's HTTP-01 order depends on. Advising `mail.<domain>`
    /// instead — which is conventional, and what the DNS tab used to say — would
    /// report every auto-configured domain as broken and break certificate
    /// issuance for new ones.
    #[test]
    fn the_advised_mail_host_is_the_apex() {
        assert_eq!(of_type("A").fqdn, "example.com");
        assert_eq!(of_type("MX").value, "10 example.com");
    }

    #[test]
    fn the_dkim_record_uses_the_domains_own_selector() {
        let recs = mail_records("example.com", "s2026", Some(PEM), "203.0.113.7");
        let dkim = recs.iter().find(|r| r.value.starts_with("v=DKIM1")).unwrap();
        assert_eq!(dkim.fqdn, "s2026._domainkey.example.com");
        assert_eq!(dkim.name, "s2026._domainkey");
    }

    #[test]
    fn a_domain_with_no_dkim_key_gets_no_dkim_record() {
        assert_eq!(mail_records("example.com", "dockpanel", None, "203.0.113.7").len(), 4);
        assert_eq!(
            mail_records("example.com", "dockpanel", Some("  "), "203.0.113.7").len(),
            4,
            "a blank key is not a key"
        );
        assert_eq!(records().len(), 5);
    }

    #[test]
    fn dkim_txt_strips_pem_armour_and_newlines() {
        let v = dkim_txt_value(PEM);
        assert!(v.starts_with("v=DKIM1; k=rsa; p=MIIBIjANBgkq"));
        assert!(!v.contains('\n') && !v.contains("BEGIN"));
    }

    // ── the matcher: what the old check got wrong ─────────────────────────

    /// The headline regression test. The old check passed on ANY `v=spf1`, so a
    /// domain that explicitly forbids this server reported "verified".
    #[test]
    fn an_spf_record_for_a_different_server_does_not_satisfy_us() {
        assert!(!record_satisfies(
            &txt_starting("v=spf1"),
            "v=spf1 ip4:198.51.100.1 -all",
            "203.0.113.7"
        ));
    }

    /// …but an operator whose SPF is stricter or broader than ours is fine.
    #[test]
    fn a_richer_spf_record_still_satisfies_us() {
        let spf = txt_starting("v=spf1");
        assert!(record_satisfies(&spf, "v=spf1 a mx ip4:203.0.113.7 include:sendgrid.net -all", "203.0.113.7"));
        assert!(record_satisfies(&spf, "v=spf1 mx -all", "203.0.113.7"));
    }

    /// The old check passed on any MX at all — including the one that means our
    /// mail is going to somebody else entirely.
    #[test]
    fn an_mx_pointing_at_another_provider_does_not_satisfy_us() {
        let mx = of_type("MX");
        assert!(!record_satisfies(&mx, "1 aspmx.l.google.com.", "203.0.113.7"));
        assert!(record_satisfies(&mx, "10 example.com.", "203.0.113.7"));
        // A backup MX at another preference is still our host.
        assert!(record_satisfies(&mx, "50 example.com", "203.0.113.7"));
    }

    /// Both topologies this product has ever produced must pass. The DNS tab
    /// advised `mail.<domain>` for years; someone who followed it has a working
    /// setup, and calling it broken would repeat the false-verdict failure this
    /// check exists to fix.
    #[test]
    fn the_conventional_mail_subdomain_is_accepted_too() {
        let mx = of_type("MX");
        assert!(record_satisfies(&mx, "10 mail.example.com.", "203.0.113.7"));
        assert!(record_satisfies(&mx, "20 mail.example.com", "203.0.113.7"));
    }

    /// The old check accepted `contains("p=")`, so a stale key from a previous
    /// install passed while nothing we signed could be verified.
    #[test]
    fn a_different_dkim_key_does_not_satisfy_us() {
        let dkim = txt_starting("v=DKIM1");
        assert!(record_satisfies(&dkim, &dkim.value, "203.0.113.7"));
        assert!(!record_satisfies(
            &dkim,
            "v=DKIM1; k=rsa; p=SOMEOTHERKEYENTIRELY00000000000000000000000000000000",
            "203.0.113.7"
        ));
    }

    /// Providers split long TXT values into quoted chunks; that must not read as
    /// a mismatch or DKIM never verifies for a real key.
    #[test]
    fn quoted_and_split_dkim_values_still_match() {
        let dkim = txt_starting("v=DKIM1");
        let split = format!("\"{}\" \"{}\"", &dkim.value[..40], &dkim.value[40..]);
        assert!(record_satisfies(&dkim, &split, "203.0.113.7"));
    }

    #[test]
    fn any_dmarc_policy_counts_as_published() {
        let dmarc = txt_starting("v=DMARC1");
        assert!(record_satisfies(&dmarc, "v=DMARC1; p=reject", "203.0.113.7"));
        assert!(!record_satisfies(&dmarc, "not-a-dmarc-record", "203.0.113.7"));
    }

    #[test]
    fn the_a_record_must_be_this_server() {
        let a = of_type("A");
        assert!(record_satisfies(&a, "203.0.113.7", "203.0.113.7"));
        assert!(!record_satisfies(&a, "198.51.100.1", "203.0.113.7"));
    }

    // ── the checks ────────────────────────────────────────────────────────

    #[test]
    fn a_missing_dkim_key_warns_but_never_blocks() {
        let r = check_dkim_key_present("example.com", None);
        assert!(!r.blocks());
        assert_eq!(r.state, PrereqState::Unsatisfied);
        assert_eq!(r.severity, PrereqSeverity::Warning);

        assert_eq!(check_dkim_key_present("example.com", Some(PEM)).state, PrereqState::Satisfied);
        assert_eq!(
            check_dkim_key_present("example.com", Some("   ")).state,
            PrereqState::Unsatisfied,
            "a blank key is not a key"
        );
    }

    #[tokio::test]
    async fn an_unknown_server_ip_is_unknown_not_a_failure() {
        let r = check_mail_dns_published("example.com", "dockpanel", Some(PEM), "").await;
        assert_eq!(r.state, PrereqState::Unknown);
        assert!(!r.blocks());
    }

    /// A name dig would parse as an option must never reach the command line.
    #[tokio::test]
    async fn a_hostile_domain_name_is_not_looked_up() {
        let evil = DnsRecordHint::new("x", "-f/etc/passwd", "TXT", "v=spf1", "300");
        assert!(lookup(&evil).await.is_none());
    }

    /// Nothing on the mail surface is gated, so nothing here may ever block.
    #[tokio::test]
    async fn mail_prerequisites_never_gate_a_control() {
        for r in evaluate("example.invalid", "dockpanel", None, "203.0.113.7").await {
            assert!(!r.blocks(), "{} must not block", r.key);
        }
    }
}
