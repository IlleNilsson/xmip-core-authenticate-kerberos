#![forbid(unsafe_code)]

//! Authenticate by kerberos: verifies an AP-REQ — its service ticket with
//! the node's keytab, and its authenticator with the ticket's session key.
//!
//! The first gate unwrapped the `Negotiate` token and presented the service
//! the ticket is for — the client principal is sealed and unreadable there —
//! with the whole AP-REQ riding as the `kerberos.ap-req` proof. This gate
//! holds the node's keytab: the service keys, by principal and key version.
//! It reads the ticket, finds the key for that service principal and version,
//! and decrypts the ticket's sealed part (`aes256-cts-hmac-sha1-96`, RFC 3962
//! — see [`crypto`]): where the checksum holds, it reads the client
//! principal, the ticket's validity window and the session key out of it.
//! It then does what RFC 4120 section 3.2.3 has a server do: it decrypts the
//! authenticator under that session key (key usage 11, see
//! [`mod@authenticator`]), requires the client it names to be the ticket's
//! client, requires its `ctime` to be within the leeway of the node's clock,
//! and spends it in a replay cache, so an AP-REQ copied off the wire and
//! presented again is refused. It refuses where the service principal is not
//! the claim, where no held key opens the ticket, or where the ticket is
//! outside its window with the configured leeway. The leeway is the
//! `clock_skew` setting and the replay cache's bound the `replay_capacity`
//! setting, both declared in [`settings`] with their defaults: an
//! authenticator is kept until its skew has passed, and a cache full of live
//! ones refuses the next rather than forget one. The token is read by the
//! identify capability's `identify::kerberos::Ticket`, the reader the first
//! gate reads it with; only the decrypted [`EncTicketPart`] and
//! [`authenticator::Authenticator`] are read here.
//!
//! Offline throughout (ADR-0045): the keytab is configuration, and no KDC is
//! reached. Only `aes256-cts-hmac-sha1-96` is decrypted, for the ticket and
//! the session key alike; `rc4-hmac`, `aes128` and the rest are refused by
//! name. The authenticator's checksum, its subkey and mutual authentication
//! (the AP-REP) are not read or made. That the AP-REQ is this connection's
//! is the transport's.
//!
//! Principal names are the identify capability's (ADR-0054): the ticket's
//! service is compared with the claim, and with a keytab entry, as a
//! `ServicePrincipalName`, so `HTTP/XMIP.example` is the service a ticket
//! for `HTTP/xmip.example@EXAMPLE.COM` names. The client is sealed in the
//! ticket, so it is proven here and not claimed: the gate is answered with a
//! `Conclusion` that proves it — the identity is the client and its Party is
//! resolved by the client, never by the service — and carries it as
//! [`evidence::KERBEROS_CLIENT`], and as `principal.user` in canonical form
//! where it is one user in one realm and not a host or a service.

pub mod authenticator;
pub mod crypto;
pub mod enc_ticket_part;
pub mod settings;

pub use enc_ticket_part::EncTicketPart;
pub use settings::SETTINGS;

use authenticate::clock::{Clock, Window};
use authenticate::replay::Replay;
use authenticate::{AuthenticateError, Authenticator, Conclusion};
use context::Verified;
use crypto::{AES256_CTS_HMAC_SHA1_96, AUTHENTICATOR_KEY_USAGE, TICKET_KEY_USAGE};
use identify::Presented;
use identify::evidence::{self, KERBEROS_AP_REQ};
use identify::kerberos::Ticket;
use identify::{ServicePrincipalName, UserPrincipalName};
use xcore::{Mechanism, mechanism};

/// One service key the node holds: the base key for a service principal at a
/// key version.
#[derive(Clone)]
pub struct KeyEntry {
    principal: String,
    version: Option<u32>,
    base_key: Vec<u8>,
}

impl KeyEntry {
    /// A key for `principal` (`HTTP/xmip.example@EXAMPLE.COM`) at `version`,
    /// as thirty-two raw bytes.
    #[must_use]
    pub fn new(principal: impl Into<String>, version: Option<u32>, base_key: Vec<u8>) -> Self {
        Self {
            principal: principal.into(),
            version,
            base_key,
        }
    }

    /// A key derived from the service's password and salt (RFC 3962), the
    /// way a KDC derives it, for a keytab built from a password.
    ///
    /// # Errors
    ///
    /// Where the derivation cannot produce a key.
    pub fn from_password(
        principal: impl Into<String>,
        version: Option<u32>,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> Result<Self, AuthenticateError> {
        let base_key = crypto::string_to_key(password, salt, iterations)?;
        Ok(Self::new(principal, version, base_key))
    }

    fn opens(&self, principal: &str, version: Option<u32>) -> bool {
        same_service(&self.principal, principal)
            && (self.version.is_none() || self.version == version)
    }
}

/// Whether two texts name the same service: the capability's own question
/// where both are service principal names, and the text itself where either
/// is not.
fn same_service(ours: &str, theirs: &str) -> bool {
    let read = ServicePrincipalName::parse;
    match (read(ours), read(theirs)) {
        (Some(ours), Some(theirs)) => ours.is(&theirs),
        _ => ours == theirs,
    }
}

/// The service the claim names: its `principal.service` evidence and its
/// value must each be the service the ticket is for.
fn claims(presented: &Presented, service: &str) -> Result<(), AuthenticateError> {
    let evidence = presented.evidence(evidence::PRINCIPAL_SERVICE);
    match [Some(presented.value.as_str()), evidence]
        .into_iter()
        .flatten()
        .find(|claimed| !same_service(service, claimed))
    {
        Some(claimed) => Err(AuthenticateError::new(format!(
            "the ticket is for '{service}' and the claim is '{claimed}'"
        ))),
        None => Ok(()),
    }
}

/// The kerberos authenticator: the node's keytab, how far a clock may be
/// off, and the authenticators already spent.
pub struct Verifier {
    keytab: Vec<KeyEntry>,
    clock: Clock,
    spent: Replay,
}

impl Verifier {
    /// How far a clock may be off before the validity window bites.
    #[must_use]
    pub fn with_leeway(mut self, seconds: i64) -> Self {
        self.clock = self.clock.forgiving(seconds);
        self
    }

    /// Where the time comes from; the tests pin it.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = self.clock.reading(clock);
        self
    }

    /// The AP-REQ its base64 proof carries.
    fn ticket_of(presented: &Presented) -> Result<Ticket, AuthenticateError> {
        let encoded = presented.proof(evidence::KERBEROS_AP_REQ).ok_or_else(|| {
            AuthenticateError::new(format!("no {KERBEROS_AP_REQ} proof was presented"))
        })?;
        let bytes = codec::base64::decode(encoded.trim())
            .map_err(|_| AuthenticateError::new("the AP-REQ is not base64"))?;
        Ticket::from_negotiate(&bytes)?
            .ok_or_else(|| AuthenticateError::new("the Negotiate token carries no Kerberos ticket"))
    }

    /// Open the ticket and read what it seals, having checked the service
    /// principal against the claim.
    fn open(
        &self,
        ticket: &Ticket,
        presented: &Presented,
    ) -> Result<EncTicketPart, AuthenticateError> {
        claims(presented, &ticket.service_principal())?;
        if ticket.encryption_type != AES256_CTS_HMAC_SHA1_96 {
            return Err(AuthenticateError::new(format!(
                "the ticket's encryption type is {} and this node decrypts \
                 aes256-cts-hmac-sha1-96 (18) only",
                ticket.encryption_type
            )));
        }
        let key = self
            .keytab
            .iter()
            .find(|entry| entry.opens(&ticket.service_principal(), ticket.key_version))
            .ok_or_else(|| {
                AuthenticateError::new(format!(
                    "the node's keytab holds no key for '{}' at version {:?}",
                    ticket.service_principal(),
                    ticket.key_version
                ))
            })?;
        let plaintext = crypto::decrypt(&key.base_key, TICKET_KEY_USAGE, &ticket.cipher)?;
        EncTicketPart::parse(&plaintext)
    }

    /// RFC 4120 3.2.3: the authenticator opens under the ticket's session
    /// key, names the ticket's client, was made within the leeway of now,
    /// and has not been presented before.
    fn hold_authenticator(
        &self,
        ticket: &Ticket,
        part: &EncTicketPart,
    ) -> Result<(), AuthenticateError> {
        let sealed = &ticket.authenticator;
        if sealed.encryption_type != AES256_CTS_HMAC_SHA1_96
            || part.session_key.key_type != AES256_CTS_HMAC_SHA1_96
        {
            return Err(AuthenticateError::new(format!(
                "the authenticator is sealed as {} under a session key of type {}, and this \
                 node opens aes256-cts-hmac-sha1-96 (18) only",
                sealed.encryption_type, part.session_key.key_type
            )));
        }
        let plaintext = crypto::decrypt(
            &part.session_key.value,
            AUTHENTICATOR_KEY_USAGE,
            &sealed.cipher,
        )
        .map_err(|failure| {
            AuthenticateError::new(format!(
                "the authenticator does not open under the ticket's session key: {}",
                failure.message
            ))
        })?;
        let read = authenticator::Authenticator::parse(&plaintext)?;
        if read.client != part.client || read.client_realm != part.client_realm {
            return Err(AuthenticateError::new(format!(
                "the authenticator names '{}' and the ticket was issued to '{}'",
                read.client_principal(),
                part.client_principal()
            )));
        }
        let (now, leeway) = (self.clock.now(), self.clock.leeway());
        if read.time.abs_diff(now) > leeway.unsigned_abs() {
            return Err(AuthenticateError::new(format!(
                "the authenticator was made at {} and it is {now}: more than the {leeway} \
                 seconds of skew this node allows",
                read.time
            )));
        }
        let key = format!(
            "{}|{}|{}|{}",
            part.client_principal(),
            ticket.service_principal(),
            read.time,
            read.microseconds
        );
        self.spent
            .spend(&key, read.time.saturating_add(leeway), now)
            .map_err(|refused| AuthenticateError::new(format!("the AP-REQ: {refused}")))
    }

    /// RFC 4120 5.3: a ticket is honored from its `starttime` through its
    /// `endtime`, so the window closes the second after.
    fn within_window(&self, part: &EncTicketPart) -> Result<(), AuthenticateError> {
        let window = Window::between(Some(part.start), Some(part.end.saturating_add(1)));
        self.clock
            .admits(window)
            .map_err(|outside| AuthenticateError::new(format!("the ticket {outside}")))
    }
}

impl Authenticator for Verifier {
    fn mechanism(&self) -> Mechanism {
        mechanism::kerberos()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        self.conclude(presented)
            .map(|conclusion| conclusion.verified)
    }

    fn conclude(&self, presented: &Presented) -> Result<Conclusion, AuthenticateError> {
        let ticket = Self::ticket_of(presented)?;
        let part = self.open(&ticket, presented)?;
        self.within_window(&part)?;
        self.hold_authenticator(&ticket, &part)?;
        let client = part.client_principal();
        let conclusion = Conclusion::proven()
            .proving(&client)
            .learning(evidence::KERBEROS_CLIENT, client);

        Ok(match part.client.as_slice() {
            [user] => match UserPrincipalName::of(user, &part.client_realm) {
                Some(name) => conclusion.learning(evidence::PRINCIPAL_USER, name.to_string()),
                None => conclusion,
            },
            _ => conclusion,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticator::tests::authenticator;
    use crate::enc_ticket_part::tests::{ap_req, enc_ticket_part};

    const NOW: i64 = 1_800_000_000;
    const KEY: [u8; 32] = [7u8; 32];
    const SERVICE: &[&str] = &["HTTP", "xmip.example"];
    const REALM: &str = "EXAMPLE.COM";
    const PRINCIPAL: &str = "HTTP/xmip.example@EXAMPLE.COM";

    /// An AP-REQ for `service`, its ticket sealed under `key` for `client`,
    /// its authenticator naming the same client made now.
    fn token(service: &[&str], key: &[u8], client: &[&str], start: i64, end: i64) -> String {
        made(
            service,
            key,
            client,
            start,
            end,
            &authenticator(REALM, client, NOW, 1),
        )
    }

    fn made(
        service: &[&str],
        key: &[u8],
        client: &[&str],
        start: i64,
        end: i64,
        authenticator: &[u8],
    ) -> String {
        let sealed = enc_ticket_part(REALM, client, start, end);
        codec::base64::encode(&ap_req(service, REALM, key, &sealed, authenticator))
    }

    fn alice() -> String {
        token(SERVICE, &KEY, &["alice"], NOW - 3_600, NOW + 3_600)
    }

    fn verifier() -> Verifier {
        Verifier::new(vec![KeyEntry::new(PRINCIPAL, Some(3), KEY.to_vec())]).with_clock(|| NOW)
    }

    fn presented(token: &str) -> Presented {
        Presented::passed(mechanism::kerberos(), PRINCIPAL)
            .with_proof(evidence::KERBEROS_AP_REQ, token)
    }

    #[test]
    fn a_ticket_sealed_under_the_service_key_is_proven_and_proves_the_client() {
        let conclusion = verifier().conclude(&presented(&alice())).expect("proven");

        assert_eq!(conclusion.verified, Verified::Proven);
        assert_eq!(conclusion.proven.as_deref(), Some("alice@EXAMPLE.COM"));
        assert_eq!(
            conclusion.learned(evidence::KERBEROS_CLIENT),
            Some("alice@EXAMPLE.COM")
        );
    }

    #[test]
    fn a_replayed_ap_req_is_refused_the_second_time() {
        // The ticket and the authenticator are genuine; a copy of the whole
        // AP-REQ taken off the wire proves nothing a second time.
        let gate = verifier();
        let claim = presented(&alice());

        assert_eq!(gate.verify(&claim).expect("proven"), Verified::Proven);
        let replay = gate.verify(&claim).expect_err("a replay");

        assert!(replay.message.contains("replay"), "{replay}");
    }

    #[test]
    fn the_same_authenticator_sealed_into_a_second_ap_req_is_a_replay() {
        // RFC 4120 3.2.3: the replay is the client, the server, ctime and
        // cusec seen before, however the AP-REQ around them is sealed.
        let gate = verifier();
        let once = alice();
        let again = made(
            SERVICE,
            &KEY,
            &["alice"],
            NOW - 86_400,
            NOW + 86_400,
            &authenticator(REALM, &["alice"], NOW, 1),
        );
        assert_ne!(once, again);

        gate.verify(&presented(&once)).expect("proven");
        let replay = gate.verify(&presented(&again)).expect_err("a replay");
        let later = made(
            SERVICE,
            &KEY,
            &["alice"],
            NOW - 86_400,
            NOW + 86_400,
            &authenticator(REALM, &["alice"], NOW, 2),
        );

        assert!(replay.message.contains("replay"), "{replay}");
        gate.verify(&presented(&later)).expect("another cusec");
    }

    #[test]
    fn the_configured_skew_and_replay_bound_are_the_ones_held() {
        let skewed = made(
            SERVICE,
            &KEY,
            &["alice"],
            NOW - 3_600,
            NOW + 3_600,
            &authenticator(REALM, &["alice"], NOW - 90, 1),
        );
        let configured = |given: &[(&str, xcore::settings::Given)]| {
            let given: Vec<_> = given
                .iter()
                .map(|(name, value)| ((*name).to_string(), value.clone()))
                .collect();
            Verifier::configured(
                vec![KeyEntry::new(PRINCIPAL, Some(3), KEY.to_vec())],
                &given,
            )
            .expect("configured")
            .with_clock(|| NOW)
        };
        let text = |value: &str| xcore::settings::Given::Text(value.to_string());

        configured(&[])
            .verify(&presented(&skewed))
            .expect("ninety seconds is within the default five minutes");
        let tight = configured(&[("clock_skew", text("1m"))])
            .verify(&presented(&skewed))
            .expect_err("ninety seconds is beyond one minute");
        let small = configured(&[("replay_capacity", xcore::settings::Given::Integer(1))]);
        small.verify(&presented(&alice())).expect("the first");
        let full = small
            .verify(&presented(&skewed))
            .expect_err("the cache holds one live authenticator");

        assert!(tight.message.contains("60 seconds of skew"), "{tight}");
        assert!(full.message.contains("have not expired"), "{full}");
    }

    #[test]
    fn an_authenticator_from_another_client_or_another_hour_is_refused() {
        let other = made(
            SERVICE,
            &KEY,
            &["alice"],
            NOW - 3_600,
            NOW + 3_600,
            &authenticator(REALM, &["mallory"], NOW, 1),
        );
        let stale = made(
            SERVICE,
            &KEY,
            &["alice"],
            NOW - 3_600,
            NOW + 3_600,
            &authenticator(REALM, &["alice"], NOW - 3_600, 1),
        );

        let named = verifier().verify(&presented(&other)).expect_err("another");
        let late = verifier().verify(&presented(&stale)).expect_err("stale");

        assert!(
            named.message.contains("names 'mallory@EXAMPLE.COM'"),
            "{named}"
        );
        assert!(late.message.contains("seconds of skew"), "{late}");
    }

    #[test]
    fn an_authenticator_not_sealed_under_the_session_key_is_refused() {
        // A ticket alone, copied, with an authenticator the copier cannot
        // seal: what proving possession of the session key means.
        let sealed = enc_ticket_part(REALM, &["alice"], NOW - 3_600, NOW + 3_600);
        let cipher = crypto::tests::encrypt(&KEY, TICKET_KEY_USAGE, [5u8; 16], &sealed);
        let forged = crypto::tests::encrypt(
            &[1u8; 32],
            AUTHENTICATOR_KEY_USAGE,
            [6u8; 16],
            &authenticator(REALM, &["alice"], NOW, 1),
        );
        let token = codec::base64::encode(&identify::kerberos::fixture::ap_req_with(
            SERVICE, REALM, &cipher, &forged,
        ));

        let failure = verifier().verify(&presented(&token)).expect_err("forged");

        assert!(failure.message.contains("session key"), "{failure}");
    }

    #[test]
    fn a_ticket_sealed_under_another_key_fails_its_checksum() {
        let claim = presented(&token(
            SERVICE,
            &[1u8; 32],
            &["alice"],
            NOW - 3_600,
            NOW + 3_600,
        ));

        let failure = verifier().verify(&claim).expect_err("refused");

        assert!(failure.message.contains("checksum does not match"));
    }

    #[test]
    fn a_ticket_the_node_holds_no_key_for_is_refused_by_the_principal() {
        let other = ["HTTP", "other.example"];
        let claim = Presented::passed(mechanism::kerberos(), "HTTP/other.example@EXAMPLE.COM")
            .with_proof(
                evidence::KERBEROS_AP_REQ,
                token(&other, &KEY, &["alice"], NOW - 3_600, NOW + 3_600),
            );

        let failure = verifier().verify(&claim).expect_err("refused");

        assert!(
            failure
                .message
                .contains("holds no key for 'HTTP/other.example@EXAMPLE.COM'")
        );
    }

    #[test]
    fn a_ticket_outside_its_window_is_refused_by_it() {
        let expired = token(SERVICE, &KEY, &["alice"], NOW - 86_400, NOW - 3_600);
        let early = token(SERVICE, &KEY, &["alice"], NOW + 3_600, NOW + 86_400);

        let late = verifier()
            .verify(&presented(&expired))
            .expect_err("expired");
        let soon = verifier().verify(&presented(&early)).expect_err("early");

        assert!(late.message.contains("expired at"));
        assert!(soon.message.contains("not valid before"));
    }

    #[test]
    fn a_ticket_whose_service_is_not_the_claim_is_refused() {
        let claim = Presented::passed(mechanism::kerberos(), "HTTP/wrong.example@EXAMPLE.COM")
            .with_proof(evidence::KERBEROS_AP_REQ, alice());

        let failure = verifier().verify(&claim).expect_err("refused");

        assert!(failure.message.contains("the claim is"));
    }

    #[test]
    fn a_service_spelled_another_way_or_without_its_realm_is_the_service_the_ticket_names() {
        let token = token(SERVICE, &KEY, &["Alice"], NOW - 3_600, NOW + 3_600);

        for spelling in ["HTTP/XMIP.Example@example.com", "HTTP/xmip.example"] {
            let claim = Presented::passed(mechanism::kerberos(), spelling)
                .with_evidence(evidence::PRINCIPAL_SERVICE, "HTTP/xmip.example@example.com")
                .with_proof(evidence::KERBEROS_AP_REQ, &token);

            let conclusion = verifier().conclude(&claim).expect("proven");

            assert_eq!(
                conclusion.learned(evidence::PRINCIPAL_USER),
                Some("Alice@example.com"),
                "{spelling}"
            );
            assert!(conclusion.learned(evidence::KERBEROS_CLIENT).is_some());
        }
    }

    #[test]
    fn another_service_is_refused_naming_both_and_a_host_client_is_no_user() {
        let token = token(
            SERVICE,
            &KEY,
            &["host", "pc1.example"],
            NOW - 3_600,
            NOW + 3_600,
        );
        let cased = Presented::passed(mechanism::kerberos(), "http/xmip.example@EXAMPLE.COM")
            .with_proof(evidence::KERBEROS_AP_REQ, &token);
        let filed = presented(&token)
            .with_evidence(evidence::PRINCIPAL_SERVICE, "HTTP/xmip.example@other.com");

        let class = verifier().verify(&cased).expect_err("refused");
        let realm = verifier().verify(&filed).expect_err("refused");
        let host = verifier().conclude(&presented(&token)).expect("proven");

        assert_eq!(
            class.message,
            "the ticket is for 'HTTP/xmip.example@EXAMPLE.COM' and the claim is \
             'http/xmip.example@EXAMPLE.COM'"
        );
        assert!(realm.message.contains("'HTTP/xmip.example@other.com'"));
        assert_eq!(host.learned(evidence::PRINCIPAL_USER), None);
        assert_eq!(host.proven.as_deref(), Some("host/pc1.example@EXAMPLE.COM"));
    }

    #[test]
    fn a_password_derived_keytab_opens_a_ticket_sealed_under_the_same_key() {
        let entry =
            KeyEntry::from_password(PRINCIPAL, Some(3), b"s3cret", b"EXAMPLE.COMHTTP", 4096)
                .expect("a key");
        let base_key = crypto::string_to_key(b"s3cret", b"EXAMPLE.COMHTTP", 4096).expect("a key");
        let claim = presented(&token(
            SERVICE,
            &base_key,
            &["bob"],
            NOW - 3_600,
            NOW + 3_600,
        ));
        let gate = Verifier::new(vec![entry]).with_clock(|| NOW);

        let conclusion = gate.conclude(&claim).expect("proven");

        assert_eq!(conclusion.proven.as_deref(), Some("bob@EXAMPLE.COM"));
    }

    #[test]
    fn a_missing_proof_is_refused_by_name() {
        let bare = Presented::passed(mechanism::kerberos(), PRINCIPAL);

        assert!(
            verifier()
                .verify(&bare)
                .expect_err("refused")
                .message
                .contains("kerberos.ap-req")
        );
    }
}
