#![forbid(unsafe_code)]

//! Authenticate by kerberos: verifies a service ticket with the node's
//! keytab.
//!
//! The first gate unwrapped the `Negotiate` token and presented the service
//! the ticket is for — the client principal is sealed and unreadable there —
//! with the whole AP-REQ riding as the `kerberos.ap-req` proof. This gate
//! holds the node's keytab: the service keys, by principal and key version.
//! It reads the ticket, finds the key for that service principal and version,
//! decrypts the ticket's sealed part (`aes256-cts-hmac-sha1-96`, RFC 3962 —
//! see [`crypto`]), and, where the checksum holds, reads the client
//! principal and the ticket's validity window out of it. It refuses where the
//! service principal is not the claim, where no held key opens the ticket, or
//! where the ticket is outside its window with the configured leeway.
//!
//! **A gap for the owner, not worked around here.** `Authenticator::verify`
//! answers only a [`Verified`], so this gate cannot hand back the one thing
//! it learned that the first gate could not read — the client principal. It
//! is exposed instead through [`Verifier::client_of`], and the capability has
//! no way yet to replace a claim's value (the service) with the verified
//! value (the client). Until it does, the record shows the service the ticket
//! was for, which is true, and a Party resolves from the service, not the
//! client. This is ADR-0050's to settle, said here and in the report.
//!
//! Offline throughout (ADR-0045): the keytab is configuration, and no KDC is
//! reached. Only `aes256-cts-hmac-sha1-96` is decrypted; `rc4-hmac`,
//! `aes128` and the rest are refused by name where a ticket names them. The
//! authenticator inside the AP-REQ is sealed under the ticket's session key,
//! which the node does not hold, so it is not opened: this gate proves the
//! ticket, keeps no replay cache, and does not check the authenticator's
//! clock skew. That the AP-REQ is this connection's is the transport's.

pub mod crypto;
pub mod der;
pub mod ticket;

pub use ticket::{EncTicketPart, Ticket};

use authenticate::{AuthenticateError, Authenticator, Presented};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use context::Verified;
use crypto::{AES256_CTS_HMAC_SHA1_96, TICKET_KEY_USAGE};
use std::time::{SystemTime, UNIX_EPOCH};
use xcore::{Mechanism, mechanism};

/// The proof the identify sibling attaches the base64 AP-REQ under.
pub const AP_REQ_PROOF: &str = "kerberos.ap-req";

type Clock = Box<dyn Fn() -> i64 + Send + Sync>;

/// Seconds since the Unix epoch, now.
#[must_use]
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        })
}

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
        self.principal == principal && (self.version.is_none() || self.version == version)
    }
}

/// The kerberos authenticator: the node's keytab and how far a clock may be
/// off.
pub struct Verifier {
    keytab: Vec<KeyEntry>,
    leeway: i64,
    clock: Clock,
}

impl Verifier {
    /// Verifies against this keytab, with five minutes of leeway on the
    /// ticket's window and the system clock.
    #[must_use]
    pub fn new(keytab: Vec<KeyEntry>) -> Self {
        Self {
            keytab,
            leeway: 300,
            clock: Box::new(now),
        }
    }

    /// How far a clock may be off before the validity window bites.
    #[must_use]
    pub const fn with_leeway(mut self, seconds: i64) -> Self {
        self.leeway = seconds;
        self
    }

    /// Where the time comes from; the tests pin it.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// The AP-REQ its base64 proof carries.
    fn ticket_of(presented: &Presented) -> Result<Ticket, AuthenticateError> {
        let name = presented.mechanism.name();
        if name != mechanism::kerberos().name() {
            return Err(AuthenticateError::new(format!(
                "'{name}' was presented and this authenticator verifies kerberos"
            )));
        }
        let encoded = presented.proof(AP_REQ_PROOF).ok_or_else(|| {
            AuthenticateError::new(format!("no {AP_REQ_PROOF} proof was presented"))
        })?;
        let bytes = STANDARD
            .decode(encoded.trim())
            .map_err(|_| AuthenticateError::new("the AP-REQ is not base64"))?;
        Ticket::from_negotiate(&bytes)?
            .ok_or_else(|| AuthenticateError::new("the Negotiate token carries no Kerberos ticket"))
    }

    /// Open the ticket and read what it seals, having checked the service
    /// principal against the claim.
    fn open(&self, presented: &Presented) -> Result<EncTicketPart, AuthenticateError> {
        let ticket = Self::ticket_of(presented)?;
        if ticket.service_principal() != presented.value {
            return Err(AuthenticateError::new(format!(
                "the ticket is for '{}' and the claim is '{}'",
                ticket.service_principal(),
                presented.value
            )));
        }
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

    /// The client principal a proven ticket names — the verified identity the
    /// gate cannot yet return through [`Authenticator::verify`].
    ///
    /// # Errors
    ///
    /// As [`Authenticator::verify`]: everything that would refuse the ticket
    /// refuses here too.
    pub fn client_of(&self, presented: &Presented) -> Result<String, AuthenticateError> {
        let part = self.open(presented)?;
        self.within_window(&part)?;
        Ok(part.client_principal())
    }

    fn within_window(&self, part: &EncTicketPart) -> Result<(), AuthenticateError> {
        let now = (self.clock)();
        if now.saturating_add(self.leeway) < part.start {
            return Err(AuthenticateError::new(format!(
                "the ticket is not valid before {} and it is {now}",
                part.start
            )));
        }
        if now.saturating_sub(self.leeway) > part.end {
            return Err(AuthenticateError::new(format!(
                "the ticket expired at {} and it is {now}",
                part.end
            )));
        }
        Ok(())
    }
}

impl Authenticator for Verifier {
    fn mechanism(&self) -> Mechanism {
        mechanism::kerberos()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        let part = self.open(presented)?;
        self.within_window(&part)?;
        Ok(Verified::Proven)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ticket::tests::{ap_req, enc_ticket_part};

    const NOW: i64 = 1_800_000_000;
    const KEY: [u8; 32] = [7u8; 32];
    const SERVICE: &[&str] = &["HTTP", "xmip.example"];
    const REALM: &str = "EXAMPLE.COM";
    const PRINCIPAL: &str = "HTTP/xmip.example@EXAMPLE.COM";

    fn token(service: &[&str], realm: &str, key: &[u8], sealed: &[u8]) -> String {
        STANDARD.encode(ap_req(service, realm, key, sealed))
    }

    fn sealed_for(client: &[&str], start: i64, end: i64) -> Vec<u8> {
        enc_ticket_part(REALM, client, start, end)
    }

    fn verifier() -> Verifier {
        Verifier::new(vec![KeyEntry::new(PRINCIPAL, Some(3), KEY.to_vec())]).with_clock(|| NOW)
    }

    fn presented(token: &str) -> Presented {
        Presented::passed(mechanism::kerberos(), PRINCIPAL).with_proof(AP_REQ_PROOF, token)
    }

    #[test]
    fn a_ticket_sealed_under_the_service_key_is_proven_and_yields_the_client() {
        let sealed = sealed_for(&["alice"], NOW - 3_600, NOW + 3_600);
        let claim = presented(&token(SERVICE, REALM, &KEY, &sealed));

        let verified = verifier().verify(&claim).expect("proven");
        let client = verifier().client_of(&claim).expect("a client");

        assert_eq!(verified, Verified::Proven);
        assert_eq!(client, "alice@EXAMPLE.COM");
    }

    #[test]
    fn a_ticket_sealed_under_another_key_fails_its_checksum() {
        let sealed = sealed_for(&["alice"], NOW - 3_600, NOW + 3_600);
        let claim = presented(&token(SERVICE, REALM, &[1u8; 32], &sealed));

        let failure = verifier().verify(&claim).expect_err("refused");

        assert!(failure.message.contains("checksum does not match"));
    }

    #[test]
    fn a_ticket_the_node_holds_no_key_for_is_refused_by_the_principal() {
        let sealed = sealed_for(&["alice"], NOW - 3_600, NOW + 3_600);
        let other = ["HTTP", "other.example"];
        let claim = Presented::passed(mechanism::kerberos(), "HTTP/other.example@EXAMPLE.COM")
            .with_proof(AP_REQ_PROOF, token(&other, REALM, &KEY, &sealed));

        let failure = verifier().verify(&claim).expect_err("refused");

        assert!(
            failure
                .message
                .contains("holds no key for 'HTTP/other.example@EXAMPLE.COM'")
        );
    }

    #[test]
    fn an_expired_ticket_is_refused_by_its_window() {
        let sealed = sealed_for(&["alice"], NOW - 86_400, NOW - 3_600);
        let claim = presented(&token(SERVICE, REALM, &KEY, &sealed));

        let failure = verifier().verify(&claim).expect_err("refused");

        assert!(failure.message.contains("expired at"));
    }

    #[test]
    fn a_ticket_not_yet_valid_is_refused_by_its_window() {
        let sealed = sealed_for(&["alice"], NOW + 3_600, NOW + 86_400);
        let claim = presented(&token(SERVICE, REALM, &KEY, &sealed));

        let failure = verifier().verify(&claim).expect_err("refused");

        assert!(failure.message.contains("not valid before"));
    }

    #[test]
    fn a_ticket_whose_service_is_not_the_claim_is_refused() {
        let sealed = sealed_for(&["alice"], NOW - 3_600, NOW + 3_600);
        let claim = Presented::passed(mechanism::kerberos(), "HTTP/wrong.example@EXAMPLE.COM")
            .with_proof(AP_REQ_PROOF, token(SERVICE, REALM, &KEY, &sealed));

        let failure = verifier().verify(&claim).expect_err("refused");

        assert!(failure.message.contains("the claim is"));
    }

    #[test]
    fn a_password_derived_keytab_opens_a_ticket_sealed_under_the_same_key() {
        let entry =
            KeyEntry::from_password(PRINCIPAL, Some(3), b"s3cret", b"EXAMPLE.COMHTTP", 4096)
                .expect("a key");
        let base_key = crypto::string_to_key(b"s3cret", b"EXAMPLE.COMHTTP", 4096).expect("a key");
        let sealed = sealed_for(&["bob"], NOW - 3_600, NOW + 3_600);
        let claim = presented(&token(SERVICE, REALM, &base_key, &sealed));
        let gate = Verifier::new(vec![entry]).with_clock(|| NOW);

        assert_eq!(gate.verify(&claim).expect("proven"), Verified::Proven);
        assert_eq!(gate.client_of(&claim).expect("a client"), "bob@EXAMPLE.COM");
    }

    #[test]
    fn another_mechanism_and_a_missing_proof_are_each_refused_by_name() {
        let other = Presented::passed(mechanism::ntlm(), PRINCIPAL);
        let bare = Presented::passed(mechanism::kerberos(), PRINCIPAL);

        assert!(
            verifier()
                .verify(&other)
                .expect_err("refused")
                .message
                .contains("'ntlm' was presented")
        );
        assert!(
            verifier()
                .verify(&bare)
                .expect_err("refused")
                .message
                .contains("kerberos.ap-req")
        );
    }
}
