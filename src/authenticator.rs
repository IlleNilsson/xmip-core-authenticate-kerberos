//! What an AP-REQ's authenticator holds once the ticket's session key
//! opens it.
//!
//! RFC 4120 section 5.5.1:
//!
//! ```text
//! Authenticator ::= [APPLICATION 2] SEQUENCE {
//!     authenticator-vno [0] INTEGER (5),   crealm [1] Realm,
//!     cname [2] PrincipalName,             cksum [3] Checksum OPTIONAL,
//!     cusec [4] Microseconds,              ctime [5] KerberosTime, ... }
//! ```
//!
//! A ticket is a bearer token for as long as it lives: anyone who copied it
//! off the wire may present it. The authenticator is what proves the
//! presenter holds the session key the ticket seals, and when: it is sealed
//! under that key, names the client, and carries the client's clock. The
//! fields are read with the identify capability's Kerberos vocabulary, on
//! the estate's one X.690 reader.

use asn1::{Element, SEQUENCE, application};
use authenticate::AuthenticateError;
use identify::kerberos::{principal, required, string, time, written};

/// The application tag of an `Authenticator`.
const AUTHENTICATOR: u8 = 2;

/// What the authenticator says, once opened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authenticator {
    /// The realm the client says it belongs to.
    pub client_realm: String,
    /// The client principal's components.
    pub client: Vec<String>,
    /// The client's clock when it made this, in seconds since the Unix epoch.
    pub time: i64,
    /// The microseconds of that second, which tell two authenticators of
    /// one second apart.
    pub microseconds: u32,
}

impl Authenticator {
    /// The client principal as Kerberos writes one: `alice@REALM`.
    #[must_use]
    pub fn client_principal(&self) -> String {
        written(&self.client, &self.client_realm)
    }

    /// Read a decrypted `Authenticator`.
    ///
    /// # Errors
    ///
    /// Where the bytes are not an `Authenticator`, or it lacks a client
    /// realm, a client name, `cusec` or `ctime`.
    pub fn parse(plaintext: &[u8]) -> Result<Self, AuthenticateError> {
        let part = Element::expect(plaintext, application(AUTHENTICATOR), "an Authenticator")?;
        let part = Element::expect(part.content, SEQUENCE, "an Authenticator")?;

        let unread = |what: &str| AuthenticateError::new(format!("the authenticator's {what}"));
        let client_realm = string(&required(&part, 1, "client realm")?)
            .ok_or_else(|| unread("client realm is not readable"))?
            .to_string();
        let client = principal(required(&part, 2, "client name")?)?;
        let microseconds = required(&part, 4, "cusec")?
            .integer()
            .ok_or_else(|| unread("cusec is not an integer"))?;
        let time = time(&required(&part, 5, "ctime")?)
            .ok_or_else(|| unread("ctime is not a KerberosTime"))?;

        Ok(Self {
            client_realm,
            client,
            time,
            microseconds,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::enc_ticket_part::tests::kerberos_time;
    use asn1::{GENERAL_STRING, INTEGER, tlv};
    use identify::kerberos::fixture::{self, field};

    /// An `Authenticator` for `client@realm` made at `at`, `micro` into it.
    pub(crate) fn authenticator(realm: &str, client: &[&str], at: i64, micro: u8) -> Vec<u8> {
        let mut fields = field(0, &tlv(INTEGER, &[5]));
        fields.extend(field(1, &tlv(GENERAL_STRING, realm.as_bytes())));
        fields.extend(field(2, &fixture::principal_name(client)));
        fields.extend(field(4, &tlv(INTEGER, &[micro])));
        fields.extend(field(5, &kerberos_time(at)));
        tlv(application(AUTHENTICATOR), &tlv(SEQUENCE, &fields))
    }

    #[test]
    fn an_opened_authenticator_reads_the_client_and_its_clock() {
        let read =
            Authenticator::parse(&authenticator("EXAMPLE.COM", &["alice"], 1_800_000_000, 7))
                .expect("read");

        assert_eq!(read.client_principal(), "alice@EXAMPLE.COM");
        assert_eq!((read.time, read.microseconds), (1_800_000_000, 7));
    }

    #[test]
    fn an_authenticator_missing_its_time_is_refused_naming_it() {
        let mut fields = field(1, &tlv(GENERAL_STRING, b"EXAMPLE.COM"));
        fields.extend(field(2, &fixture::principal_name(&["alice"])));
        fields.extend(field(4, &tlv(INTEGER, &[1])));
        let part = tlv(application(AUTHENTICATOR), &tlv(SEQUENCE, &fields));

        let failure = Authenticator::parse(&part).expect_err("refused");

        assert!(failure.message.contains("has no ctime"), "{failure}");
    }
}
