//! What a ticket's cipher holds once the node's key opens it.
//!
//! The ticket as it arrives — the `Negotiate` wrappings, the AP-REQ, the
//! service, the realm, the encryption type, the key version and the cipher —
//! is read by the identify capability's `identify::kerberos::Ticket`, the
//! one reader the first gate reads the same token with (ADR-0044). What only
//! this gate reads is the cipher's plaintext, an `EncTicketPart` (RFC 4120
//! section 5.3): the client principal the ticket names and the window it is
//! valid for. Its fields are read with the same capability's `required` and
//! `principal`, on the estate's one X.690 reader.

use asn1::{Element, SEQUENCE, application};
use authenticate::AuthenticateError;
use identify::kerberos::{principal, required, written};

/// The application tag of an `EncTicketPart`.
const ENC_TICKET_PART: u8 = 3;

/// What the ticket's cipher held once the node's key opened it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncTicketPart {
    /// The realm the client belongs to.
    pub client_realm: String,
    /// The client principal's components.
    pub client: Vec<String>,
    /// When the ticket becomes valid: `starttime`, or `authtime` where there
    /// is no `starttime`, in seconds since the Unix epoch.
    pub start: i64,
    /// When the ticket stops being valid, in seconds since the Unix epoch.
    pub end: i64,
}

impl EncTicketPart {
    /// The client principal as Kerberos writes one: `alice@REALM`.
    #[must_use]
    pub fn client_principal(&self) -> String {
        written(&self.client, &self.client_realm)
    }

    /// Read a decrypted `EncTicketPart`.
    ///
    /// # Errors
    ///
    /// Where the bytes are not an `EncTicketPart`, or it lacks a client
    /// realm, a client name, an `authtime` or an `endtime`.
    pub fn parse(plaintext: &[u8]) -> Result<Self, AuthenticateError> {
        let part = Element::expect(plaintext, application(ENC_TICKET_PART), "an EncTicketPart")?;
        let part = Element::expect(part.content, SEQUENCE, "an EncTicketPart")?;

        let client_realm = required(&part, 2, "client realm")?
            .text()
            .ok_or_else(|| AuthenticateError::new("the ticket's client realm is not readable"))?
            .to_string();
        let client = principal(required(&part, 3, "client name")?)?;
        let authtime = required(&part, 5, "authtime")?
            .time()
            .ok_or_else(|| AuthenticateError::new("the ticket's authtime is not a KerberosTime"))?;
        let start = part
            .field(6)?
            .and_then(|starttime| starttime.time())
            .unwrap_or(authtime);
        let end = required(&part, 7, "endtime")?
            .time()
            .ok_or_else(|| AuthenticateError::new("the ticket's endtime is not a KerberosTime"))?;

        Ok(Self {
            client_realm,
            client,
            start,
            end,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::crypto::{self, TICKET_KEY_USAGE};
    use asn1::{GENERAL_STRING, GENERALIZED_TIME, tlv};
    use identify::kerberos::fixture::{self, field};

    /// `YYYYMMDDHHMMSSZ` for a Unix time; the tests use whole minutes.
    fn kerberos_time(seconds: i64) -> Vec<u8> {
        // 2027-01-15T08:00:00Z is 1_800_000_000; the tests offset from there.
        let table = [
            (1_800_000_000i64, "20270115080000Z"),
            (1_800_000_000 - 3_600, "20270115070000Z"),
            (1_800_000_000 + 3_600, "20270115090000Z"),
            (1_800_000_000 - 86_400, "20270114080000Z"),
            (1_800_000_000 + 86_400, "20270116080000Z"),
        ];
        let text = table
            .iter()
            .find(|(at, _)| *at == seconds)
            .map(|(_, text)| *text)
            .expect("a tabulated time");
        tlv(GENERALIZED_TIME, text.as_bytes())
    }

    /// A sealed `EncTicketPart` for a client valid over `[start, end]`.
    pub(crate) fn enc_ticket_part(realm: &str, client: &[&str], start: i64, end: i64) -> Vec<u8> {
        let mut fields = field(0, &tlv(0x03, &[0, 0, 0, 0, 0])); // flags, BIT STRING
        fields.extend(field(1, &tlv(SEQUENCE, &[]))); // key, elided shape
        fields.extend(field(2, &tlv(GENERAL_STRING, realm.as_bytes())));
        fields.extend(field(3, &fixture::principal_name(client)));
        fields.extend(field(4, &tlv(SEQUENCE, &[]))); // transited
        fields.extend(field(5, &kerberos_time(start))); // authtime
        fields.extend(field(7, &kerberos_time(end))); // endtime
        tlv(application(ENC_TICKET_PART), &tlv(SEQUENCE, &fields))
    }

    /// A bare AP-REQ whose ticket is for `service@realm`, sealed under `key`.
    pub(crate) fn ap_req(service: &[&str], realm: &str, key: &[u8], sealed: &[u8]) -> Vec<u8> {
        let cipher = crypto::tests::encrypt(key, TICKET_KEY_USAGE, [5u8; 16], sealed);
        fixture::ap_req(service, realm, &cipher)
    }

    #[test]
    fn a_decrypted_enc_ticket_part_reads_the_client_and_the_window() {
        let sealed = enc_ticket_part(
            "EXAMPLE.COM",
            &["alice"],
            1_800_000_000 - 3_600,
            1_800_000_000 + 3_600,
        );

        let part = EncTicketPart::parse(&sealed).expect("read");

        assert_eq!(part.client_principal(), "alice@EXAMPLE.COM");
        assert_eq!(part.start, 1_800_000_000 - 3_600);
        assert_eq!(part.end, 1_800_000_000 + 3_600);
    }

    #[test]
    fn a_part_missing_its_client_name_is_refused_naming_it() {
        let part = tlv(
            application(ENC_TICKET_PART),
            &tlv(SEQUENCE, &field(2, &tlv(GENERAL_STRING, b"EXAMPLE.COM"))),
        );

        let failure = EncTicketPart::parse(&part).expect_err("refused");

        assert!(failure.message.contains("has no client name"), "{failure}");
    }
}
