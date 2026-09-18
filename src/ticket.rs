//! The AP-REQ's ticket, in the clear and once opened.
//!
//! [`Ticket`] is what an AP-REQ says without a key: whom the ticket is for,
//! the realm that issued it, and the encryption type, key version and cipher
//! of its sealed part (RFC 4120 sections 5.5.1 and 5.3). The `Negotiate`
//! wrappings — GSS-API, SPNEGO, the RFC 4121 token id — are unwrapped to
//! reach it. [`EncTicketPart`] is what the cipher holds once the node's key
//! opens it: the client principal the ticket names and the window it is
//! valid for. The DER is [`der`](crate::der); this technology reads the same
//! token the identify sibling reads and depends on neither it nor its reader
//! (ADR-0050 section 6).

use crate::der::{self, Element, principal};
use authenticate::AuthenticateError;

/// 1.3.6.1.5.5.2, SPNEGO.
const SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
/// 1.2.840.113554.1.2.2, Kerberos 5.
const KERBEROS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
/// 1.2.840.48018.1.2.2, the Kerberos 5 OID older Windows clients send.
const KERBEROS_LEGACY: &[u8] = &[0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02];
/// What an NTLM message starts with; `Negotiate` carries those too.
const NTLMSSP: &[u8] = b"NTLMSSP\0";
/// RFC 4121 section 4.1: the token id of an AP-REQ.
const TOKEN_AP_REQ: [u8; 2] = [0x01, 0x00];
/// The `msg-type` and application tag of an AP-REQ.
const AP_REQ: u8 = 14;
/// The application tag of an `EncTicketPart`.
const ENC_TICKET_PART: u8 = 3;

/// A service ticket as it arrives, sealed part unread.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ticket {
    /// The service principal's components: `HTTP`, `xmip.example`.
    pub service: Vec<String>,
    /// The realm that issued the ticket.
    pub realm: String,
    /// The encryption type of the sealed part; 18 is this gate's.
    pub encryption_type: u32,
    /// The version of the service key the ticket is sealed under, where the
    /// KDC named one.
    pub key_version: Option<u32>,
    /// The sealed `enc-part` cipher, for the node's key to open.
    pub cipher: Vec<u8>,
}

impl Ticket {
    /// The service principal as Kerberos writes one: `HTTP/xmip.example@REALM`.
    #[must_use]
    pub fn service_principal(&self) -> String {
        format!("{}@{}", self.service.join("/"), self.realm)
    }

    /// Read a `Negotiate` token to its AP-REQ ticket.
    ///
    /// `None` where the token is somebody else's — an NTLM message, or a
    /// SPNEGO continuation with no token in it.
    ///
    /// # Errors
    ///
    /// Where the token is not DER, names a mechanism that is neither SPNEGO
    /// nor Kerberos, or its AP-REQ or ticket cannot be read.
    pub fn from_negotiate(token: &[u8]) -> Result<Option<Self>, AuthenticateError> {
        if token.starts_with(NTLMSSP) {
            return Ok(None);
        }
        let (outer, _) = Element::read(token)?;
        match outer.tag {
            tag if tag == der::application(0) => Self::from_gss(outer),
            tag if tag == der::application(AP_REQ) => Self::parse(token).map(Some),
            tag if tag == der::context(1) => {
                let response = Element::expect(outer.content, der::SEQUENCE, "a NegTokenResp")?;
                Self::from_mechanism_token(response.field(2)?)
            }
            tag => Err(AuthenticateError::new(format!(
                "the Negotiate token starts with tag {tag:#04x}, which is neither GSS-API, \
                 SPNEGO nor an AP-REQ"
            ))),
        }
    }

    fn from_gss(outer: Element<'_>) -> Result<Option<Self>, AuthenticateError> {
        let (mechanism, inner) = Element::read(outer.content)?;
        if mechanism.tag != der::OID {
            return Err(AuthenticateError::new(
                "the GSS-API token does not start with a mechanism OID",
            ));
        }
        if mechanism.content == SPNEGO {
            let init = Element::expect(inner, der::context(0), "a NegTokenInit")?;
            let init = Element::expect(init.content, der::SEQUENCE, "a NegTokenInit")?;
            Self::from_mechanism_token(init.field(2)?)
        } else if mechanism.content == KERBEROS || mechanism.content == KERBEROS_LEGACY {
            match inner.split_at_checked(2) {
                Some((id, message)) if id == TOKEN_AP_REQ => Self::parse(message).map(Some),
                _ => Err(AuthenticateError::new(
                    "the Kerberos token is not an AP-REQ: its token id is not 01 00",
                )),
            }
        } else {
            Err(AuthenticateError::new(
                "the GSS-API token names a mechanism that is neither SPNEGO nor Kerberos",
            ))
        }
    }

    fn from_mechanism_token(token: Option<Element<'_>>) -> Result<Option<Self>, AuthenticateError> {
        match token {
            None => Ok(None),
            Some(token) if token.tag == der::OCTET_STRING => Self::from_negotiate(token.content),
            Some(_) => Err(AuthenticateError::new(
                "the SPNEGO mechanism token is not an OCTET STRING",
            )),
        }
    }

    /// Read a bare AP-REQ.
    ///
    /// # Errors
    ///
    /// Where the bytes are not a Kerberos 5 AP-REQ, or its ticket lacks a
    /// realm, a service name or a sealed part.
    pub fn parse(message: &[u8]) -> Result<Self, AuthenticateError> {
        let request = Element::expect(message, der::application(AP_REQ), "an AP-REQ")?;
        let request = Element::expect(request.content, der::SEQUENCE, "an AP-REQ")?;
        let version = request.field(0)?.and_then(|pvno| pvno.integer());
        let kind = request.field(1)?.and_then(|kind| kind.integer());
        if version != Some(5) || kind != Some(u32::from(AP_REQ)) {
            return Err(AuthenticateError::new(
                "the AP-REQ is not Kerberos 5 message type 14",
            ));
        }

        let ticket = request.required(3, "ticket")?;
        if ticket.tag != der::application(1) {
            return Err(AuthenticateError::new(
                "the AP-REQ's ticket is not a Ticket",
            ));
        }
        let ticket = Element::expect(ticket.content, der::SEQUENCE, "a Ticket")?;
        let realm = ticket
            .required(1, "realm in its ticket")?
            .text()
            .filter(|realm| !realm.is_empty())
            .ok_or_else(|| AuthenticateError::new("the ticket's realm is not readable"))?
            .to_string();
        let service_name = principal(ticket.required(2, "service name in its ticket")?)?;
        let service = service_name.split('/').map(str::to_string).collect();

        let sealed = ticket.required(3, "sealed part in its ticket")?;
        Ok(Self {
            service,
            realm,
            encryption_type: sealed
                .required(0, "encryption type on its ticket")?
                .integer()
                .ok_or_else(|| {
                    AuthenticateError::new("the ticket's encryption type is not read")
                })?,
            key_version: sealed.field(1)?.and_then(|kvno| kvno.integer()),
            cipher: sealed.required(2, "cipher in its ticket")?.content.to_vec(),
        })
    }
}

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
        format!("{}@{}", self.client.join("/"), self.client_realm)
    }

    /// Read a decrypted `EncTicketPart`.
    ///
    /// # Errors
    ///
    /// Where the bytes are not an `EncTicketPart`, or it lacks a client
    /// realm, a client name, an `authtime` or an `endtime`.
    pub fn parse(plaintext: &[u8]) -> Result<Self, AuthenticateError> {
        let part = Element::expect(
            plaintext,
            der::application(ENC_TICKET_PART),
            "an EncTicketPart",
        )?;
        let part = Element::expect(part.content, der::SEQUENCE, "an EncTicketPart")?;

        let client_realm = part
            .required(2, "client realm")?
            .text()
            .ok_or_else(|| AuthenticateError::new("the ticket's client realm is not readable"))?
            .to_string();
        let client = principal(part.required(3, "client name")?)?
            .split('/')
            .map(str::to_string)
            .collect();
        let authtime = part
            .required(5, "authtime")?
            .time()
            .ok_or_else(|| AuthenticateError::new("the ticket's authtime is not a KerberosTime"))?;
        let start = part
            .field(6)?
            .and_then(|starttime| starttime.time())
            .unwrap_or(authtime);
        let end = part
            .required(7, "endtime")?
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
    use crate::der::tests::{field, name, tlv};
    use crate::der::{
        GENERAL_STRING, GENERALIZED_TIME, INTEGER, OCTET_STRING, SEQUENCE, application,
    };

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
        fields.extend(field(3, &name(client)));
        fields.extend(field(4, &tlv(SEQUENCE, &[]))); // transited
        fields.extend(field(5, &kerberos_time(start))); // authtime
        fields.extend(field(7, &kerberos_time(end))); // endtime
        tlv(application(ENC_TICKET_PART), &tlv(SEQUENCE, &fields))
    }

    /// A bare AP-REQ whose ticket is for `service@realm`, sealed under `key`.
    pub(crate) fn ap_req(service: &[&str], realm: &str, key: &[u8], sealed: &[u8]) -> Vec<u8> {
        let cipher = crypto::tests::encrypt(key, TICKET_KEY_USAGE, [5u8; 16], sealed);
        let mut enc_part = field(0, &tlv(INTEGER, &[18]));
        enc_part.extend(field(1, &tlv(INTEGER, &[3]))); // kvno
        enc_part.extend(field(2, &tlv(OCTET_STRING, &cipher)));
        let mut ticket = field(0, &tlv(INTEGER, &[5]));
        ticket.extend(field(1, &tlv(GENERAL_STRING, realm.as_bytes())));
        ticket.extend(field(2, &name(service)));
        ticket.extend(field(3, &tlv(SEQUENCE, &enc_part)));
        let ticket = tlv(application(1), &tlv(SEQUENCE, &ticket));
        let mut request = field(0, &tlv(INTEGER, &[5]));
        request.extend(field(1, &tlv(INTEGER, &[14]))); // msg-type
        request.extend(field(2, &tlv(0x03, &[0, 0, 0, 0, 0]))); // ap-options
        request.extend(field(3, &ticket));
        request.extend(field(4, &tlv(SEQUENCE, &[]))); // authenticator, sealed elsewhere
        tlv(application(14), &tlv(SEQUENCE, &request))
    }

    #[test]
    fn a_bare_ap_req_reads_its_service_realm_etype_kvno_and_cipher() {
        let request = ap_req(
            &["HTTP", "xmip.example"],
            "EXAMPLE.COM",
            &[7u8; 32],
            b"sealed",
        );

        let ticket = Ticket::from_negotiate(&request)
            .expect("read")
            .expect("a ticket");

        assert_eq!(ticket.service_principal(), "HTTP/xmip.example@EXAMPLE.COM");
        assert_eq!(ticket.encryption_type, 18);
        assert_eq!(ticket.key_version, Some(3));
        assert!(!ticket.cipher.is_empty());
    }

    #[test]
    fn an_ntlm_message_under_negotiate_is_not_a_kerberos_ticket() {
        let mut token = b"NTLMSSP\0".to_vec();
        token.extend_from_slice(&3u32.to_le_bytes());

        assert_eq!(Ticket::from_negotiate(&token).expect("read"), None);
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
    fn a_token_that_is_neither_gss_nor_an_ap_req_is_refused_by_its_tag() {
        let failure = Ticket::from_negotiate(&tlv(SEQUENCE, &[1, 2, 3])).expect_err("refused");

        assert!(failure.message.contains("neither GSS-API"));
    }
}
