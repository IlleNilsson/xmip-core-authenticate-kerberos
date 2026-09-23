//! The DER an AP-REQ and its sealed part are, named the way RFC 4120 names
//! them.
//!
//! The reader is the estate's one, `xmip-core-library-asn1`; this carried its own
//! until 2026-09-22, as did `identify/kerberos` for the clear part of the same
//! token. What stays here is Kerberos's: every field of a Kerberos `SEQUENCE`
//! is explicitly tagged and constructed, a missing one is named in the
//! message's words, and a `PrincipalName` is its components joined by `/`.

pub use asn1::{
    Element, GENERAL_STRING, GENERALIZED_TIME, INTEGER, OBJECT_IDENTIFIER as OID, OCTET_STRING,
    SEQUENCE, application,
};
use authenticate::AuthenticateError;

/// The tag of `[n]`, context-specific and constructed.
#[must_use]
pub const fn context(number: u8) -> u8 {
    asn1::context(number, true)
}

/// A field a Kerberos message must carry.
pub trait Required<'a> {
    /// `[number]`, required: the error says `what` is missing.
    ///
    /// # Errors
    ///
    /// As [`Element::field`], and where the field is absent.
    fn required(&self, number: u8, what: &str) -> Result<Element<'a>, AuthenticateError>;
}

impl<'a> Required<'a> for Element<'a> {
    fn required(&self, number: u8, what: &str) -> Result<Element<'a>, AuthenticateError> {
        self.field(number)?
            .ok_or_else(|| AuthenticateError::new(format!("the Kerberos message has no {what}")))
    }
}

/// A `PrincipalName` — `SEQUENCE { name-type [0], name-string [1] SEQUENCE
/// OF GeneralString }` — as Kerberos writes one: components joined by `/`.
///
/// # Errors
///
/// Where the name has no readable component.
pub fn principal(name: Element<'_>) -> Result<String, AuthenticateError> {
    let unreadable = || AuthenticateError::new("a principal name in the ticket is not readable");
    let components = name
        .field(1)?
        .ok_or_else(unreadable)?
        .children()?
        .iter()
        .map(Element::text)
        .collect::<Option<Vec<_>>>()
        .filter(|components| !components.is_empty())
        .ok_or_else(unreadable)?;
    Ok(components.join("/"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) use asn1::tlv;

    /// `[number]` around `inner`.
    pub(crate) fn field(number: u8, inner: &[u8]) -> Vec<u8> {
        tlv(context(number), inner)
    }

    /// A `PrincipalName` of these components.
    pub(crate) fn name(components: &[&str]) -> Vec<u8> {
        let strings: Vec<u8> = components
            .iter()
            .flat_map(|component| tlv(GENERAL_STRING, component.as_bytes()))
            .collect();
        let mut fields = field(0, &tlv(INTEGER, &[1]));
        fields.extend(field(1, &tlv(SEQUENCE, &strings)));
        tlv(SEQUENCE, &fields)
    }

    #[test]
    fn a_principal_name_is_its_components_joined_by_a_slash() {
        let encoded = name(&["HTTP", "xmip.example"]);
        let (element, _) = Element::read(&encoded).expect("read");

        assert_eq!(principal(element).expect("a name"), "HTTP/xmip.example");
    }

    #[test]
    fn a_missing_required_field_is_named() {
        let sequence = tlv(SEQUENCE, &field(0, &tlv(INTEGER, &[5])));
        let (element, _) = Element::read(&sequence).expect("read");

        let failure = element.required(3, "ticket").expect_err("missing");

        assert_eq!(
            element.required(0, "number").expect("there").integer(),
            Some(5)
        );
        assert!(failure.message.contains("no ticket"));
    }
}
