//! As much DER as an AP-REQ and what is sealed inside it need, and no more.
//!
//! X.690: every element is a tag octet, a length and that many content
//! octets. Kerberos and SPNEGO use only low tag numbers, so the tag is one
//! octet here and the high-tag-number form is refused; the length is the
//! short form or a long form of up to four octets. Nothing is copied: an
//! [`Element`] borrows its content from the bytes it was read out of.
//! `identify/kerberos` reads the clear part of the same token with the same
//! subset; neither technology may depend on the other (ADR-0050 section 6).

use authenticate::AuthenticateError;

/// `SEQUENCE`, constructed.
pub const SEQUENCE: u8 = 0x30;
/// `INTEGER`.
pub const INTEGER: u8 = 0x02;
/// `OCTET STRING`.
pub const OCTET_STRING: u8 = 0x04;
/// `OBJECT IDENTIFIER`.
pub const OID: u8 = 0x06;
/// `GeneralizedTime`, which RFC 4120 uses for every time.
pub const GENERALIZED_TIME: u8 = 0x18;
/// `GeneralString`, which RFC 4120 uses for every name.
pub const GENERAL_STRING: u8 = 0x1b;

/// The tag of `[APPLICATION n]`, constructed.
#[must_use]
pub const fn application(number: u8) -> u8 {
    0x60 | number
}

/// The tag of `[n]`, context-specific and constructed.
#[must_use]
pub const fn context(number: u8) -> u8 {
    0xa0 | number
}

/// One element: its tag octet and its content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Element<'a> {
    /// The tag octet.
    pub tag: u8,
    /// The content octets.
    pub content: &'a [u8],
}

impl<'a> Element<'a> {
    /// Read the element at the head of `input`, and what follows it.
    ///
    /// # Errors
    ///
    /// Where the input ends inside the element, the tag is in the
    /// high-tag-number form, or the length is indefinite or longer than four
    /// octets.
    pub fn read(input: &'a [u8]) -> Result<(Self, &'a [u8]), AuthenticateError> {
        let truncated = || AuthenticateError::new("the DER ends inside an element");

        let (&tag, rest) = input.split_first().ok_or_else(truncated)?;
        if tag & 0x1f == 0x1f {
            return Err(AuthenticateError::new(
                "the DER holds a high-tag-number element, which no Kerberos message has",
            ));
        }
        let (&first, rest) = rest.split_first().ok_or_else(truncated)?;
        let (length, rest) = if first & 0x80 == 0 {
            (usize::from(first), rest)
        } else {
            let octets = usize::from(first & 0x7f);
            if octets == 0 || octets > 4 {
                return Err(AuthenticateError::new(
                    "the DER holds a length that is indefinite or longer than four octets",
                ));
            }
            let (length, rest) = rest.split_at_checked(octets).ok_or_else(truncated)?;
            let length = length
                .iter()
                .fold(0_usize, |sum, octet| (sum << 8) | usize::from(*octet));
            (length, rest)
        };

        let (content, rest) = rest.split_at_checked(length).ok_or_else(truncated)?;
        Ok((Self { tag, content }, rest))
    }

    /// Read the element at the head of `input` and require its tag.
    ///
    /// # Errors
    ///
    /// As [`Element::read`], and where the tag is another: the error names
    /// `what` was expected.
    pub fn expect(input: &'a [u8], tag: u8, what: &str) -> Result<Self, AuthenticateError> {
        let (element, _) = Self::read(input)?;
        if element.tag == tag {
            Ok(element)
        } else {
            Err(AuthenticateError::new(format!(
                "expected {what} (tag {tag:#04x}) and found tag {:#04x}",
                element.tag
            )))
        }
    }

    /// The elements inside this one, in order.
    ///
    /// # Errors
    ///
    /// As [`Element::read`], for any of them.
    pub fn children(&self) -> Result<Vec<Element<'a>>, AuthenticateError> {
        let mut children = Vec::new();
        let mut rest = self.content;
        while !rest.is_empty() {
            let (child, after) = Self::read(rest)?;
            children.push(child);
            rest = after;
        }
        Ok(children)
    }

    /// What `[number]` wraps among this element's children, where it is
    /// there: the fields of a Kerberos `SEQUENCE` are all explicitly tagged.
    ///
    /// # Errors
    ///
    /// As [`Element::read`].
    pub fn field(&self, number: u8) -> Result<Option<Element<'a>>, AuthenticateError> {
        self.children()?
            .into_iter()
            .find(|child| child.tag == context(number))
            .map(|wrapper| Self::read(wrapper.content).map(|(inner, _)| inner))
            .transpose()
    }

    /// `[number]`, required: the error says `what` is missing.
    ///
    /// # Errors
    ///
    /// As [`Element::field`], and where the field is absent.
    pub fn required(&self, number: u8, what: &str) -> Result<Element<'a>, AuthenticateError> {
        self.field(number)?
            .ok_or_else(|| AuthenticateError::new(format!("the Kerberos message has no {what}")))
    }

    /// The content as a non-negative `INTEGER` that fits 32 bits.
    #[must_use]
    pub fn integer(&self) -> Option<u32> {
        if self.tag != INTEGER || self.content.is_empty() || self.content[0] & 0x80 != 0 {
            return None;
        }
        let digits = match self.content {
            [0, rest @ ..] => rest,
            all => all,
        };
        (digits.len() <= 4).then(|| {
            digits
                .iter()
                .fold(0_u32, |sum, octet| (sum << 8) | u32::from(*octet))
        })
    }

    /// The content as the text of a `GeneralString`.
    #[must_use]
    pub fn text(&self) -> Option<&'a str> {
        (self.tag == GENERAL_STRING)
            .then(|| core::str::from_utf8(self.content).ok())
            .flatten()
    }

    /// The content as a `KerberosTime` — `YYYYMMDDHHMMSSZ`, RFC 4120 section
    /// 5.2.3 — in seconds since the Unix epoch.
    #[must_use]
    pub fn time(&self) -> Option<i64> {
        let text = core::str::from_utf8(self.content).ok()?;
        if self.tag != GENERALIZED_TIME || text.len() != 15 || !text.ends_with('Z') {
            return None;
        }
        let number = |from: usize, to: usize| text.get(from..to)?.parse::<i64>().ok();
        let (year, month, day) = (number(0, 4)?, number(4, 6)?, number(6, 8)?);
        let (hour, minute, second) = (number(8, 10)?, number(10, 12)?, number(12, 14)?);
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
            return None;
        }
        // Days from the civil date, proleptic Gregorian.
        let year = if month <= 2 { year - 1 } else { year };
        let era = year.div_euclid(400);
        let year_of_era = year.rem_euclid(400);
        let shifted = (month + 9) % 12;
        let day_of_year = (153 * shifted + 2) / 5 + day - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        let days = era * 146_097 + day_of_era - 719_468;
        Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
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

    /// Encode one element.
    pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut element = vec![tag];
        if content.len() < 0x80 {
            element.push(u8::try_from(content.len()).expect("short"));
        } else {
            let length = u32::try_from(content.len())
                .expect("a length")
                .to_be_bytes();
            let skip = length.iter().take_while(|octet| **octet == 0).count();
            element.push(0x80 | u8::try_from(4 - skip).expect("at most four"));
            element.extend_from_slice(&length[skip..]);
        }
        element.extend_from_slice(content);
        element
    }

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
    fn a_long_form_length_is_read_and_a_truncated_element_is_refused() {
        let element = tlv(OCTET_STRING, &[7; 300]);

        let (read, rest) = Element::read(&element).expect("read");
        let failure = Element::read(&element[..100]).expect_err("truncated");

        assert_eq!(
            (read.tag, read.content.len(), rest.len()),
            (OCTET_STRING, 300, 0)
        );
        assert!(failure.message.contains("ends inside"));
    }

    #[test]
    fn a_kerberos_time_is_seconds_since_the_epoch() {
        let at = |text: &str| {
            let encoded = tlv(GENERALIZED_TIME, text.as_bytes());
            Element::read(&encoded).expect("read").0.time()
        };

        assert_eq!(at("19700101000000Z"), Some(0));
        assert_eq!(at("20270115080000Z"), Some(1_800_000_000));
        assert_eq!(at("20271315080000Z"), None);
        assert_eq!(at("2027011508Z"), None);
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
            element.field(0).expect("read").and_then(|e| e.integer()),
            Some(5)
        );
        assert!(failure.message.contains("no ticket"));
    }
}
