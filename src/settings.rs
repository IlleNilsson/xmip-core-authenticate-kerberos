//! What a Receive Location configures the kerberos authenticator with,
//! declared once (ADR-0064, amendment 2026-09-26) and read through that
//! declaration.
//!
//! RFC 4120 section 3.2.3 leaves two numbers to the server: how far a
//! client's clock may be off its own, and how many authenticators it keeps
//! to refuse a replay. Both are here, with their defaults, so neither is a
//! constant buried in the verifier. The keytab is the node's secret and is
//! handed to [`Verifier::configured`] apart from these.

use core::time::Duration;

use authenticate::AuthenticateError;
use authenticate::clock::Clock;
use authenticate::replay::Replay;
use xcore::settings::{Applies, Fixed, Given, Kind, Presence, Setting, Settings};

use crate::{KeyEntry, Verifier};

/// How far a client's clock may be off the node's, five minutes as RFC 4120
/// section 1.6 suggests.
pub const CLOCK_SKEW: Duration = Duration::from_secs(300);

/// How many authenticators the node keeps within their skew before it
/// refuses the next rather than forget one.
pub const REPLAY_CAPACITY: i64 = 65_536;

/// The kerberos authenticator's settings.
pub const SETTINGS: &Settings = &Settings {
    technology: "xmip-core-authenticate-kerberos",
    settings: &[
        Setting {
            name: "clock_skew",
            kind: Kind::Duration,
            presence: Presence::Default(Fixed::Duration(CLOCK_SKEW)),
            meaning: "How far a client's clock may be off the node's: an authenticator made \
                      further from now is refused, and one within it is kept that long.",
            applies: Applies::Receive,
        },
        Setting {
            name: "replay_capacity",
            kind: Kind::Integer {
                minimum: 1,
                maximum: 16_777_216,
            },
            presence: Presence::Default(Fixed::Integer(REPLAY_CAPACITY)),
            meaning: "How many authenticators within the clock skew the node keeps to refuse \
                      their replay; when it is full of live ones the next is refused.",
            applies: Applies::Receive,
        },
    ],
};

/// Whole seconds, as the capability's clock counts them.
fn seconds(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

impl Verifier {
    /// Verifies against this keytab with the defaults [`SETTINGS`] declares
    /// and the system clock.
    #[must_use]
    pub fn new(keytab: Vec<KeyEntry>) -> Self {
        Self {
            keytab,
            clock: Clock::system(seconds(CLOCK_SKEW)),
            spent: Replay::holding(usize::try_from(REPLAY_CAPACITY).unwrap_or(usize::MAX)),
        }
    }

    /// Verifies against this keytab with what a Receive Location `given`,
    /// read through [`SETTINGS`].
    ///
    /// # Errors
    ///
    /// Where the settings are refused: a setting the declaration does not
    /// have, or one of another kind or out of its range, each named.
    pub fn configured(
        keytab: Vec<KeyEntry>,
        given: &[(String, Given)],
    ) -> Result<Self, AuthenticateError> {
        let read = SETTINGS
            .read(Applies::Receive, given)
            .map_err(|refused| AuthenticateError::new(refused.to_string()))?;
        let capacity = usize::try_from(read.integer("replay_capacity")).unwrap_or(usize::MAX);
        Ok(Self {
            keytab,
            clock: Clock::system(seconds(read.duration("clock_skew"))),
            spent: Replay::holding(capacity),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_declaration_is_sound_and_its_defaults_are_the_verifiers() {
        assert_eq!(SETTINGS.problems(), Vec::<String>::new());
        let read = SETTINGS.read(Applies::Receive, &[]).expect("the defaults");

        assert_eq!(read.duration("clock_skew"), CLOCK_SKEW);
        assert_eq!(read.integer("replay_capacity"), REPLAY_CAPACITY);
    }

    #[test]
    fn a_setting_out_of_its_range_or_of_another_kind_is_refused_naming_it() {
        let given = [
            ("replay_capacity".to_string(), Given::Integer(0)),
            ("clock_skew".to_string(), Given::Integer(300)),
        ];

        let Err(refused) = Verifier::configured(Vec::new(), &given) else {
            panic!("refused");
        };

        assert!(refused.message.contains("\"replay_capacity\""), "{refused}");
        assert!(refused.message.contains("\"clock_skew\""), "{refused}");
    }
}
