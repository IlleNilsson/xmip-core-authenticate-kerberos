# xmip-core-authenticate-kerberos

Authenticate by kerberos: verifies an AP-REQ — its service ticket with the node's keytab, its authenticator with the ticket's session key. A technology of
[xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

It decrypts the service ticket of an AP-REQ with the node's
aes256-cts-hmac-sha1-96 key (RFC 3962, key usage 2) and checks the service
principal against the claim and the ticket's validity window. It then
decrypts the authenticator under the session key the ticket seals (key usage
11), requires it to name the ticket's client and to have been made within the
leeway of the node's clock, and spends it in a replay cache, so a copied
AP-REQ is refused when presented again (RFC 4120 section 3.2.3). Two
settings, declared in `settings.rs` through `xcore::settings`, set it:

| Setting | Default | Meaning |
| --- | --- | --- |
| `clock_skew` | `5m` | How far a client's clock may be off the node's; an authenticator made further from now is refused, and one within it is kept that long. |
| `replay_capacity` | `65536` | How many live authenticators the node keeps; when it is full the next is refused rather than one forgotten. |

The keytab is the node's secret and is given apart from them. The client
principal is what the gate records as the identity and resolves the Party by.
Other encryption types and the keytab file format are refused or not read;
the authenticator's checksum and subkey are not read and no AP-REP is made.
The `Negotiate` token — SPNEGO, GSS-API or a bare AP-REQ — is read by the
identify capability's `identify::kerberos::Ticket`, the reader the first gate
uses too; only the decrypted `EncTicketPart` and `Authenticator` are read
here.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
