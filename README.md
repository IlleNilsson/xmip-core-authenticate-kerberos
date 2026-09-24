# xmip-core-authenticate-kerberos

Authenticate by kerberos: verifies a service ticket with the node's keytab. A technology of
[xmip-core-authenticate](https://github.com/IlleNilsson/xmip-core-authenticate).

It decrypts the service ticket of an AP-REQ with the node's
aes256-cts-hmac-sha1-96 key (RFC 3962, key usage 2), and checks the service
principal, the ticket's validity window and that the client principal is the
claim. It does not decrypt the authenticator, so it keeps no replay cache and
proves possession of a ticket and not of its session key; other encryption
types and the keytab file format are refused or not read. The `Negotiate`
token — SPNEGO, GSS-API or a bare AP-REQ — is read by the identify
capability's `identify::kerberos::Ticket`, the reader the first gate uses too;
only the decrypted `EncTicketPart` is read here.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
