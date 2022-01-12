---
title: QUIC Version 2
abbrev: QUICv2
docname: draft-ietf-quic-v2-latest
category: std
ipr: trust200902
area: "Transport"
workgroup: "QUIC"
venue:
  group: "QUIC"
  type: "Working Group"
  mail: "quic@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/quic/"
  github: "quicwg/quic-v2"
  latest: "https://quicwg.org/quic-v2/draft-ietf-quic-v2.html"

stand_alone: yes
pi: [toc, sortrefs, symrefs, docmapping]

author:
  -
    ins: M. Duke
    name: Martin Duke
    org: Google LLC
    email: martin.h.duke@gmail.com

normative:
  QUIC: RFC9000
  QUIC-TLS: RFC9001

informative:

--- abstract

This document specifies QUIC version 2, which is identical to QUIC version 1
except for some trivial details. Its purpose is to combat various ossification
vectors and exercise the version negotiation framework. It also serves as a
template for the minimum changes in any future version of QUIC.

Note that "version 2" is an informal name for this proposal that indicates it
is the second standards-track QUIC version. The protocol specified here will
receive a version number other than 2 from IANA.

Discussion of this work is encouraged to happen on the QUIC IETF
mailing list [](quic@ietf.org) or on the GitHub repository which
contains the draft:
[](https://github.com/quicwg/quic-v2).

--- middle

# Introduction

QUIC {{QUIC}} has numerous extension points, including the version number
that occupies the second through fifth octets of every long header (see
{{?RFC8999}}). If experimental versions are rare, and QUIC version 1 constitutes
the vast majority of QUIC traffic, there is the potential for middleboxes to
ossify on the version octets always being 0x00000001.

Furthermore, version 1 Initial packets are encrypted with keys derived from a
universally known salt, which allow observers to inspect the contents of these
packets, which include the TLS Client Hello and Server Hello messages. Again,
middleboxes may ossify on the version 1 key derivation and packet formats.

Finally {{!QUIC-VN=I-D.ietf-quic-version-negotiation}} provides two mechanisms
for endpoints to negotiate the QUIC version to use. The "incompatible" version
negotiation method can support switching from any initial QUIC version to any
other version with full generality, at the cost of an additional round-trip at
the start of the connection. "Compatible" version negotiation eliminates the
round-trip penalty but levies some restrictions on how much the two versions can
differ semantically.

QUIC version 2 is meant to mitigate ossification concerns and exercise the
version negotiation mechanisms. The only change is a tweak to the inputs of
some crypto derivation functions to enforce full key separation. Any endpoint
that supports two versions needs to implement version negotiation to protect
against downgrade attacks.

{{?I-D.duke-quic-version-aliasing}} is a more robust, but much more complicated,
proposal to address these ossification problems. By design, it requires
incompatible version negotiation. QUICv2 enables exercise of compatible version
negotiation mechanism.

# Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119 {{?RFC2119}}.

# Changes from QUIC Version 1

QUIC version 2 endpoints MUST implement the QUIC version 1 specification as
described in {{QUIC}}, {{QUIC-TLS}}, and {{!RFC9002}}, with the following
changes.

## Version Field

The version field of long headers is 0x709a50c4.

## Long Header Packet Types

Initial packets use a packet type field of 0b01. 0-RTT packets use a packet
type field of 0b10. Handshake packets use a packet type field of 0b11. Retry
packets use a packet type field of 0b00.

## Cryptography changes

### Initial Salt

The salt used to derive Initial keys in {{Section 5.2 of QUIC-TLS}} changes to:

~~~
initial_salt = 0xa707c203a59b47184a1d62ca570406ea7ae3e5d3
~~~

### HKDF Labels

The labels used in {{QUIC-TLS}} to derive packet protection keys (Section
{{Section 5.1 of QUIC-TLS}}{:sectionFormat="bare"}), header protection keys
(Section {{Section 5.4 of QUIC-TLS}}{:sectionFormat="bare"}), Retry Integrity
Tag keys (Section {{Section 5.8 of QUIC-TLS}}{:sectionFormat="bare"}), and key
updates (Section {{Section 6.1 of QUIC-TLS}}{:sectionFormat="bare"}) change from
"quic key" to "quicv2 key", from "quic iv" to "quicv2 iv", from "quic hp" to
"quicv2 hp", and from "quic ku" to "quicv2 ku", to meet the guidance for new
versions in Section {{Section 9.6 of QUIC-TLS}}{:sectionFormat="bare"} of that
document.

### Retry Integrity Tag

The key and nonce used for the Retry Integrity Tag ({{Section 5.8 of QUIC-TLS}})
change to:

~~~
secret =
  0x3425c20cf88779df2ff71e8abfa78249891e763bbed2f13c048343d348c060e2
key = 0xba858dc7b43de5dbf87617ff4ab253db
nonce = 0x141b99c239b03e785d6a2e9f
~~~


# Version Negotiation Considerations

QUIC version 2 endpoints SHOULD also support QUIC version 1. Any QUIC endpoint
that supports multiple versions MUST fully implement {{QUIC-VN}} to prevent
version downgrade attacks.

Note that version 2 meets that document's definition of a compatible version
with version 1. Therefore, v2-capable servers MUST use compatible version
negotiation unless they do not support version 1.

## Compatible Negotiation Requirements

Compatible version negotiation between versions 1 and 2 follow the same
requirements in either direction. This section uses the terms "original
version" and "negotiated version" from {{QUIC-VN}}.

If the server sends a Retry packet, it MUST use the original version. The
client ignores Retry packets using other versions. The client MUST NOT use a
different version in the subsequent Initial that contains the Retry token. The
server MAY encode the QUIC version in its Retry token to validate that the
client did not switch versions, and drop the packet if it switched.

QUIC version 2 uses the same transport parameters to authenticate the Retry as
QUIC version 1. After switching to a negotiated version after a Retry, the
server MUST include the relevant transport parameters to validate that the
server sent the Retry and the connection IDs used in the exchange, as described
in {{QUIC}}. Note that the version of the first Initial and the subsequent Retry
are not authenticated by transport parameters.  

The server SHOULD start sending its Initial packets using the negotiated
version as soon as it decides to change. Note that the server might send some
Initial packets using the original version.

Once the client has processed a packet using the negotiated version, it SHOULD
send subsequent Initial packets using that version. The server MUST NOT discard
its original version Initial receive keys until it successfully processes a
packet with the negotiated version.

Both endpoints MUST send Handshake or 1-RTT packets using the negotiated
version. An endpoint MUST drop packets using any other version. Endpoints have
no need to generate the keying material that would allow them to decrypt or
authenticate these packets. 

If the server's version_information transport parameter does not contain a
Chosen Version field equivalent to the version in the server's Handshake packet
headers, the client MUST terminate the connection with a
VERSION_NEGOTIATION_ERROR.

The client MUST NOT send 0-RTT packets using the negotiated version, even after
processing a packet of that version from the server. Servers can apply original
version 0-RTT packets to a connection without additional considerations.

# Ossification Considerations

QUIC version 2 provides protection against some forms of ossification. Devices
that assume that all long headers will contain encode version 1, or that the
version 1 Initial key derivation formula will remain version-invariant, will not
correctly process version 2 packets.

However, many middleboxes such as firewalls focus on the first packet in a
connection, which will often remain in the version 1 format due to the
considerations above.

Clients interested in combating firewall ossification can initiate a connection
using version 2 if they are either reasonably certain the server supports it, or
are willing to suffer a round-trip penalty if they are incorrect.

# Applicability

This version of QUIC provides no change from QUIC version 1 relating to the
capabilities available to applications. Therefore, all Application Layer
Protocol Negotiation (ALPN) ({{?RFC7301}}) codepoints specified to operate over
QUICv1 can also operate over this version of QUIC.

All QUIC extensions defined to work with version 1 also work with version 2.

# Security Considerations

QUIC version 2 introduces no changes to the security or privacy properties of
QUIC version 1.

The mandatory version negotiation mechanism guards against downgrade attacks,
but downgrades have no security implications, as the version properties are
identical.

# IANA Considerations

This document requests that IANA add the following entry to the QUIC version
registry:

Value: 0x709a50c4

Status: provisional

Specification: This Document

Change Controller: IETF

Contact: QUIC WG

--- back

# Changelog

> **RFC Editor's Note:**  Please remove this section prior to
> publication of a final version of this document.

## since draft-ietf-quic-v2-00
* Expanded requirements for compatible version negotiation
* Greased the packet type codepoints
* Random version number

## since draft-duke-quic-v2-02

* Converted to adopted draft
* Deleted references to QUIC improvements
* Clarified status of QUIC extensions

## since draft-duke-quic-v2-01

* Made the final version number TBD.
* Added ALPN considerations

## since draft-duke-quic-v2-00

* Added provisional versions for interop
* Change the v1 Retry Tag secret
* Change labels to create full key separation
