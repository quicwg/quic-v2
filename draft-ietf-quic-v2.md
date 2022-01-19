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
that supports multiple versions MUST meet the minimum requirements described in
{{QUIC-VN}} to prevent version downgrade attacks.

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
in {{Section 7.3 of QUIC}}. Note that the version of the first Initial and the subsequent Retry
are not authenticated by transport parameters.  

The server SHOULD start sending its Initial packets using the negotiated
version as soon as it decides to change. Before the server is able to process
transport parameters from the client, it might need to respond to Initial
packets from the client. For these packets the server uses the original version.

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

# Sample Packet Protection

These test vectors are copied verbatim from {{QUIC-TLS}}, except (of course)
where the derived values differ.

This section shows examples of packet protection so that implementations can be
verified incrementally. Samples of initial packets from both client and server
plus a Retry packet are defined. These packets use an 8-byte client-chosen
Destination Connection ID of 0x8394c8f03e515708.

## Keys

The labels generated during the execution of the HKDF-Expand-Label function
that is, HkdfLabel.label) and part of the value given to the HKDF-Expand
function in order to produce its output are:

client in: (unchanged from QUICv1)
00200f746c73313320636c69656e7420696e00

server in: (unchanged from QUICv1)
00200f746c7331332073657276657220696e00

quicv2 key:
001010746c73313320717569637632206b657900

quicv2 iv:
000c0f746c7331332071756963763220697600

quicv2 hp:
00100f746c7331332071756963763220687000

The initial secret is common:
~~~
initial_secret = HKDF-Extract(initial_salt, cid)
    = ddfcb7b82a430b7845210ad64b406977
      ed51b269a14bc69aa9ea9b366fa3b06b
~~~

The secrets for protecting client packets are:

~~~
client_initial_secret
    = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    = 9fe72e1452e91f551b770005054034e4
      7575d4a0fb4c27b7c6cb303a338423ae

key = HKDF-Expand-Label(client_initial_secret, "quicv2 key", "", 16)
    = 95df2be2e8d549c82e996fc9339f4563

iv  = HKDF-Expand-Label(client_initial_secret, "quicv2 iv", "", 12)
    = ea5e3c95f933db14b7020ad8

hp  = HKDF-Expand-Label(client_initial_secret, "quicv2 hp", "", 16)
    = 091efb735702447d07908f6501845794
~~~

The secrets for protecting server packets are:

~~~
server_initial_secret
    = HKDF-Expand-Label(initial_secret, "server in", "", 32)
    = 3c9bf6a9c1c8c71819876967bd8b979e
      fd98ec665edf27f22c06e9845ba0ae2f

key = HKDF-Expand-Label(server_initial_secret, "quicv2 key", "", 16)
    = 15d5b4d9a2b8916aa39b1bfe574d2aad

iv  = HKDF-Expand-Label(server_initial_secret, "quicv2 iv", "", 12)
    = a85e7ac31cd275cbb095c626

hp  = HKDF-Expand-Label(server_initial_secret, "quicv2 hp", "", 16)
    = b13861cfadbb9d11ff942dd80c8fc33b
~~~


## Client Initial {#sample-client-initial}

TODO: Update this to v2

The client sends an Initial packet.  The unprotected payload of this packet
contains the following CRYPTO frame, plus enough PADDING frames to make a
1162-byte payload:

~~~
060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
0d0010000e0403050306030203080408 050806002d00020101001c0002400100
3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
75300901100f088394c8f03e51570806 048000ffff
~~~

The unprotected header indicates a length of 1182 bytes: the 4-byte packet
number, 1162 bytes of frames, and the 16-byte authentication tag.  The header
includes the connection ID and a packet number of 2:

~~~
c300000001088394c8f03e5157080000449e00000002
~~~

Protecting the payload produces output that is sampled for header protection.
Because the header uses a 4-byte packet number encoding, the first 16 bytes of
the protected payload is sampled and then applied to the header as follows:

~~~
sample = d1b1c98dd7689fb8ec11d242b123dc9b

mask = AES-ECB(hp, sample)[0..4]
     = 437b9aec36

header[0] ^= mask[0] & 0x0f
     = c0
header[18..21] ^= mask[1..4]
     = 7b9aec34
header = c000000001088394c8f03e5157080000449e7b9aec34
~~~

The resulting protected packet is:

~~~
c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11
d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399
1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c
8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212
30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5
457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208
4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec
4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3
485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db
059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c
7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8
9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556
be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74
68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a
c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00
f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632
291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964
25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd
14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff
ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198
e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd
c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73
203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f
cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e
fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade
a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047
90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2
162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4
40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0
6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e
8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0
be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400
54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab
760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9
f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4
056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064
7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241
e221af44860018ab0856972e194cd934
~~~


## Server Initial

TODO: Update this to v2

The server sends the following payload in response, including an ACK frame, a
CRYPTO frame, and no PADDING frames:

~~~
02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739
88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94
0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00
020304
~~~

The header from the server includes a new connection ID and a 2-byte packet
number encoding for a packet number of 1:

~~~
c1000000010008f067a5502a4262b50040750001
~~~

As a result, after protection, the header protection sample is taken starting
from the third protected byte:

~~~
sample = 2cd0991cd25b0aac406a5816b6394100
mask   = 2ec0d8356a
header = cf000000010008f067a5502a4262b5004075c0d9
~~~

The final protected packet is then:

~~~
cf000000010008f067a5502a4262b500 4075c0d95a482cd0991cd25b0aac406a
5816b6394100f37a1c69797554780bb3 8cc5a99f5ede4cf73c3ec2493a1839b3
dbcba3f6ea46c5b7684df3548e7ddeb9 c3bf9c73cc3f3bded74b562bfb19fb84
022f8ef4cdd93795d77d06edbb7aaf2f 58891850abbdca3d20398c276456cbc4
2158407dd074ee
~~~

TBD

## Retry

This shows a Retry packet that might be sent in response to the Initial packet
in {{client-initial}}. The integrity check includes the client-chosen connection
ID value of 0x8394c8f03e515708, but that value is not included in the final retry
packet:

~~~
cf709a50c40008f067a5502a4262b574  6f6b656e1dc71130cd1ed39d6efcee5c
85806501
~~~

## ChaCha20-Poly1305 Short Header Packet

TODO: Update this to v2

This example shows some of the steps required to protect a packet with
a short header.  This example uses AEAD_CHACHA20_POLY1305.

In this example, TLS produces an application write secret from which a server
uses HKDF-Expand-Label to produce four values: a key, an IV, a header
protection key, and the secret that will be used after keys are updated (this
last value is not used further in this example).

~~~
secret
    = 9ac312a7f877468ebe69422748ad00a1
      5443f18203a07d6060f688f30f21632b

key = HKDF-Expand-Label(secret, "quic key", "", 32)
    = c6d98ff3441c3fe1b2182094f69caa2e
      d4b716b65488960a7a984979fb23e1c8

iv  = HKDF-Expand-Label(secret, "quic iv", "", 12)
    = e0459b3474bdd0e44a41c144

hp  = HKDF-Expand-Label(secret, "quic hp", "", 32)
    = 25a282b9e82f06f21f488917a4fc8f1b
      73573685608597d0efcb076b0ab7a7a4

ku  = HKDF-Expand-Label(secret, "quic ku", "", 32)
    = 1223504755036d556342ee9361d25342
      1a826c9ecdf3c7148684b36b714881f9
~~~

The following shows the steps involved in protecting a minimal packet with an
empty Destination Connection ID. This packet contains a single PING frame (that
is, a payload of just 0x01) and has a packet number of 654360564. In this
example, using a packet number of length 3 (that is, 49140 is encoded) avoids
having to pad the payload of the packet; PADDING frames would be needed if the
packet number is encoded on fewer bytes.

~~~
pn                 = 654360564 (decimal)
nonce              = e0459b3474bdd0e46d417eb0
unprotected header = 4200bff4
payload plaintext  = 01
payload ciphertext = 655e5cd55c41f69080575d7999c25a5bfb
~~~

The resulting ciphertext is the minimum size possible. One byte is skipped to
produce the sample for header protection.

~~~
sample = 5e5cd55c41f69080575d7999c25a5bfb
mask   = aefefe7d03
header = 4cfe4189
~~~

The protected packet is the smallest possible packet size of 21 bytes.

~~~
packet = 4cfe4189655e5cd55c41f69080575d7999c25a5bfb
~~~

# Changelog

> **RFC Editor's Note:**  Please remove this section prior to
> publication of a final version of this document.

## since draft-ietf-quic-v2-00

* Expanded requirements for compatible version negotiation
* Added Initial Key and Retry test vector
* Greased the packet type codepoints
* Random version number
* Clarified requirement to use QUIC-VN

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
