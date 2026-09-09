"""Peer Content Caching and Retrieval: Retrieval Protocol [MS-PCCRR]

The Retrieval Protocol is used for point-to-point communication
between two peers (or between a peer and a hosted cache server).  It
defines the messages used for retrieving encrypted blocks from a peer.

It also defines messages that can be used for enumerating the segments
and blocks held by a peer.  (These are not the messages actually used
for discovering segments and blocks: that process is handled by the
entirely unrelated Discovery Protocol.)
"""

from __future__ import annotations

import base64
from collections.abc import Buffer, Mapping, MutableSequence, Sequence
from dataclasses import dataclass, field
from enum import IntEnum
from struct import Struct
from typing import ClassVar, Optional


UINT32 = Struct(">I")
UINT32x2 = Struct(">2I")
UINT32x4 = Struct(">4I")


class ProtVer(IntEnum):
    """Protocol version

    This does not encode anything about the protocol version in use:
    it is merely a somewhat useless extension to the `MsgType`
    enumeration that seems to define the protocol version in which
    that message type was defined.
    """
    V1_0 = 0x00000001
    V2_0 = 0x00000002


class MsgType(IntEnum):
    """Message type"""
    MSG_NEGO_REQ = 0x00000000
    MSG_NEGO_RESP = 0x00000001
    MSG_GETBLKLIST = 0x00000002
    MSG_GETBLKS = 0x00000003
    MSG_BLKLIST = 0x00000004
    MSG_BLK = 0x00000005
    MSG_GETSEGLIST = 0x00000006
    MSG_SEGLIST = 0x00000007


class CryptoAlgId(IntEnum):
    """Encryption algorithm"""
    NONE = 0x00000000
    AES_128 = 0x00000001
    AES_192 = 0x00000002
    AES_256 = 0x00000003


@dataclass(kw_only=True)
class Range:
    """Block or segment range specifier"""

    index: int
    """Index of first block in range"""

    count: int
    """Number of blocks in range"""


@dataclass
class Encoder:
    """Message encoder"""

    elements: MutableSequence[Buffer] = field(
        default_factory=lambda: [bytearray()]
    )
    """List of encoded elements"""

    length: int = 0
    """Total length of encoded elements"""

    def raw(self, element: Buffer, split=False) -> None:
        """Prepend a raw element"""
        if element:
            if split:
                self.elements[:0] = (bytearray(), element)
            else:
                self.elements[0][:0] = element
            self.length += len(element)

    def pack(self, struct, *args) -> None:
        """Prepend a packed structure"""
        self.raw(struct.pack(*args))

    def uint32(self, value: int) -> None:
        """Prepend an unsigned 32-bit integer"""
        self.pack(UINT32, value)

    def sized(self, element: Buffer, split=False) -> None:
        """Prepend a variably sized element

        The element will be zero-padded to a four-byte boundary if it
        is not the last element.
        """
        length = len(element)
        if self.length:
            self.raw(bytes(-length % 4))
        if length:
            self.raw(element, split=split)
        self.uint32(length)

    def ranges(self, ranges: Sequence[Range]) -> None:
        """Prepend a range list"""
        for r in reversed(ranges):
            self.pack(UINT32x2, r.index, r.count)
        self.uint32(len(ranges))


@dataclass(kw_only=True)
class Message:
    """Message"""

    crypto_alg_id: CryptoAlgId = CryptoAlgId.NONE
    """Encryption algorithm"""

    PROT_VER: ClassVar[Optional[ProtVer]] = None
    """Protocol version for this message type"""

    MSG_TYPE: ClassVar[Optional[MsgType]] = None
    """Message type"""

    _MSG_TYPES: ClassVar[Mapping[MsgType, type[Message]]] = {}

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        if cls.MSG_TYPE is not None:
            Message._MSG_TYPES[cls.MSG_TYPE] = cls

    def __bytes__(self) -> bytes:
        """Message encoded as a byte sequence"""
        return b''.join(self.encoded)

    @property
    def hex(self) -> str:
        """Message encoded as a hexadecimal string"""
        return base64.b16encode(bytes(self)).decode().lower()

    @property
    def encoded(self) -> Sequence[Buffer]:
        """Message encoded as a buffer sequence"""
        encoder = Encoder()
        self.encode(encoder)
        return tuple(memoryview(x).toreadonly() for x in encoder.elements)

    def encode(self, encoder: Encoder) -> None:
        """Encode message"""
        length = (encoder.length + UINT32x4.size)
        encoder.pack(UINT32x4, self.PROT_VER, self.MSG_TYPE, length,
                     self.crypto_alg_id)


@dataclass(kw_only=True)
class Request(Message):
    """Request message"""


@dataclass(kw_only=True)
class Response(Message):
    """Response message"""

    def encode(self, encoder: Encoder) -> None:
        """Encode message"""
        super().encode(encoder)
        encoder.uint32(encoder.length)


@dataclass(kw_only=True)
class MsgGetBlks(Request):
    """Get blocks message content"""

    PROT_VER = ProtVer.V1_0
    MSG_TYPE = MsgType.MSG_GETBLKS

    crypto_alg_id: CryptoAlgId = CryptoAlgId.AES_128
    """Requested encryption algorithm (defaults to AES-128-CBC)"""

    segment_id: bytes
    """Segment identifier"""

    req_block_ranges: Sequence[Range] = (Range(index=0, count=1),)
    """List of requested block ranges"""

    vrf: bytes = b''
    """Useless VRF data"""

    def encode(self, encoder: Encoder) -> None:
        """Encode message"""
        encoder.sized(self.vrf)
        encoder.ranges(self.req_block_ranges)
        encoder.sized(self.segment_id)
        super().encode(encoder)


@dataclass(kw_only=True)
class MsgBlk(Response):
    """Block message content"""

    PROT_VER = ProtVer.V1_0
    MSG_TYPE = MsgType.MSG_BLK

    crypto_alg_id: CryptoAlgId = CryptoAlgId.AES_128
    """Requested encryption algorithm (defaults to AES-128-CBC)"""

    segment_id: bytes
    """Segment identifier"""

    block_index: int = 0
    """Block index within this segment"""

    next_block_index: int = 0
    """Next block index (or zero if no next block exists)"""

    block: memoryview = memoryview(b'')
    """Encrypted data block"""

    vrf: bytes = b''
    """Useless VRF data"""

    iv: bytes = b''
    """Initialization vector for block cipher"""

    def encode(self, encoder: Encoder) -> None:
        """Encode message"""
        encoder.sized(self.iv)
        encoder.sized(self.vrf)
        encoder.sized(self.block, split=True)
        encoder.pack(UINT32x2, self.block_index, self.next_block_index)
        encoder.sized(self.segment_id)
        super().encode(encoder)
