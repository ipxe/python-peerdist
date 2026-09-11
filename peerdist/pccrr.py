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

from collections.abc import Buffer, MutableMapping, Sequence
from dataclasses import dataclass, field
from enum import IntEnum
from struct import Struct
from typing import Any, cast, ClassVar, Self, TypeVar


MAGIC_PATH = "/116B50EB-ECE2-41ac-8429-9F9E963361B7/"
"""Magic retrieval URI path

This is the fixed HTTP URI path that clients use to send retrieval
protocol requests.

Yes, this is a mixed-case GUID used as string literal.  Nobody knows
how or why this happened.
"""


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

    index: int = 0
    """Index of first block in range"""

    count: int = 1
    """Number of blocks in range"""


class DecodeError(Exception):
    """Malformed protocol data"""


@dataclass(kw_only=True)
class Decoder:
    """Message decoder"""

    data: memoryview
    """Raw data"""

    offset: int = 0
    """Position within original data"""

    @property
    def len(self) -> int:
        """Length of original data"""
        return self.data.nbytes

    @property
    def remaining(self) -> int:
        """Length of data remaining"""
        return (self.len - self.offset)

    def reset(self) -> None:
        """Reset decoder position"""
        self.offset = 0

    def raw(self, length: int) -> memoryview:
        """Extract raw bytes"""
        offset = self.offset
        if length > self.remaining:
            raise DecodeError("too short for %d bytes at offset %d (of %d)" %
                              (length, offset, self.len))
        data = self.data[offset:(offset + length)].toreadonly()
        self.offset += length
        return data

    def unpack(self, struct: Struct) -> Sequence[int]:
        """Extract a packed structure"""
        return struct.unpack(self.raw(struct.size))

    def uint32(self) -> int:
        """Extract an unsigned 32-bit integer"""
        return self.unpack(UINT32)[0]

    def sized(self) -> Buffer:
        """Extract a variably-sized data block

        Any zero-padding following the block will also be extracted,
        unless it is at the end of the overall message.
        """
        size = self.uint32()
        data = self.raw(size)
        if self.offset < self.len:
            pad_len = (-size % 4)
            self.raw(pad_len)
        return data

    def ranges(self) -> Sequence[Range]:
        """Extract a range list"""
        num_ranges = self.uint32()
        ranges = [Range(index=index, count=count)
                  for _ in range(num_ranges)
                  for (index, count) in (self.unpack(UINT32x2),)]
        return ranges


@dataclass(kw_only=True)
class Encoder:
    """Message encoder"""

    head: bytearray = field(default_factory=bytearray)
    """First buffer holding encoded message data"""

    tail: list[Buffer] = field(default_factory=list)
    """Remaining buffers holding encoded message data"""

    length: int = 0
    """Total length of encoded message data"""

    @property
    def buffers(self) -> Sequence[Buffer]:
        """List of buffers holding encoded message data"""
        return (bytes(self.head), *self.tail)

    def raw(self, data: Buffer, split: bool = False) -> None:
        """Prepend raw data"""
        memory = memoryview(data)
        length = memory.nbytes
        if length:
            if split:
                self.tail[:0] = (memory, memoryview(self.head).toreadonly())
                self.head = bytearray()
            else:
                self.head[:0] = memory
            self.length += length

    def pack(self, struct: Struct, *args: int) -> None:
        """Prepend a packed structure"""
        self.raw(struct.pack(*args))

    def uint32(self, value: int) -> None:
        """Prepend an unsigned 32-bit integer"""
        self.pack(UINT32, value)

    def sized(self, data: Buffer, split: bool = False) -> None:
        """Prepend a variably sized data block

        The block will be zero-padded to a four-byte boundary, unless
        it is at the end of the overall message.
        """
        size = memoryview(data).nbytes
        if self.length:
            pad_len = (-size % 4)
            self.raw(bytes(pad_len))
        if size:
            self.raw(data, split=split)
        self.uint32(size)

    def ranges(self, ranges: Sequence[Range]) -> None:
        """Prepend a range list"""
        for r in reversed(ranges):
            self.pack(UINT32x2, r.index, r.count)
        self.uint32(len(ranges))


MessageT = TypeVar('MessageT', bound='Message')


@dataclass(kw_only=True)
class Message:
    """Message"""

    crypto_alg_id: CryptoAlgId = CryptoAlgId.NONE
    """Encryption algorithm"""

    PROT_VER: ClassVar[ProtVer]
    """Protocol version for this message type"""

    MSG_TYPE: ClassVar[MsgType]
    """Message type"""

    _MSG_TYPES: ClassVar[MutableMapping[MsgType, type[Self]]] = {}

    def __init_subclass__(cls: type[Self], **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if getattr(cls, 'MSG_TYPE', None) is not None:
            if cls.MSG_TYPE in cls._MSG_TYPES:
                raise RuntimeError("Duplicate message type %s vs %s" %
                                   (cls, cls._MSG_TYPES[cls.MSG_TYPE]))
            cls._MSG_TYPES[cls.MSG_TYPE] = cls

    @classmethod
    def from_bytes(cls: type[MessageT], data: Buffer) -> MessageT:
        """Message decoded from a byte sequence"""
        decoder = Decoder(data=memoryview(data))
        subcls: type[MessageT] = cls
        if not hasattr(cls, 'MSG_TYPE'):
            subcls = cls.autodetect(decoder)
            decoder.reset()
        self = subcls.decode(decoder)
        if decoder.remaining:
            raise DecodeError("unextracted bytes at offset %d (of %d)" %
                              (decoder.offset, decoder.len))
        return cast(MessageT, self)

    def to_buffers(self) -> Sequence[Buffer]:
        """Message encoded as a buffer sequence"""
        encoder = Encoder()
        self.encode(encoder)
        return encoder.buffers

    def to_bytes(self) -> bytes:
        """Message encoded as a byte sequence"""
        return b''.join(self.to_buffers())

    def __bytes__(self) -> bytes:
        """Message encoded as a byte sequence"""
        return self.to_bytes()

    def hex(self) -> str:
        """Message encoded as a hexadecimal string"""
        return bytes(self).hex()

    @classmethod
    def autodetect(cls, decoder: Decoder) -> type[Self]:
        """Autodetect message type"""
        (_, msg_type, _, _) = decoder.unpack(UINT32x4)
        if msg_type not in MsgType:
            raise DecodeError("unrecognised message type %d" % msg_type)
        if msg_type not in cls._MSG_TYPES:
            raise DecodeError("unregistered message type %d" % msg_type)
        return cls._MSG_TYPES[MsgType(msg_type)]

    @classmethod
    def decode(cls, decoder: Decoder) -> Message:
        """Decode message"""
        remaining = decoder.remaining
        (prot_ver, msg_type, length, crypto_alg_id) = decoder.unpack(UINT32x4)
        if prot_ver != cls.PROT_VER:
            raise DecodeError("protocol version %d is wrong for %s" %
                              (prot_ver, cls.__name__))
        if msg_type != cls.MSG_TYPE:
            raise DecodeError("message type %d is wrong for %s" %
                              (msg_type, cls.__name__))
        if length != remaining:
            raise DecodeError("message header length %d does not match %d" %
                              (length, remaining))
        if crypto_alg_id not in CryptoAlgId:
            raise DecodeError("unrecognised crypto algorithm %d" %
                              crypto_alg_id)
        return Message(crypto_alg_id=CryptoAlgId(crypto_alg_id))

    def encode(self, encoder: Encoder) -> None:
        """Encode message"""
        length = (encoder.length + UINT32x4.size)
        encoder.pack(UINT32x4, self.PROT_VER, self.MSG_TYPE, length,
                     self.crypto_alg_id)


@dataclass(kw_only=True)
class Request(Message):
    """Request message"""

    _MSG_TYPES: ClassVar[MutableMapping[MsgType, type[Request]]] = {}


@dataclass(kw_only=True)
class Response(Message):
    """Response message"""

    _MSG_TYPES: ClassVar[MutableMapping[MsgType, type[Response]]] = {}

    @classmethod
    def autodetect(cls, decoder: Decoder) -> type[Self]:
        """Autodetect message type"""
        decoder.uint32()
        return super().autodetect(decoder)

    @classmethod
    def decode(cls, decoder: Decoder) -> Message:
        """Decode message"""
        length = decoder.uint32()
        if length != decoder.remaining:
            raise DecodeError("response header length %d does not match %d" %
                              (length, decoder.remaining))
        return super().decode(decoder)

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

    req_block_ranges: Sequence[Range] = field(
        default_factory=lambda: [Range()]
    )
    """List of requested block ranges"""

    vrf: bytes = b''
    """Useless VRF data"""

    @classmethod
    def decode(cls, decoder: Decoder) -> Self:
        """Decode message"""
        self = super().decode(decoder)
        segment_id = bytes(decoder.sized())
        req_block_ranges = decoder.ranges()
        vrf = bytes(decoder.sized())
        return cls(
            crypto_alg_id=self.crypto_alg_id,
            segment_id=segment_id,
            req_block_ranges=req_block_ranges,
            vrf=vrf,
        )

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

    block: Buffer = b''
    """Encrypted data block"""

    vrf: bytes = b''
    """Useless VRF data"""

    iv: bytes = b''
    """Initialization vector for block cipher"""

    @classmethod
    def decode(cls, decoder: Decoder) -> Self:
        """Decode message"""
        self = super().decode(decoder)
        segment_id = bytes(decoder.sized())
        (block_index, next_block_index) = decoder.unpack(UINT32x2)
        block = decoder.sized()
        vrf = bytes(decoder.sized())
        iv = bytes(decoder.sized())
        return cls(
            crypto_alg_id=self.crypto_alg_id,
            segment_id=segment_id,
            block_index=block_index,
            next_block_index=next_block_index,
            block=block,
            vrf=vrf,
            iv=iv,
        )

    def encode(self, encoder: Encoder) -> None:
        """Encode message"""
        encoder.sized(self.iv)
        encoder.sized(self.vrf)
        encoder.sized(self.block, split=True)
        encoder.pack(UINT32x2, self.block_index, self.next_block_index)
        encoder.sized(self.segment_id)
        super().encode(encoder)
