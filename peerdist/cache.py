"""Block replay cache

We define an on-disk directory layout for a cache containing encrypted
retrieval blocks:

    cache/
    |______00/
    |______01/
    |______02/
    |______...
    |______xx/xxyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy-b.blk
    |...

where:

  * `xxyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy` is the segment ID (HoHoDK) as
    a lower-case hexadecimal string

  * `xx` is the first two characters (i.e. the first byte) of the
    segment ID

  * `b` is the block index within the segment (which will always be
    zero when using MS-PCCRC version 2 content information), as an
    unpadded decimal string.

Each block file, if present, contains the raw byte serialization of a
`MSG_BLK` response message for that segment ID and block index.

The content of each block is encrypted with the cipher specified
within its `MSG_BLK` message header (typically AES-128-CBC).  The
decryption key may not be known to the cache.  Blocks may not
necessarily all be encrypted with the same cipher.

This on-disk layout and format is designed to allow for at least two
use cases:

  * A replay server may respond to `MSG_GETBLKS` request messages by
    simply parsing the segment ID and block index from the request and
    then sending back the corresponding block file unmodified.  The
    block file is already a valid `MSG_BLK` response message.

  * A client with access to the cache directory (e.g. iPXE with the
    cache directory held in a FAT filesystem) may retrieve blocks from
    the cache rather than from a network peer.

"""

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import io
import mmap
import os
from pathlib import Path
import tempfile
from typing import BinaryIO, cast, ClassVar, Self

from . import pccrr


@dataclass
class CacheKey:
    """Block replay cache key"""

    segment_id: bytes
    """Segment identifier (HoHoDK)"""

    block_index: int = 0
    """Block index within this segment (usually zero)"""

    SUFFIX: ClassVar[str] = "blk"
    """File name suffix"""

    def __post_init__(self) -> None:
        segment_id = bytes(self.segment_id)
        block_index = int(self.block_index)
        if not segment_id or block_index < 0:
            raise ValueError("Invalid cache key %s" % self)
        self.segment_id = segment_id
        self.block_index = block_index

    @property
    def path(self) -> Path:
        """Path for this cache key"""
        filename = "%s-%d.%s" % (self.segment_id.hex(), self.block_index,
                                self.SUFFIX)
        dirname = filename[:2]
        return Path(dirname) / Path(filename)

    @classmethod
    def from_path(cls, path: os.PathLike | str) -> Self | None:
        """Construct cache key matching a path"""
        path = Path(path)
        (segment_id_str, _, block_index_str) = path.stem.rpartition('-')
        try:
            self = cls(bytes.fromhex(segment_id_str), int(block_index_str))
            return self if self.path == path else None
        except ValueError:
            return None

    @classmethod
    def glob(cls, segment_id: bytes | None = None) -> str:
        """Construct glob expression"""
        if segment_id is None:
            return "*/*-*.%s" % cls.SUFFIX
        segment_id_str = bytes(segment_id).hex()
        if not segment_id_str:
            raise ValueError("Invalid segment ID %r" % segment_id)
        dirname = segment_id_str[:2]
        return "%s/%s-*.%s" % (dirname, segment_id_str, cls.SUFFIX)
        

@dataclass
class CacheEntry:
    """Block replay cache entry"""

    path: Path
    """Path representing this cache entry"""

    def __bool__(self) -> bool:
        """Check if cache entry is present"""
        return self.path.exists()

    @contextmanager
    def reader(self) -> Iterator[BinaryIO]:
        """Context manager for reading a cache entry

        Returns a context for a file handle from which the cached
        block file content can be read.  Raises `FileNotFoundError` if
        the cached block file does not exist.
        """
        with self.path.open(mode='rb') as fh:
            yield fh

    @contextmanager
    def writer(self, sync: bool = False) -> Iterator[BinaryIO]:
        """Context manager for creating a cache entry

        Returns a context for a temporary file into which the cached
        block file content can be written.  On a clean exit, the
        temporary file will be atomically renamed to appear under the
        cache key.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
                mode='w+b',
                dir=self.path.parent,
                prefix=".%s." % self.path.name,
                delete_on_close=False,
        ) as tmp:
            yield cast(BinaryIO, tmp)
            tmp.flush()
            if sync:
                os.fsync(tmp.fileno())
            Path(tmp.name).replace(self.path)

    @property
    def msg(self) -> pccrr.MsgBlk | None:
        """Block message content"""
        try:
            with self.reader() as fh:
                with mmap.mmap(fh.fileno(), 0, prot=mmap.PROT_READ) as memory:
                    return pccrr.MsgBlk.from_bytes(memory)
        except FileNotFoundError:
            return None

    @msg.setter
    def msg(self, msg: pccrr.MsgBlk | None) -> None:
        """Block message content"""
        if msg is not None:
            buffers = [memoryview(x) for x in msg.to_buffers()]
            with self.writer() as fh:
                index = 0
                count = len(buffers)
                while index < count:
                    written = os.writev(fh.fileno(), buffers[index:])
                    while written >= len(buffers[index]):
                        written -= len(buffers[index])
                        index += 1
                    if written:
                        buffers[index] = memoryview(buffers[index])[written:]
        else:
            self.path.unlink(missing_ok=True)


@dataclass
class Cache(Mapping[CacheKey, CacheEntry]):
    """Block replay cache"""

    path: Path
    """Cache directory"""

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        if not self.path.exists():
            raise ValueError("Cache directory %s does not exist" % self.path)

    def __getitem__(self, key: CacheKey | tuple[bytes, int]) -> CacheEntry:
        """Get cache entry"""
        try:
            if not isinstance(key, CacheKey):
                key = CacheKey(key[0], key[1])
        except ValueError:
            raise KeyError from None
        return CacheEntry(self.path / key.path)

    def blocks(self, segment_id: bytes) -> Iterator[CacheKey]:
        """Iterate over all cached block files within a segment"""
        for path in self.path.glob(CacheKey.glob(segment_id)):
            key = CacheKey.from_path(path)
            if key is not None:
                yield key

    def __iter__(self) -> Iterator[CacheKey]:
        """Iterate over all cached block files"""
        for path in self.path.glob(CacheKey.glob()):
            key = CacheKey.from_path(path)
            if key is not None:
                yield key

    def __len__(self) -> int:
        """Count cached block files"""
        return sum(1 for _ in self)

    @contextmanager
    def retrieve(self, req: pccrr.MsgGetBlks) -> Iterator[BinaryIO]:
        """Context manager for responding to a retrieval request

        Returns a context for a file handle from which the response
        bytes may be read.
        """
        segment_id = req.segment_id
        ranges = req.req_block_ranges
        if len(ranges) != 1 or ranges[0].count != 1:
            raise ValueError("Invalid retrieval range")
        block_index = ranges[0].index
        key = CacheKey(segment_id, block_index)
        entry = self[key]
        try:
            with entry.reader() as fh:
                yield fh
        except FileNotFoundError:
            missing = pccrr.MsgBlk(
                crypto_alg_id=req.crypto_alg_id,
                segment_id=segment_id,
                block_index=block_index,
            )
            yield io.BytesIO(missing.to_bytes())
