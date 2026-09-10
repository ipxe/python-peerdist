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
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
import io
import os
from pathlib import Path
import tempfile
from typing import BinaryIO, cast, ClassVar, Self

from . import pccrr


@dataclass(frozen=True)
class CacheKey:
    """Block replay cache key"""

    segment_id: bytes
    """Segment identifier (HoHoDK)"""

    block_index: int = 0
    """Block index within this segment (usually zero)"""

    SUFFIX: ClassVar[str] = "blk"
    """File name suffix"""

    def __post_init__(self) -> None:
        if not isinstance(self.segment_id, bytes):
            raise ValueError("Unexpected segment ID %r" % self.segment_id)
        if not self.segment_id:
            raise ValueError("Empty segment ID")
        if not isinstance(self.block_index, int):
            raise ValueError("Unexpected block index %r" % self.block_index)
        if self.block_index < 0:
            raise ValueError("Invalid block index %d" % self.block_index)

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

    def delete(self) -> None:
        """Delete cache entry"""
        self.path.unlink(missing_ok=True)

    @contextmanager
    def reader(self) -> Iterator[BinaryIO | None]:
        """Context manager for reading a cache entry

        Returns a context yielding a file handle from which the cached
        block file content can be read, or `None` if the cached block
        file does not exist.
        """
        with ExitStack() as stack:
            try:
                fh = stack.enter_context(self.path.open(mode='rb'))
            except FileNotFoundError:
                yield None
            else:
                yield fh

    @contextmanager
    def writer(self, sync: bool = False) -> Iterator[BinaryIO]:
        """Context manager for creating a cache entry

        Returns a context yielding a temporary file into which the
        cached block file content can be written.  On a clean exit,
        the temporary file will be atomically renamed to appear under
        the cache key.
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
        with self.reader() as fh:
            if fh is None:
                return None
            msg = pccrr.MsgBlk.from_bytes(fh.read())
        return msg

    @msg.setter
    def msg(self, msg: pccrr.MsgBlk | None) -> None:
        """Block message content"""
        if msg is not None:
            buffers = [memoryview(x) for x in msg.to_buffers()]
            with self.writer() as fh:
                index = 0
                count = len(buffers)
                while index < count:
                    fh.flush()
                    written = os.writev(fh.fileno(), buffers[index:])
                    while index < count and written >= len(buffers[index]):
                        written -= len(buffers[index])
                        index += 1
                    if written:
                        buffers[index] = memoryview(buffers[index])[written:]
        else:
            self.delete()


@dataclass
class Cache(Mapping[CacheKey, CacheEntry]):
    """Block replay cache"""

    path: Path
    """Cache directory"""

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        if not self.path.exists():
            raise ValueError("Cache directory %s does not exist" % self.path)

    def __getitem__(self, key: object) -> CacheEntry:
        """Get (possibly empty) cache entry"""
        if not isinstance(key, CacheKey):
            raise KeyError(key)
        return CacheEntry(self.path / key.path)

    def __contains__(self, key: object) -> bool:
        """Check if cache entry exists"""
        try:
            return bool(self[key])
        except KeyError:
            return False

    def __delitem__(self, key: CacheKey) -> None:
        """Delete cache entry"""
        self[key].delete()

    def blocks(self, segment_id: bytes) -> Iterator[CacheKey]:
        """Iterate over all cached block files within a segment"""
        for path in self.path.glob(CacheKey.glob(segment_id)):
            key = CacheKey.from_path(path.relative_to(self.path))
            if key is not None:
                yield key

    def __iter__(self) -> Iterator[CacheKey]:
        """Iterate over all cached block files"""
        for path in self.path.glob(CacheKey.glob()):
            key = CacheKey.from_path(path.relative_to(self.path))
            if key is not None:
                yield key

    def __len__(self) -> int:
        """Count cached block files"""
        return sum(1 for _ in self)


class BadRetrievalRequest(Exception):
    """Bad cache retrieval request"""


@dataclass
class CacheServer:
    """Block replay cache server"""

    cache: Cache
    """Underlying block replay cache"""

    @contextmanager
    def retrieve(self, req: pccrr.MsgGetBlks) -> Iterator[BinaryIO]:
        """Context manager for responding to a retrieval request

        Returns a context yielding a file handle from which the
        response bytes may be read.

        The `MSG_GETBLKS` format allows for multiple blocks to be
        requested, though the specification states that the requested
        block ranges list must specify a single block range containing
        only one block.
        """
        segment_id = req.segment_id
        ranges = req.req_block_ranges
        if len(ranges) != 1:
            raise BadRetrievalRequest("Multiple block ranges")
        if ranges[0].count != 1:
            raise BadRetrievalRequest("Block range not for a single block")
        block_index = ranges[0].index
        try:
            key = CacheKey(segment_id, block_index)
        except ValueError as exc:
            raise BadRetrievalRequest(str(exc)) from exc
        with self.cache[key].reader() as fh:
            if fh is not None:
                yield fh
            else:
                missing = pccrr.MsgBlk(
                    crypto_alg_id=req.crypto_alg_id,
                    segment_id=segment_id,
                    block_index=block_index,
                )
                yield io.BytesIO(missing.to_bytes())
