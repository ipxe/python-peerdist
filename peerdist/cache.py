"""Block replay cache

We define an on-disk directory layout for a cache containing encrypted
retrieval blocks:

    cache/
    |______00/
    |______01/
    |______02/
    |______...
    |______xx/xxyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy-b.blk
    |______xx/xxyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy.lst (for v1 only)
    |...

where:

  * `xxyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy` is the segment ID (HoHoDK) as
    a lower-case hexadecimal string

  * `xx` is the first two characters (i.e. the first byte) of the
    segment ID

  * `b` is the block index within the segment (which will always be
    zero when using MS-PCCRC version 2 content information), as an
    unpadded decimal string

  * the extension `.blk` represents a block file

  * the extension `.lst` represents a block list file, for segments
    that may contain blocks with a non-zero block index

Each block file, if present, contains the raw byte serialization of a
`MSG_BLK` response message for that segment ID and block index.

Each block list file, if present, contains the raw byte serialization
of a `MSG_BLKLIST` response message for that segment ID.  When using
the Content Information Data Structure version 2.0, there can only
ever be one block within a segment and it will always have a block
index of zero.  The list file may be omitted for any such segments.

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

When using the Content Information Data Structure Version 2.0, no
`MSG_BLKLIST` block list file is required, and the next block index
within each `MSG_BLK` block file header will always be zero.

When using the Content Information Data Structure Version 1.0, a
`MSG_BLKLIST` block list file is required to keep track of the blocks
within each segment, and the next block index within every `MSG_BLK`
block file header within the segment must be updated to match.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, ExitStack
from ctypes import addressof, c_char
from dataclasses import dataclass, field, InitVar
from itertools import chain
import mmap
import os
from pathlib import Path
import tempfile
from typing import BinaryIO, cast, ClassVar

from . import pccrr


@dataclass
class CacheResponse[ResponseT: pccrr.Response](ABC):
    """A cached response message"""

    cache: Cache
    """Containing cache"""

    MSG_TYPE: ClassVar[type[ResponseT]]  # type: ignore[misc]
    """Response message type"""

    @property
    @abstractmethod
    def relpath(self) -> Path:
        """Relative path for cached response message within the cache"""

    @property
    def path(self) -> Path:
        """Path containing cached response message"""
        return self.cache.path / self.relpath

    def missed(self) -> None:
        """Report a cache miss"""

    def unlink(self) -> None:
        """Delete cached response message"""
        self.path.unlink(missing_ok=True)

    @contextmanager
    def reader(self) -> Iterator[BinaryIO | None]:
        """Context manager for reading a cached response message

        Returns a context yielding a file-like object from which the
        cached response message content can be read, or `None` if the
        response message is not present in the cache.
        """
        with ExitStack() as stack:
            try:
                fh = stack.enter_context(self.path.open(mode="rb"))
            except FileNotFoundError:
                self.missed()
                yield None
                return
            yield fh

    @contextmanager
    def writer(self, sync: bool = False) -> Iterator[BinaryIO]:
        """Context manager for creating a cached response message

        Returns a context yielding a temporary file into which the
        cached response message can be written.  On a clean exit, the
        temporary file will be renamed atomically to appear under the
        correct path.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
                mode="w+b",
                dir=self.path.parent,
                prefix=".%s." % self.path.name,
                delete_on_close=False,
        ) as tmp:
            yield cast(BinaryIO, tmp)
            tmp.flush()
            if sync:
                os.fsync(tmp.fileno())
            Path(tmp.name).replace(self.path)

    @contextmanager
    def editor(self, sync: bool = False) -> Iterator[mmap.mmap | None]:
        """Context manager for editing a cached response message

        Returns a context yielding an `mmap.mmap` that can be edited
        in place, or `None` if the response message is not present in
        the cache.

        In-place edits are not atomic, and care must be taken not to
        expose an invalid intermediate state.
        """
        with ExitStack() as stack:
            try:
                fh = stack.enter_context(self.path.open(mode="r+b"))
                mapped = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_WRITE)
            except FileNotFoundError:
                yield None
                return
            yield mapped
            fh.flush()
            if sync:
                os.fsync(fh.fileno())

    @property
    def msg(self) -> ResponseT | None:
        """Response message content"""
        with self.reader() as fh:
            if fh is None:
                return None
            try:
                msg = self.MSG_TYPE.from_bytes(fh.read())
            except pccrr.DecodeError:
                return None
        return msg

    @msg.setter
    def msg(self, msg: ResponseT | None) -> None:
        """Response message content"""
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
            self.unlink()

    @contextmanager
    def editmsg(self) -> Iterator[ResponseT | None]:
        """Context manager for an editable cached response message

        Returns a context yielding an editable version of a cached
        response message, or `None` if the response message is not
        present in the cache.

        The cached response message will be mapped using mmap(), and
        only modified portions will be overwritten.  The overall size
        of the message cannot be changed.

        In-place edits are not atomic, and care must be taken not to
        expose an invalid intermediate state.
        """
        with self.editor() as mapped:
            if mapped is None:
                yield None
                return
            try:
                msg = self.MSG_TYPE.from_bytes(mapped)
            except pccrr.DecodeError:
                yield None
                return
            yield msg
            views = [memoryview(x) for x in msg.to_buffers(readonly=False)]
            base = addressof(c_char.from_buffer(mapped))
            offset = 0
            for view in views:
                if (view.obj is mapped and
                   (offset == (addressof(c_char.from_buffer(view)) - base))):
                    # In-place mmap() slice: nothing to write
                    pass
                elif mapped[offset:(offset + view.nbytes)] == view:
                    # Unchanged content: nothing to write
                    pass
                else:
                    mapped[offset:(offset + view.nbytes)] = view
                offset += view.nbytes


@dataclass
class CacheBlock(CacheResponse[pccrr.MsgBlk]):
    """A cached block"""

    segment: CacheSegment
    """Containing segment"""

    block_index: int = 0
    """Block index within this segment (usually zero)"""

    MSG_TYPE = pccrr.MsgBlk
    """Response message type"""

    def __post_init__(self) -> None:
        if not isinstance(self.block_index, int):
            raise ValueError("Unexpected block index %r" % self.block_index)
        if self.block_index < 0:
            raise ValueError("Invalid block index %d" % self.block_index)

    def __str__(self) -> str:
        return "%s-%d" % (self.segment, self.block_index)

    def __bool__(self) -> bool:
        """Check if cached block is present"""
        return self.path.exists()

    @property
    def relpath(self) -> Path:
        """Relative path for block file within the cache"""
        filename = "%s.blk" % self
        dirname = filename[:2]
        return Path(dirname) / Path(filename)

    @property
    def segment_id(self) -> bytes:
        """Containing segment identifier (HoHoDK)"""
        return self.segment.segment_id

    def missed(self) -> None:
        """Report a cache miss"""
        self.cache.missed(self)

    def delete(self) -> None:
        """Delete cached block"""
        self.unlink()


@dataclass
class CacheSegment(Mapping[int, CacheBlock], CacheResponse[pccrr.MsgBlkList]):
    """A cached segment"""

    segment_id: bytes
    """Segment identifier (HoHoDK)"""

    MSG_TYPE = pccrr.MsgBlkList
    """Response message type"""

    MAX_SEGMENT_ID_LEN: ClassVar[int] = 64
    """Maximum length of a segment identifier"""

    def __post_init__(self) -> None:
        if not isinstance(self.segment_id, bytes):
            raise ValueError("Unexpected segment ID %r" % self.segment_id)
        if not 0 < len(self.segment_id) <= self.MAX_SEGMENT_ID_LEN:
            raise ValueError("Invalid segment ID length %d" %
                             len(self.segment_id))

    def __str__(self) -> str:
        return self.segment_id.hex()

    @property
    def relpath(self) -> Path:
        """Relative path for block list file within the cache"""
        filename = "%s.lst" % self
        dirname = filename[:2]
        return Path(dirname) / Path(filename)

    def __getitem__(self, key: object) -> CacheBlock:
        """Get (possibly empty) cached block"""
        if not isinstance(key, int):
            raise KeyError(key)
        return CacheBlock(self.cache, self, key)

    def __contains__(self, key: object) -> bool:
        """Check if cached block exists"""
        try:
            return bool(self[key])
        except KeyError:
            return False

    def __delitem__(self, key: int) -> None:
        """Delete cached block"""
        self[key].delete()

    def __bool__(self) -> bool:
        """Check if any cached block is present in this segment"""
        if self[0]:
            return True
        msg = self.msg
        if msg is None:
            return False
        return any(x.count for x in msg.block_ranges)

    def __iter__(self) -> Iterator[int]:
        """Iterate over all cached blocks

        If a block list file exists, then this will return the list of
        blocks represented within the block list file.

        If no block list file exists but block zero is present
        (i.e. the common case when using version 2.0 content
        information), then this will return the single zero index.
        """
        msg = self.msg
        if msg is not None:
            yield from chain.from_iterable(x.range for x in msg.block_ranges)
        elif self[0]:
            yield 0

    def __len__(self) -> int:
        """Count cached blocks"""
        return sum(1 for _ in self)

    def scan(self) -> Iterator[int]:
        """Scan filesystem for cached blocks within this segment"""
        parent = self.cache.path / str(self)[:2]
        pattern = "%s-*.blk" % self
        for path in parent.glob(pattern):
            block_index_str = path.stem.rpartition("-")[2]
            try:
                block = self[int(block_index_str)]
            except ValueError:
                continue
            if block.path == path:
                yield block.block_index

    def rebuild(self) -> None:
        """Rebuild block list and next-block indexes

        This should be invoked after storing a block obtained using
        version 1 content information, to rebuild the block list file
        and to update the next-block index within all other blocks in
        the same segment.

        There is no need to call this method for blocks obtained using
        version 2 content information (where there can only ever be a
        single block with index zero): doing so would simply create an
        unnecessary block list file.
        """
        ranges: list[pccrr.Range] = []
        next_block_index = 0
        for block_index in sorted(self.scan(), reverse=True):
            block = self[block_index]
            with block.editmsg() as blockmsg:
                if blockmsg is not None:
                    blockmsg.next_block_index = next_block_index
                    next_block_index = block_index
                    if ranges and ranges[-1].index == (block_index + 1):
                        ranges[-1].index -= 1
                        ranges[-1].count += 1
                    else:
                        ranges.insert(0, pccrr.Range(index=block_index))
        msg = pccrr.MsgBlkList(segment_id=self.segment_id, block_ranges=ranges)
        self.msg = msg

    def delete(self) -> None:
        """Delete cached segment"""
        self.unlink()
        for block in self:
            del self[block]


@dataclass
class Cache(Mapping[bytes, CacheSegment]):
    """Block replay cache"""

    dirname: InitVar[os.PathLike[str] | str]
    """Cache directory"""

    path: Path = field(init=False)
    """Cache directory (as a path object)"""

    on_miss: Callable[[CacheBlock], None] | None = None
    """Cache miss callback"""

    def __post_init__(self, dirname: os.PathLike[str] | str) -> None:
        self.path = Path(dirname)
        if not self.path.exists():
            raise ValueError("Cache directory %s does not exist" % self.path)

    def __getitem__(self, key: object) -> CacheSegment:
        """Get (possibly empty) cached segment"""
        if not isinstance(key, bytes):
            raise KeyError(key)
        return CacheSegment(self, key)

    def __contains__(self, key: object) -> bool:
        """Check if cache entry exists"""
        try:
            return bool(self[key])
        except KeyError:
            return False

    def __delitem__(self, key: bytes) -> None:
        """Delete cache entry"""
        self[key].delete()

    def __iter__(self) -> Iterator[bytes]:
        """Iterate over all cached segments

        No segment index is maintained, and so this will always
        require a filesystem scan.
        """
        return self.scan()

    def __len__(self) -> int:
        """Count cached segments"""
        return sum(1 for _ in self)

    def scan(self) -> Iterator[bytes]:
        """Scan filesystem for cached segments"""
        segment_ids = set()
        pattern = "*/*-*.blk"
        for path in self.path.glob(pattern):
            (segment_id_str, _, block_index_str) = path.stem.rpartition("-")
            try:
                segment_id = bytes.fromhex(segment_id_str)
                block_index = int(block_index_str)
                block = self[segment_id][block_index]
            except ValueError:
                continue
            if block.path == path:
                segment_ids.add(segment_id)
        yield from segment_ids

    def missed(self, block: CacheBlock) -> None:
        """Report a cache miss

        Invoke the cache miss callback (if any).  The callback cannot
        change the result of this cache lookup from a miss to a hit,
        but may schedule a download of the missing block.
        """
        if self.on_miss:
            self.on_miss(block)
