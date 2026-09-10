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
from pathlib import Path
import tempfile
from typing import cast, BinaryIO


SUFFIX = ".blk"
"""Filename suffix"""

CacheKey = tuple[bytes, int]
"""Cache key (segment ID and block index)"""


@dataclass
class Cache(Mapping[CacheKey, Path]):
    """Block replay cache"""

    path: Path
    """Cache directory"""

    def __post_init__(self) -> None:
        self.path = Path(self.path)

    @classmethod
    def cachekey(cls, filename: str) -> CacheKey | None:
        """Construct cache key from cached block file name"""
        stem = filename.removesuffix(SUFFIX)
        if stem == filename:
            return None
        (segment_id_hex, sep, block_index) = stem.rpartition('-')
        if not sep:
            return None
        try:
            key = (bytes.fromhex(segment_id_hex), int(block_index))
        except ValueError:
            return None
        return key if cls.filename(key) == filename else None

    @staticmethod
    def filename(key: CacheKey) -> str:
        """Construct cached block file name from cache key"""
        segment_id_hex = key[0].hex()
        if not segment_id_hex:
            raise KeyError(key)
        block_index = int(key[1])
        if block_index < 0:
            raise KeyError(key)
        return "%s-%d%s" % (segment_id_hex, block_index, SUFFIX)

    def filepath(self, key: CacheKey) -> Path:
        """Construct cached block file path from cache key"""
        filename = self.filename(key)
        return self.path / filename[0:2] / filename

    def __getitem__(self, key: CacheKey) -> Path:
        """Get cached block file (if present in the cache)"""
        path = self.filepath(key)
        if not path.exists():
            raise KeyError(key)
        return path

    @contextmanager
    def create(self, key: CacheKey) -> Iterator[BinaryIO]:
        """Context manager for creating a cached block file"""
        path = self.filepath(key)
        subdir = path.parent
        subdir.mkdir(exist_ok=True)
        with tempfile.NamedTemporaryFile(
                dir=subdir,
                prefix=".%s." % path.name,
                delete_on_close=False,
        ) as tmp:
            yield cast(BinaryIO, tmp)
            tmp.flush()
            Path(tmp.name).replace(path)

    def __len__(self) -> int:
        """Count cached block files"""
        return sum(1 for _ in self)

    def __iter__(self) -> Iterator[CacheKey]:
        """Iterate over all cached block files"""
        for path in self.path.glob("*/*%s" % SUFFIX):
            key = self.cachekey(path.name)
            if key is not None:
                yield key

    def blocks(self, segment_id: bytes) -> Iterator[CacheKey]:
        """Iterate over all cached block files within a segment"""
        path = self.filepath((segment_id, 0))
        glob = path.name.replace("-0", "-*") # "xxxxxxxx-0.blk"
        for path in path.parent.glob(glob):
            key = self.cachekey(path.name)
            if key is not None and key[0] == segment_id:
                yield key
