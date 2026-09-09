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

  * `b` is the block number within the segment (which will always be
    zero when using MS-PCCRC version 2 content information), as an
    unpadded decimal string.

Each block file, if present, contains the raw byte serialization of a
`MSG_BLK` response message for that segment ID and block number.

The content of each block is encrypted with the cipher specified
within its `MSG_BLK` message header (typically AES-128-CBC).  The
decryption key may not be known to the cache.  Blocks may not
necessarily all by encrypted with the same cipher.

This on-disk layout and format is designed to allow for at least two
use cases:

  * A replay server may respond to `MSG_GETBLKS` request messages by
    simply parsing the segment ID and block number from the request
    and then sending back the corresponding block file unmodified.
    The block file is already a valid `MSG_BLK` response message.

  * A client with access to the cache directory (e.g. iPXE with the
    cache directory held in a FAT filesystem) may retrieve blocks from
    the cache rather than from a network peer.

"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


CacheKey = tuple[bytes, int]


@dataclass
class Cache(Mapping[CacheKey, Path]):
    """Block replay cache"""

    path: Path
    """Cache directory"""

    def __post_init__(self) -> None:
        self.path = Path(self.path)

    def __getitem__(self, key: CacheKey) -> Path:
        filename = "%s-%d.blk" % (key[0].hex(), key[1])
        dirname = filename[0:2]
        path = self.path / dirname / filename
        if not path.exists():
            raise KeyError
        return path

    def blocks(self, segment_id: bytes) -> Sequence[int]:
        """Get cached block numbers within a given segment"""
        prefix = "%s-" % segment_id.hex()
        fileglob = "%s*.blk" % prefix
        dirname = fileglob[0:2]
        subdir = self.path / dirname
        blocks = [x.stem.removeprefix(prefix) for x in subdir.glob(fileglob)]
        return sorted(int(x) for x in blocks if x.isdigit())

    def create(self, key: CacheKey) -> Path:
        """Create cache entry"""
        filename = "%s-%d.blk" % (key[0].hex(), key[1])
        dirname = filename[0:2]
        subdir = self.path / dirname
        subdir.mkdir(exist_ok=True)
        path = subdir / filename
        return path
