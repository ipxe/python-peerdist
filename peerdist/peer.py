"""PeerDist peer implementation

We implement a simple peer capable of responding to discovery and
block retrieval requests, backed by an on-disk cache.
"""

from collections.abc import Buffer, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from functools import singledispatchmethod
import io
from typing import BinaryIO

from . import pccrr
from .cache import Cache, CacheKey


RetrievalServerResponse = AbstractContextManager[BinaryIO]


class BadRetrievalRequest(Exception):
    """Bad cache retrieval request"""


@dataclass(frozen=True)
class RetrievalServer:
    """Retrieval protocol server"""

    cache: Cache
    """Underlying block replay cache"""

    def respond(self, body: Buffer) -> RetrievalServerResponse:
        """Context manager for responding to a raw HTTP POST body

        Returns a context yielding a file-like object from which the
        response bytes may be read.
        """
        try:
            req = pccrr.Request.from_bytes(body)
        except pccrr.DecodeError as exc:
            raise BadRetrievalRequest(str(exc)) from exc
        return self.msg(req)

    @singledispatchmethod
    def msg(self, req: pccrr.Request) -> RetrievalServerResponse:
        """Context manager for responding to a retrieval protocol message

        Returns a context yielding a file-like object from which the
        response bytes may be read.
        """
        raise TypeError("Unsupported request type %s" % type(req).__name__)

    @msg.register
    def msg_getblks(self, req: pccrr.MsgGetBlks) -> RetrievalServerResponse:
        """Context manager for responding to a MSG_GETBLKS request

        Returns a context yielding a file-like object from which the
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
        return self.cached(key)

    @contextmanager
    def cached(self, key: CacheKey) -> Iterator[BinaryIO]:
        """Context manager for returning a cache entry

        Returns a context yielding a file-like object from which the
        response bytes may be read.
        """
        with self.cache[key].reader() as fh:
            if fh is not None:
                yield fh
            else:
                missing = pccrr.MsgBlk(
                    crypto_alg_id=pccrr.CryptoAlgId.NONE,
                    segment_id=key.segment_id,
                    block_index=key.block_index,
                )
                yield io.BytesIO(missing.to_bytes())
