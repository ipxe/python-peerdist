"""PeerDist peer implementation

We implement a simple peer capable of responding to discovery and
block retrieval requests, backed by an on-disk cache.
"""

from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from functools import singledispatchmethod
import io
from typing import BinaryIO

from . import pccrr
from . import cache


class BadRetrievalRequest(Exception):
    """Bad cache retrieval request"""


@dataclass
class Server:
    """Peer server"""

    cache: cache.Cache
    """Underlying block replay cache"""

    @singledispatchmethod
    def respond(
            self,
            req: pccrr.Request | bytes,
    ) -> AbstractContextManager[BinaryIO]:
        """Context manager for responding to a request

        Returns a context yielding a file handle from which the
        response bytes may be read.
        """
        raise BadRetrievalRequest("Unsupported request type")

    @respond.register
    def post(self, req: bytes) -> AbstractContextManager[BinaryIO]:
        """Context manager for responding to a raw HTTP POST

        Returns a context yielding a file handle from which the
        response bytes may be read.
        """
        try:
            msg = pccrr.Request.from_bytes(req)
        except pccrr.DecodeError as exc:
            raise BadRetrievalRequest(str(exc)) from exc
        return self.respond(msg)

    @respond.register
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
            key = cache.CacheKey(segment_id, block_index)
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
