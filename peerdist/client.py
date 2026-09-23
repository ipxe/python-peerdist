"""PeerDist client implementation"""

from dataclasses import dataclass
import http.client
import logging

from . import pccrr
from .cache import Cache


logger = logging.getLogger(__name__)


@dataclass
class RetrievalClient:
    """Retrieval protocol client"""

    cache: Cache
    """Underlying block replay cache"""

    def retrieve(self, segment_id: bytes, block_index: int,
                 host: str, port: int = 80) -> None:
        """Retrieve a block from another peer"""
        block = self.cache[segment_id][block_index]
        conn = http.client.HTTPConnection(host, port)
        ranges = [pccrr.Range(index=block_index, count=1)]
        req = pccrr.MsgGetBlks(segment_id=segment_id,
                               req_block_ranges=ranges)
        conn.request("POST", pccrr.MAGIC_PATH, body=bytes(req))
        rsp = pccrr.MsgBlk.from_bytes(conn.getresponse().read())
        block.msg = rsp
        logger.debug("%s: cached", block)
