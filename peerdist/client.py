"""PeerDist client implementation"""

from dataclasses import dataclass
import http.client
import logging

from . import pccrr
from .cache import Cache, CacheBlock

logger = logging.getLogger(__name__)


@dataclass
class RetrievalClient:
    """Retrieval protocol client"""

    cache: Cache
    """Underlying block replay cache"""

    def retrieve(self, block: CacheBlock, host: str, port: int = 80) -> None:
        """Retrieve a block from another peer"""
        conn = http.client.HTTPConnection(host, port)
        ranges = [pccrr.Range(index=block.block_index, count=1)]
        req = pccrr.MsgGetBlks(segment_id=block.segment_id,
                               req_block_ranges=ranges)
        conn.request("POST", pccrr.MAGIC_PATH, body=bytes(req))
        rsp = pccrr.MsgBlk.from_bytes(conn.getresponse().read())
        block.msg = rsp
        logger.debug("%s: cached", block)
