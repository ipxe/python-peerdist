#!/usr/bin/env python3

import asyncio
import logging

from peerdist.cache import Cache, CacheBlock, CacheResponse
from peerdist.peer import StandaloneRetrievalServer
from peerdist.client import RetrievalClient

logging.basicConfig(level=logging.DEBUG)

def cache_miss(rsp: CacheResponse) -> None:
    """Handle cache miss"""
    client = RetrievalClient(cache)
    match rsp:
        case CacheBlock(segment_id=segment_id, block_index=block_index):
            client.retrieve(segment_id, block_index, key, 'hedgehog')


cache = Cache("/tmp/peerdist-cache", on_miss=cache_miss)
server = StandaloneRetrievalServer(cache)


async def main():
    running = await server.start_server(None, 8080)
    print(running.sockets)
    print("Serving on %s" %
          ",".join(str(x.getsockname()) for x in running.sockets))
    await running.serve_forever()

asyncio.run(main())
