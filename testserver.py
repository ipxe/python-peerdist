#!/usr/bin/env python3

import asyncio
import logging

from peerdist.cache import Cache, CacheBlock
from peerdist.peer import StandaloneRetrievalServer
from peerdist.client import RetrievalClient

logging.basicConfig(level=logging.DEBUG)


def cache_miss(block: CacheBlock) -> None:
    """Handle cache miss"""
    client = RetrievalClient(cache)
    client.retrieve(block, 'hedgehog')


cache = Cache("/tmp/peerdist-cache", on_miss=cache_miss)
server = StandaloneRetrievalServer(cache)


async def main() -> None:
    running = await server.start_server(None, 8080)
    print(running.sockets)
    print("Serving on %s" %
          ",".join(str(x.getsockname()) for x in running.sockets))
    await running.serve_forever()

asyncio.run(main())
