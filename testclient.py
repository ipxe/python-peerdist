#!/usr/bin/env python3

import argparse
import logging

from peerdist.cache import Cache, CacheKey
from peerdist.peer import RetrievalClient

logging.basicConfig(level=logging.DEBUG)

cache = Cache("/tmp/peerdist-cache")
client = RetrievalClient(cache)

parser = argparse.ArgumentParser(description="Retrieve block")
parser.add_argument("segment_id")
args = parser.parse_args()

key = CacheKey(segment_id=bytes.fromhex(args.segment_id))
client.retrieve(key=key, host="hedgehog", port=80)
