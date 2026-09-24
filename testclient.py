#!/usr/bin/env python3

import argparse
import logging

from peerdist.cache import Cache
from peerdist.client import RetrievalClient

logging.basicConfig(level=logging.DEBUG)

cache = Cache("/tmp/peerdist-cache")
client = RetrievalClient(cache)

parser = argparse.ArgumentParser(description="Retrieve block")
parser.add_argument("segment_id", type=bytes.fromhex)
parser.add_argument("block_index", type=int, default=0)
args = parser.parse_args()

block = cache[args.segment_id][args.block_index]
client.retrieve(block, host="hedgehog", port=80)
