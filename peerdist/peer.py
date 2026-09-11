"""PeerDist peer implementation

We implement a simple peer capable of responding to discovery and
block retrieval requests, backed by an on-disk cache.
"""

import asyncio
from collections.abc import Buffer, Iterator, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from functools import singledispatchmethod
import http.client
import io
import os
from typing import assert_never, BinaryIO, ClassVar, TypeAlias

from . import pccrr
from .cache import Cache, CacheKey


class BadRetrievalRequest(Exception):
    """Bad retrieval protocol request"""


@dataclass(frozen=True)
class RetrievalBufferResponse:
    """Retrieval protocol response content as a buffer list"""

    buffers: Sequence[Buffer]
    """Response content"""

    @property
    def length(self) -> int:
        """Response content length"""
        return sum(memoryview(x).nbytes for x in self.buffers)

    def __bytes__(self) -> bytes:
        """Response content as raw bytes"""
        return b''.join(self.buffers)


@dataclass(frozen=True)
class RetrievalFileResponse:
    """Retrieval protocol response content as an opened file

    Responses may be represented as an opened file-like object to
    allow for the use of `sendfile`.
    """

    fh: BinaryIO
    """Response content as an opened file-like object"""

    length: int
    """Response content length"""

    def __bytes__(self) -> bytes:
        """Response content as raw bytes

        For maximum efficiency, use `sendfile` on the file-like object
        instead.
        """
        return self.fh.read()


RetrievalResponse: TypeAlias = RetrievalBufferResponse | RetrievalFileResponse
RetrievalResponseManager: TypeAlias = AbstractContextManager[RetrievalResponse]


@dataclass(frozen=True)
class RetrievalServer:
    """Retrieval protocol server

    The retrieval protocol server is fundamentally transport-agnostic:
    a raw HTTP POST request body can be passed to the `response`
    method to obtain the appropriate response body.

    The most efficient way to send the response body is to use
    `sendfile`, to avoid unnecessarily copying the cached block file
    through userspace.  Cached blocks are already encrypted and stored
    in the form of a raw HTTP response body, and the retrieval
    protocol operates over HTTP rather than HTTPS, so `sendfile` is a
    perfect match for this use case.

    To facilitate this, the `response` method acts as a context
    manager that yields either a `RetrievalBufferResponse`
    (representing a short response already in memory) or a
    `RetrievalFileResponse` (representing an opened read-only file
    handle).  The caller should `match` the returned type and then
    either transmit the buffers or call `sendfile` accordingly:

        try:
            rspmanager = retrieval_server.response(req)
        except peerdist.peer.BadRetrievalRequest:
            ... report client error ...
        with rspmanager as rsp:
            ... construct headers using rsp.length ...
            match rsp:
                case RetrievalBufferResponse(buffers=buffers):
                    ... transmit buffer content ...
                case RetrievalFileResponse(fh=fh):
                    ... use sendfile(..., fh) ...

    The file handle will be automatically closed on exit from the context.

    The `response` method is non-blocking and can therefore be used in
    any synchronous or asynchronous server framework.
    """

    cache: Cache
    """Underlying block replay cache"""

    def response(self, req: Buffer) -> RetrievalResponseManager:
        """Context manager for a response to a retrieval request

        Returns a context yielding a `RetrievalResponse` from which
        the response bytes may be read.
        """
        try:
            msg = pccrr.Request.from_bytes(req)
        except pccrr.DecodeError as exc:
            raise BadRetrievalRequest(str(exc)) from exc
        return self.msg(msg)

    @singledispatchmethod
    def msg(self, msg: pccrr.Request) -> RetrievalResponseManager:
        """Context manager for a response to a retrieval request

        Returns a context yielding a `RetrievalResponse` from which
        the response bytes may be read.
        """
        raise BadRetrievalRequest(
            "Unsupported request type %s" % type(msg).__name__
        )

    @msg.register
    def msg_getblks(self, msg: pccrr.MsgGetBlks) -> RetrievalResponseManager:
        """Context manager for a response to a MSG_GETBLKS request

        Returns a context yielding a `RetrievalResponse` from which
        the response bytes may be read.

        The `MSG_GETBLKS` format allows for multiple blocks to be
        requested, though the specification states that the requested
        block ranges list must specify a single block range containing
        only one block.
        """
        segment_id = msg.segment_id
        ranges = msg.req_block_ranges
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
    def cached(self, key: CacheKey) -> Iterator[RetrievalResponse]:
        """Context manager for a response representing a cache entry

        Returns a context yielding a `RetrievalResponse` from which
        the response bytes may be read.
        """
        with self.cache[key].reader() as fh:
            if fh is not None:
                length = os.fstat(fh.fileno()).st_size
                yield RetrievalFileResponse(fh=fh, length=length)
            else:
                missing = pccrr.MsgBlk(
                    crypto_alg_id=pccrr.CryptoAlgId.NONE,
                    segment_id=key.segment_id,
                    block_index=key.block_index,
                )
                buffers = missing.to_buffers()
                yield RetrievalBufferResponse(buffers=buffers)


@dataclass(frozen=True)
class StandaloneRetrievalServer(RetrievalServer):
    """Standalone retrieval protocol server

    If you are hosting the retrieval protocol server within a
    higher-level web framework such as aiohttp, Werkzeug, Flask, etc,
    then ignore this class and instead register a route for
    `pccrr.MAGIC_PATH` that calls `RetrievalServer.response` to obtain
    the response.
    """

    MAX_RETRIEVAL_REQUEST: ClassVar[int] = 65536
    """Maximum retrieval protocol request size (including headers)"""

    async def connected(
            self,
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter
    ) -> None:
        """Handle a standalone server connection

        This may be used as the `connected_cb` callback handler for
        use with `asyncio.start_server`.
        """
        try:
            while await self.respond(reader, writer):
                pass
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        finally:
            writer.close()

    async def respond(
            self,
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter
    ) -> bool:
        """Handle a standalone server request

        Returns `True` iff the connection may be kept alive.
        """
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except asyncio.LimitOverrunError:
            return False
        (start, _, rest) = head.partition(b"\r\n")
        try:
            (method, path, _) = start.decode().split()
        except (UnicodeDecodeError, ValueError):
            return False
        headers = http.client.parse_headers(io.BytesIO(rest))
        try:
            length = int(headers["Content-Length"])
        except (TypeError, ValueError):
            return await self.respond_error(writer, 411, b"Length Required")
        if not 0 <= length <= self.MAX_RETRIEVAL_REQUEST:
            return await self.respond_error(writer, 413, b"Payload Too Large")
        req = await reader.readexactly(length)
        if method != "POST" or path.lower() != pccrr.MAGIC_PATH.lower():
            return await self.respond_error(writer, 404, b"Not Found")
        try:
            rspmanager = self.response(req)
        except BadRetrievalRequest:
            return await self.respond_error(writer, 400, b"Bad Request")
        with rspmanager as rsp:
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: %d\r\n"
                b"Connection: keep-alive\r\n"
                b"\r\n"
                % rsp.length
            )
            match rsp:
                case RetrievalBufferResponse(buffers=buffers):
                    for buf in buffers:
                        writer.write(memoryview(buf))
                    await writer.drain()
                case RetrievalFileResponse(fh=fh):
                    await writer.drain()
                    loop = asyncio.get_running_loop()
                    await loop.sendfile(writer.transport, fh)
                case _:
                    assert_never(rsp)
        return True

    @staticmethod
    async def respond_error(writer: asyncio.StreamWriter, status: int,
                            reason: bytes) -> bool:
        """Send an HTTP error response and close the connection"""
        writer.write(
            b"HTTP/1.1 %d %s\r\n"
            b"Content-Length: 0\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            % ( status, reason )
        )
        await writer.drain()
        return False

    async def start_server(self, *args, **kwargs) -> asyncio.Server:
        """Start standalone server"""
        return await asyncio.start_server(self.connected, *args, **kwargs)
