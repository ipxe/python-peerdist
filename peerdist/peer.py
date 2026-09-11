"""PeerDist peer implementation

We implement a simple peer capable of responding to discovery and
block retrieval requests, backed by an on-disk cache.
"""

import asyncio
from collections.abc import Buffer, Iterator, Sequence
from contextlib import AbstractContextManager, contextmanager, ExitStack
from contextvars import ContextVar
from dataclasses import dataclass, field, InitVar
import email.policy
from functools import singledispatchmethod
import http
import http.client
import io
import logging
import os
from typing import Any, assert_never, BinaryIO, ClassVar, TypeAlias

from . import pccrr
from .cache import Cache, CacheKey


ctx_peername: ContextVar[Any] = ContextVar("peername", default=None)


class LogFilter(logging.Filter):
    """Log message filter"""

    def filter(self, record: logging.LogRecord) -> bool:
        """Add current peer name to log record name (if applicable)"""
        peername = ctx_peername.get()
        if peername is not None:
            if isinstance(peername, tuple):
                record.name = "%s[%s]" % (record.name, peername[0])
        return True


logger = logging.getLogger(__name__)
logger.addFilter(LogFilter())


class HttpError(Exception):
    """HTTP error response"""

    def __init__(self, status: http.HTTPStatus) -> None:
        super().__init__(status.phrase)
        self.status = status


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


@dataclass
class RetrievalServer:
    """Retrieval protocol server

    The retrieval protocol server is fundamentally transport-agnostic:
    a raw HTTP POST request body can be passed to the `respond` method
    to obtain the appropriate response body.

    The most efficient way to send the response body is to use
    `sendfile`, to avoid unnecessarily copying the cached block file
    through userspace.  Cached blocks are already encrypted and stored
    in the form of a raw HTTP response body, and the retrieval
    protocol operates over HTTP rather than HTTPS, so `sendfile` is a
    perfect match for this use case.

    To facilitate this, the `respond` method acts as a context manager
    that yields either a `RetrievalBufferResponse` (representing a
    short response already in memory) or a `RetrievalFileResponse`
    (representing an opened read-only file handle).  The caller should
    `match` the returned type and then either transmit the buffers or
    call `sendfile` accordingly:

        try:
            rspmanager = retrieval_server.respond(req)
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

    The `respond` method is non-blocking and can therefore be used in
    any synchronous or asynchronous server framework.

    The `respond` method is a convenience wrapper that calls the
    `request` method to parse the raw HTTP post request body into a
    message, and then passes that to the `response` method to obtain
    the context manager.  The caller may choose to call `request` and
    `response` separately in order to gain access to the parsed
    request message (e.g. for request logging).
    """

    cache: Cache
    """Underlying block replay cache"""

    def respond(self, req: Buffer) -> RetrievalResponseManager:
        """Context manager for a response to a retrieval request

        Returns a context yielding a `RetrievalResponse` from which
        the response bytes may be read.
        """
        msg = self.request(req)
        return self.response(msg)

    def request(self, req: Buffer) -> pccrr.Request:
        """Parse request content"""
        try:
            msg = pccrr.Request.from_bytes(req)
        except pccrr.DecodeError as exc:
            raise BadRetrievalRequest(str(exc)) from exc
        return msg

    @singledispatchmethod
    def response(self, msg: pccrr.Request) -> RetrievalResponseManager:
        """Context manager for a response to a retrieval request

        Returns a context yielding a `RetrievalResponse` from which
        the response bytes may be read.
        """
        raise BadRetrievalRequest(
            "Unsupported request type %s" % type(msg).__name__
        )

    @response.register
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
                logger.debug("%s: found", key)
                length = os.fstat(fh.fileno()).st_size
                yield RetrievalFileResponse(fh=fh, length=length)
            else:
                logger.debug("%s: not found", key)
                missing = pccrr.MsgBlk(
                    crypto_alg_id=pccrr.CryptoAlgId.NONE,
                    segment_id=key.segment_id,
                    block_index=key.block_index,
                )
                buffers = missing.to_buffers()
                yield RetrievalBufferResponse(buffers=buffers)


@dataclass
class StandaloneRetrievalServer:
    """Standalone retrieval protocol server

    If you are hosting the retrieval protocol server within a
    higher-level web framework such as aiohttp, Werkzeug, Flask, etc,
    then ignore this class and instead register a route for
    `pccrr.MAGIC_PATH` that calls `RetrievalServer.respond` to obtain
    the response.
    """

    cache: InitVar[Cache]
    """Underlying block replay cache"""

    server: RetrievalServer = field(init=False)
    """Transport-agnostic retrieval protocol server"""

    MAX_REQUEST_LEN: ClassVar[int] = 65536
    """Maximum retrieval protocol request size"""

    IDLE_TIMEOUT: ClassVar[float] = 60
    """Maximum time to wait for a request on an otherwise idle connection"""

    REQUEST_TIMEOUT: ClassVar[float] = 10
    """Maximum time to wait for a request in progress"""

    def __post_init__(self, cache: Cache) -> None:
        self.server = RetrievalServer(cache)

    async def connected(
            self,
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter
    ) -> None:
        """Handle a standalone server connection

        This may be used as the `connected_cb` callback handler for
        use with `asyncio.start_server`.
        """
        ctx_peername.set(writer.get_extra_info("peername"))
        try:
            logger.debug("connected")
            while await self.handle(reader, writer):
                pass
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()
            logger.debug("disconnected")

    async def handle(
            self,
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter
    ) -> bool:
        """Handle a standalone server request

        Returns `True` iff the connection may be kept alive.
        """
        # Prepare response headers
        rspheaders = http.client.HTTPMessage(policy=email.policy.HTTP)
        # Receive request
        try:
            # Read until end of headers
            async with asyncio.timeout(self.IDLE_TIMEOUT):
                first = await reader.readexactly(1)
            async with asyncio.timeout(self.REQUEST_TIMEOUT):
                head = first + await reader.readuntil(b"\r\n\r\n")
                # Parse request line
                (start, _, rest) = head.partition(b"\r\n")
                try:
                    (method, path, _) = start.decode().split()
                except (UnicodeDecodeError, ValueError):
                    raise HttpError(http.HTTPStatus.BAD_REQUEST) from None
                # Parse request headers and body
                reqheaders = http.client.parse_headers(io.BytesIO(rest))
                try:
                    length = int(reqheaders["Content-Length"])
                except (TypeError, ValueError):
                    raise HttpError(http.HTTPStatus.LENGTH_REQUIRED) from None
                if not 0 <= length <= self.MAX_REQUEST_LEN:
                    raise HttpError(http.HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                req = await reader.readexactly(length)
                # Check request parameters
                if path.lower() != pccrr.MAGIC_PATH.lower():
                    raise HttpError(http.HTTPStatus.NOT_FOUND)
                if method != "POST":
                    rspheaders["Allow"] = "POST"
                    raise HttpError(http.HTTPStatus.METHOD_NOT_ALLOWED)
        except asyncio.LimitOverrunError:
            status = http.HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE
            return await self.error(writer, status, rspheaders)
        except TimeoutError:
            status = http.HTTPStatus.REQUEST_TIMEOUT
            return await self.error(writer, status, rspheaders)
        except HttpError as exc:
            return await self.error(writer, exc.status, rspheaders)
        # Parse request and send response
        with ExitStack() as stack:
            # Generate response
            try:
                rsp = stack.enter_context(self.server.respond(req))
            except BadRetrievalRequest:
                status = http.HTTPStatus.BAD_REQUEST
                return await self.error(writer, status, rspheaders)
            except Exception:
                logger.exception("Could not construct retrieval response")
                status = http.HTTPStatus.INTERNAL_SERVER_ERROR
                return await self.error(writer, status, rspheaders)
            # Send response
            rspheaders["Content-Length"] = str(rsp.length)
            rspheaders["Connection"] = "keep-alive"
            writer.write(b"HTTP/1.1 200 OK\r\n" + bytes(rspheaders))
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
    async def error(writer: asyncio.StreamWriter,
                    status: http.HTTPStatus,
                    headers: http.client.HTTPMessage) -> bool:
        """Send an HTTP error response"""
        headers["Content-Length"] = "0"
        headers["Connection"] = "close"
        writer.write(
            b"HTTP/1.1 %d %s\r\n%s" %
            (status.value, status.phrase.encode(), bytes(headers))
        )
        await writer.drain()
        return False

    async def start_server(self, *args: Any, **kwargs: Any) -> asyncio.Server:
        """Start standalone server"""
        return await asyncio.start_server(self.connected, *args, **kwargs)
