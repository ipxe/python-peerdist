"""Peer Content Caching and Retrieval: Discovery Protocol [MS-PCCRD]

The Discovery Protocol is used for discovery of peers that hold
particular encrypted blocks.  It is based upon the Web Service Dynamic
Discovery Protocol (WSD), which in turn uses SOAP-over-UDP.

Note that some receivers (e.g. iPXE) do not include full XML parsers
but instead use substring matching.  Such receivers may rely upon the
specific choices for namespace prefixes, and may not correctly handle
otherwise valid messages (e.g. self-closing XML tags).
"""

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import cast, ClassVar
import uuid
from xml.etree import ElementTree as ET


DEFAULT_ADDRESS = uuid.uuid4()
"""Per-endpoint unique identifier"""


PEERDIST_PREFIX = "PeerDist"
PEERDIST = "http://schemas.microsoft.com/p2p/2007/09/PeerDistributionDiscovery"
SOAP = "http://www.w3.org/2003/05/soap-envelope"
WSA = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
WSD = "http://schemas.xmlsoap.org/ws/2005/04/discovery"
XMLNS = {
    PEERDIST_PREFIX: PEERDIST,
    "soap": SOAP,
    "wsa": WSA,
    "wsd": WSD,
}


def _register_namespaces(xmlns: Mapping[str, str]) -> None:
    for prefix, uri in xmlns.items():
        ET.register_namespace(prefix, uri)


_register_namespaces(XMLNS)


@dataclass(frozen=True)
class XAddr:

    host: str
    """Host address"""

    port: int
    """Port number"""


@dataclass(kw_only=True)
class Message(ABC):
    """A discovery message"""

    WSA_TO: ClassVar[str]
    """Web Services Addressing destination"""

    WSA_ACTION: ClassVar[str]
    """Web Services Addressing action"""

    PEERDIST_TYPE: ClassVar[str]
    """PeerDist data type"""

    MATCH_BY: ClassVar[str]
    """Scope matching rule"""

    METADATA_VERSION: ClassVar[int]
    """Metadata version"""

    message_id: uuid.UUID = field(default_factory=uuid.uuid4)
    """Message ID"""

    segment_ids: Sequence[bytes] = field(default_factory=list)
    """Segment identifiers"""

    def __bytes__(self) -> bytes:
        root = self.envelope
        encoded = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        return cast(bytes, encoded)

    def __str__(self) -> str:
        return bytes(self).decode()

    @property
    def tree(self) -> ET.ElementTree:
        """Message represented as an XML element tree"""
        tree = ET.ElementTree(self.envelope)
        return tree

    @property
    def envelope(self) -> ET.Element:
        """SOAP envelope"""
        envelope = ET.Element(f"{{{SOAP}}}Envelope")
        envelope.append(self.header)
        envelope.append(self.body)
        return envelope

    @property
    def header(self) -> ET.Element:
        """SOAP header"""
        header = ET.Element(f"{{{SOAP}}}Header")
        to = ET.SubElement(header, f"{{{WSA}}}To")
        to.text = self.WSA_TO
        action = ET.SubElement(header, f"{{{WSA}}}Action")
        action.text = self.WSA_ACTION
        message_id = ET.SubElement(header, f"{{{WSA}}}MessageID")
        message_id.text = self.message_id.urn
        return header

    @property
    def body(self) -> ET.Element:
        """SOAP body"""
        body = ET.Element(f"{{{SOAP}}}Body")
        return body

    @property
    @abstractmethod
    def scopes(self) -> str:
        """Scopes to be matched"""


@dataclass(kw_only=True)
class Probe(Message):
    """A probe request"""

    WSA_TO = "urn:schemas-xmlsoap-org:ws:2005:04:discovery"
    WSA_ACTION = "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe"

    @property
    def envelope(self) -> ET.Element:
        envelope = super().envelope
        envelope.set("xmlns:%s" % PEERDIST_PREFIX, PEERDIST)
        return envelope

    @property
    def body(self) -> ET.Element:
        body = super().body
        probe = ET.SubElement(body, f"{{{WSD}}}Probe")
        types = ET.SubElement(probe, f"{{{WSD}}}Types")
        types.text = "%s:%s" % (PEERDIST_PREFIX, self.PEERDIST_TYPE)
        scopes = ET.SubElement(probe, f"{{{WSD}}}Scopes")
        scopes.set("MatchBy", self.MATCH_BY)
        scopes.text = self.scopes
        return body


@dataclass(kw_only=True)
class ProbeMatch(Message):
    """A probe match response"""

    WSA_TO = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
    WSA_ACTION = "http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches"

    PEERDIST_TYPE: ClassVar[str]
    """PeerDist data type"""

    relates_to: uuid.UUID
    """Request message ID"""

    instance_id: int
    """Instance ID"""

    message_number: int
    """Message number"""

    address: uuid.UUID = field(default=DEFAULT_ADDRESS)
    """Endpoint address"""

    xaddrs: Sequence[XAddr] = field(default_factory=list)
    """Discovered addresses"""

    @property
    def header(self) -> ET.Element:
        header = super().header
        relates_to = ET.SubElement(header, f"{{{WSA}}}RelatesTo")
        relates_to.text = self.relates_to.urn
        app_sequence = ET.SubElement(header, f"{{{WSA}}}AppSequence")
        app_sequence.set("InstanceId", str(self.instance_id))
        app_sequence.set("MessageNumber", str(self.message_number))
        return header

    @property
    def body(self) -> ET.Element:
        body = super().body
        probe_matches = ET.SubElement(body, f"{{{WSD}}}ProbeMatches")
        probe_match = ET.SubElement(probe_matches, f"{{{WSD}}}ProbeMatch")
        endpoint_reference = ET.SubElement(probe_match,
                                           f"{{{WSA}}}EndpointReference")
        address = ET.SubElement(endpoint_reference, f"{{{WSA}}}Address")
        address.text = self.address.urn
        types = ET.SubElement(probe_match, f"{{{WSD}}}Types")
        types.text = "%s:%s" % (PEERDIST_PREFIX, self.PEERDIST_TYPE)
        scopes = ET.SubElement(probe_match, f"{{{WSD}}}Scopes")
        scopes.text = self.scopes
        xaddrs = ET.SubElement(probe_match, f"{{{WSD}}}XAddrs")
        xaddrs.text = " ".join("%s:%d" % (x.host, x.port) for x in self.xaddrs)
        metadata_version = ET.SubElement(probe_match,
                                         f"{{{WSD}}}MetadataVersion")
        metadata_version.text = str(self.METADATA_VERSION)
        probe_match.append(self.peerdist_data)
        return body

    @property
    @abstractmethod
    def peerdist_data(self) -> ET.Element:
        """PeerDist-specific data element"""


@dataclass(kw_only=True)
class MessageV1(Message):
    """A version 1.0 message"""

    PEERDIST_TYPE = "PeerDistData"
    MATCH_BY = "http://schemas.xmlsoap.org/ws/2005/04/discovery/strcmp0"
    METADATA_VERSION = 1

    @property
    def scopes(self) -> str:
        return " ".join(x.hex().upper() for x in self.segment_ids)


@dataclass(kw_only=True)
class ProbeV1(Probe, MessageV1):
    """A version 1.0 probe request"""


@dataclass(kw_only=True)
class ProbeMatchV1(ProbeMatch, MessageV1):
    """A version 1.0 probe match response"""

    block_counts: Sequence[int] = field(default_factory=list)
    """Block counts"""

    @property
    def peerdist_data(self) -> ET.Element:
        peerdist_data = ET.Element(f"{{{PEERDIST}}}PeerDistData")
        block_count = ET.SubElement(peerdist_data, f"{{{PEERDIST}}}BlockCount")
        block_count.text = "".join("%08X" % x for x in self.block_counts)
        return peerdist_data


@dataclass(kw_only=True)
class MessageV2(Message):
    """A version 2.0 message"""

    PEERDIST_TYPE = "PeerDistDataV2"
    MATCH_BY = \
        "http://schemas.microsoft.com/p2p/2010/05/PeerDistV2MatchingRule"
    METADATA_VERSION = 2
