import struct
import hmac as hmac_module
import hashlib
import zlib
from enum import IntEnum
from dataclasses import dataclass
from stunpy.common import MAGIC_COOKIE
from stunpy.attributes import *

class MessageMethod(IntEnum):
    BINDING = 0x0001
    ALLOCATE = 0x0003
    REFRESH = 0x0004
    SEND = 0x0006
    DATA = 0x0007
    CREATE_PERMISSION = 0x0008
    CHANNEL_BIND = 0x0009


@dataclass
class StunHeader:
    message_type: int
    length: int
    transaction_id: bytes

    @property
    def method(self) -> MessageMethod:
        return MessageMethod(self.message_type & 0x000F)

    def __bytes__(self):
        return struct.pack("!HHI12s", self.message_type, self.length, MAGIC_COOKIE, self.transaction_id.to_bytes(12))

    @staticmethod
    def from_bytes(data: bytes):
        assert len(data) >= 20, "STUN header must be 20 bytes"
        mt, length, _, tid = struct.unpack("!HHI12s", data[:20])
        return StunHeader(mt, length, int.from_bytes(tid, "big")), data[20:]



@dataclass
class StunMessage:
    header: StunHeader
    attributes: list

    @staticmethod
    def from_bytes(data: bytes):
        header, data = StunHeader.from_bytes(data)
        assert len(data) >= header.length, "STUN message is too short"
        attributes_data = data[:header.length]
        attributes = []
        while attributes_data:
            type, length = struct.unpack("!HH", attributes_data[:4])
            if type == StunAttributeType.MAPPED_ADDRESS:
                attr, attributes_data = MappedAddress.from_bytes(attributes_data[4:])
            elif type == StunAttributeType.USERNAME:
                attr, attributes_data = Username.from_bytes(attributes_data[4:], length)
            elif type == StunAttributeType.MESSAGE_INTEGRITY:
                attr, attributes_data = MessageIntegrity.from_bytes(attributes_data[4:])
            elif type == StunAttributeType.ERROR_CODE:
                attr, attributes_data = ErrorCode.from_bytes(attributes_data[4:], length)
            elif type == StunAttributeType.UNKNOWN_ATTRIBUTES:
                attr, attributes_data = UnknownAttributes.from_bytes(attributes_data, length)
            elif type == StunAttributeType.SOFTWARE:
                attr, attributes_data = Software.from_bytes(attributes_data[4:])
            elif type == StunAttributeType.ALTERNATE_SERVER:
                attr, attributes_data = AlternateServer.from_bytes(attributes_data[4:])
            elif type == StunAttributeType.FINGERPRINT:
                attr, attributes_data = Fingerprint.from_bytes(attributes_data[4:])
            else:
                attr, attributes_data = StunAttribute.from_bytes(attributes_data)
            attributes.append(attr)
        return StunMessage(header, attributes), data[header.length:]

    def add_message_integrity(self, key: bytes):
        self.header.length += 20
        hmac = hmac_module.new(key, digestmod=hashlib.sha1)
        hmac.update(bytes(self.header))
        for attr in self.attributes:
            hmac.update(bytes(attr))
        self.attributes.append(MessageIntegrity(hmac.digest()))

    def add_fingerprint(self):
        self.header.length += 4
        crc32 = zlib.crc32(bytes(self.header))
        for attr in self.attributes:
            crc32 = zlib.crc32(bytes(attr), crc32)
        self.attributes.append(Fingerprint(crc32))


def make_long_term_key(username: str, password: str, realm: str) -> bytes:
    # TODO: Implement SASLprep
    return hashlib.md5(f"{username}:{realm}:{password}".encode("utf-8")).digest()
