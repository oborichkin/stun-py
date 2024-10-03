import struct
from enum import IntEnum
from dataclasses import dataclass

MAGIC_COOKIE = 0x2112A442

TYPE_REQ = 0x0000
TYPE_IND = 0x0010
TYPE_SUC = 0x0100
TYPE_ERR = 0x0110


class MessageMethod(IntEnum):
    BINDING = 0x0001
    ALLOCATE = 0x0003
    REFRESH = 0x0004
    SEND = 0x0006
    DATA = 0x0007
    CREATE_PERMISSION = 0x0008
    CHANNEL_BIND = 0x0009


is_request          = lambda msg_type: msg_type & 0x0110 == 0x0000
is_indication       = lambda msg_type: msg_type & 0x0110 == 0x0010
is_success_response = lambda msg_type: msg_type & 0x0110 == 0x0100
is_error_response   = lambda msg_type: msg_type & 0x0110 == 0x0110


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


class StunAttributeType(IntEnum):
    MAPPED_ADDRESS = 0x0001
    USERNAME = 0x0006
    MESSAGE_INTEGRITY = 0x0008
    ERROR_CODE = 0x0009
    UNKNOWN_ATTRIBUTES = 0x000A
    REFRESH_INTERVAL = 0x000B
    REQUESTED_TRANSPORT = 0x0019
    SOFTWARE = 0x8022
    ALTERNATE_SERVER = 0x8023


@dataclass
class StunAttribute:
    type: StunAttributeType
    value: bytes

    def __bytes__(self):
        return struct.pack("!HH", self.type, len(self.value)) + self.value

    @staticmethod
    def from_bytes(data: bytes):
        type, length = struct.unpack("!HH", data[:4])
        return StunAttribute(type, data[4:4+length]), data[4+length:]


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
            attr, attributes_data = StunAttribute.from_bytes(attributes_data)
            attributes.append(attr)
        return StunMessage(header, attributes), data[header.length:]
