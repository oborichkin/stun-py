import struct
from enum import IntEnum
from dataclasses import dataclass

MAGIC_COOKIE = 0x2112A442

class MessageType(IntEnum):
    REQUEST = 0b00
    INDICATION = 0b01
    SUCCESS_RESPONSE = 0b10
    ERROR_RESPONSE = 0b11

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
    typ: MessageType
    method: MessageMethod
    length: int
    transaction_id: bytes

    #             0                 1
    #     2  3  4 5 6 7 8 9 0 1 2 3 4 5
    #    +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
    #    |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
    #    |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
    #    +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
    @property
    def message_type(self) -> MessageType:
        return (
                0xF   & self.method        # M0-M3
             | (0x1   & self.typ)    << 4  # C0
             | (0x70  & self.method) << 1  # M4-M6
             | (0x2   & self.typ)    << 7  # C1
             | (0xf80 & self.method) << 2  # M7-M11
        )

    #        0                   1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |0 0|     STUN Message Type     |         Message Length        |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                         Magic Cookie                          |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |                                                               |
    #   |                     Transaction ID (96 bits)                  |
    #   |                                                               |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    def to_bytes(self):
        return struct.pack("!HHI12s", self.message_type, self.length, MAGIC_COOKIE, self.transaction_id.to_bytes(12))

    @staticmethod
    def from_bytes(data: bytes):
        assert len(data) == 20, "STUN header must be 20 bytes"
        mt, length, _, tid = struct.unpack("!HHI12s", data)
        return StunHeader(*StunHeader.parse_message_type(mt), length, int.from_bytes(tid, "big"))

    @staticmethod
    def parse_message_type(data: bytes):
        match data & 0x0110:
            case 0x0000:
                typ = MessageType.REQUEST
            case 0x0010:
                typ = MessageType.INDICATION
            case 0x0100:
                typ = MessageType.SUCCESS_RESPONSE
            case 0x0110:
                typ = MessageType.ERROR_RESPONSE
        method = MessageMethod(data & 0x0F)
        return typ, method


@dataclass
class StunMessage:
    header: StunHeader
    attributes: list
