import struct
import socket
import ipaddress
import hmac as hmac_module
import hashlib
import zlib
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


def _padding_length(length: int) -> int:
    return [0, 3, 2, 1][length % 4]


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
    FINGERPRINT = 0x8028

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


class AddressFamily(IntEnum):
    IPv4 = 0x01
    IPv6 = 0x02


ADDRESS_FAMILY_TO_AF = {
    AddressFamily.IPv4: socket.AF_INET,
    AddressFamily.IPv6: socket.AF_INET6,
}


@dataclass
class MappedAddress:
    address_family: AddressFamily
    port: int
    address: str

    def __bytes__(self):
        return struct.pack("!HH", self.address_family, self.port) + socket.inet_pton(ADDRESS_FAMILY_TO_AF[self.address_family], self.address)

    @classmethod
    def from_bytes(cls, data: bytes):
        address_family, port = struct.unpack("!HH", data[:4])
        address = socket.inet_ntop(ADDRESS_FAMILY_TO_AF[address_family], data[4:])
        return cls(address_family, port, address), data[20:]


@dataclass
class XorMappedAddress:
    address_family: AddressFamily
    port: int
    address: str

    def __bytes__(self):
        return struct.pack("!HH", self.address_family, self.port ^ MAGIC_COOKIE >> 16) + \
            ipaddress.ip_address(int(ipaddress.ip_address(self.address)) ^ MAGIC_COOKIE).packed

    @staticmethod
    def from_bytes(data: bytes):
        address_family, port = struct.unpack("!HH", data[:4])
        port = port ^ MAGIC_COOKIE >> 16
        address = str(ipaddress.ip_address(int.from_bytes(data[4:], 'big') ^ MAGIC_COOKIE))
        return XorMappedAddress(address_family, port, address), data[20:]


@dataclass
class Username:
    username: str

    def __bytes__(self):
        encoded = self.username.encode("utf-8")
        padding = b'\x00' * _padding_length(len(encoded))
        return encoded + padding

    @staticmethod
    def from_bytes(data: bytes, length: int):
        padding_length = _padding_length(length)
        return Username(data[:length].decode("utf-8")), data[length+padding_length:]


@dataclass
class MessageIntegrity:
    hmac: bytes

    def __bytes__(self):
        return self.hmac

    @staticmethod
    def from_bytes(data: bytes):
        return MessageIntegrity(data[:20]), data[20:]


@dataclass
class Fingerprint:
    crc32: int

    def __bytes__(self):
        return struct.pack("!I", self.crc32)

    @staticmethod
    def from_bytes(data: bytes):
        return Fingerprint(struct.unpack("!I", data[:4])[0]), data[4:]


@dataclass
class ErrorCode:
    code: int
    reason: str

    @property
    def error_class(self) -> int:
        return self.code // 100

    @property
    def error_number(self) -> int:
        return self.code % 100

    def __bytes__(self):
        encoded = self.reason.encode("utf-8")
        padding = b'\x00' * _padding_length(len(encoded))
        return struct.pack("!HBB", 0, self.error_class, self.error_number) + encoded + padding

    @staticmethod
    def from_bytes(data: bytes):
        _, class_number, number = struct.unpack("!HBB", data[:4])
        code = class_number * 100 + number
        reason = data[4:].decode("utf-8")
        return ErrorCode(code, reason), data[4+len(reason):]


@dataclass
class Realm:
    realm: str

    def __bytes__(self):
        encoded = self.realm.encode("utf-8")
        padding = b'\x00' * _padding_length(len(encoded))
        return encoded + padding

    @staticmethod
    def from_bytes(data: bytes):
        return Realm(data.decode("utf-8")), data[len(data):]


@dataclass
class Nonce:
    nonce: str

    def __bytes__(self):
        encoded = self.nonce.encode("utf-8")
        padding = b'\x00' * _padding_length(len(encoded))
        return encoded + padding

    @staticmethod
    def from_bytes(data: bytes):
        return Nonce(data.decode("utf-8")), data[len(data):]


@dataclass
class UnknownAttributes:
    attributes: list[int]

    def __bytes__(self):
        return struct.pack("!" + "H" * len(self.attributes), *self.attributes)

    @staticmethod
    def from_bytes(data: bytes):
        return UnknownAttributes(struct.unpack("!" + "H" * (len(data) // 2), data)), data[len(data):]


@dataclass
class Software:
    software: str

    def __bytes__(self):
        encoded = self.software.encode("utf-8")
        padding = b'\x00' * _padding_length(len(encoded))
        return encoded + padding

    @staticmethod
    def from_bytes(data: bytes):
        return Software(data.decode("utf-8")), data[len(data):]


@dataclass
class AlternateServer(MappedAddress):
    pass


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
