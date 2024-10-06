from dataclasses import dataclass
from enum import IntEnum
from stunpy.common import _padding_length, MAGIC_COOKIE
import struct
import socket
import ipaddress

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

