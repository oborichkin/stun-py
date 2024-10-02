from dataclasses import dataclass

MAGIC_COOKIE = 0x2112A442

TYP_REQ = 0b000000000
TYP_IND = 0b000010000
TYP_SUC = 0b100000000
TYP_ERR = 0b100010000

MET_BINDING = 0b000000000001

is_request          = lambda msg_type: msg_type & 0x0110 == 0x0000
is_indication       = lambda msg_type: msg_type & 0x0110 == 0x0010
is_success_response = lambda msg_type: msg_type & 0x0110 == 0x0100
is_error_response   = lambda msg_type: msg_type & 0x0110 == 0x0110


@dataclass
class StunHeader:
    msg_type: int
    length: int
    transaction_id: bytes
