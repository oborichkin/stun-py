MAGIC_COOKIE = 0x2112A442

def _padding_length(length: int) -> int:
    return [0, 3, 2, 1][length % 4]

TYPE_REQ = 0x0000
TYPE_IND = 0x0010
TYPE_SUC = 0x0100
TYPE_ERR = 0x0110


is_request          = lambda msg_type: msg_type & 0x0110 == 0x0000
is_indication       = lambda msg_type: msg_type & 0x0110 == 0x0010
is_success_response = lambda msg_type: msg_type & 0x0110 == 0x0100
is_error_response   = lambda msg_type: msg_type & 0x0110 == 0x0110