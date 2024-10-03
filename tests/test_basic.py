import stunpy


def test_message_type_forming():
    assert stunpy.StunHeader(stunpy.MessageType.REQUEST, stunpy.MessageMethod.BINDING, 0, 0).message_type == 0x0001
    assert stunpy.StunHeader(stunpy.MessageType.INDICATION, stunpy.MessageMethod.BINDING, 0, 0).message_type == 0x0011
    assert stunpy.StunHeader(stunpy.MessageType.SUCCESS_RESPONSE, stunpy.MessageMethod.BINDING, 0, 0).message_type == 0x0101
    assert stunpy.StunHeader(stunpy.MessageType.ERROR_RESPONSE, stunpy.MessageMethod.BINDING, 0, 0).message_type == 0x111


def test_decode_stun():
    msg = b"\x00\x03\x00\x08!\x12\xa4B\x05\xf1\xd3\xed\x12<\xeb\xe3\xb2\x90I\x8d\x00\x19\x00\x04\x11\x00\x00\x00"
    header = stunpy.StunHeader.from_bytes(msg[:20])
    assert header.typ == stunpy.MessageType.REQUEST
    assert header.method == stunpy.MessageMethod.ALLOCATE
    assert header.length == 8
    assert header.transaction_id == 0x005f1d3ed123cebe3b290498d
