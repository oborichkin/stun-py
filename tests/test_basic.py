import stunpy


def test_decode_stun_message():
    message, remaining = stunpy.StunMessage.from_bytes(
        b"\x00\x03\x00\x08"  # Header: Type and Length
        b"!\x12\xa4B"        # Magic Cookie
        b"\x05\xf1\xd3\xed\x12<\xeb\xe3\xb2\x90I\x8d"  # Transaction ID
        b"\x00\x19\x00\x04"  # Attribute header: Type and Length
        b"\x11\x00\x00\x00"  # Attribute value: Requested Transport
    )
    assert message.header.method == stunpy.MessageMethod.ALLOCATE
    assert message.header.length == 8
    assert message.header.transaction_id == 0x005f1d3ed123cebe3b290498d
    assert len(message.attributes) == 1
    assert message.attributes[0].type == stunpy.StunAttributeType.REQUESTED_TRANSPORT
    assert message.attributes[0].value == b"\x11\x00\x00\x00"
    assert not remaining