import stunpy as stun


def test_decode_stun_message():
    message, remaining = stun.StunMessage.from_bytes(
        b"\x00\x03\x00\x08"  # Header: Type and Length
        b"!\x12\xa4B"        # Magic Cookie
        b"\x05\xf1\xd3\xed\x12<\xeb\xe3\xb2\x90I\x8d"  # Transaction ID
        b"\x00\x19\x00\x04"  # Attribute header: Type and Length
        b"\x11\x00\x00\x00"  # Attribute value: Requested Transport
    )
    assert message.header.method == stun.MessageMethod.ALLOCATE
    assert message.header.length == 8
    assert message.header.transaction_id == 0x005f1d3ed123cebe3b290498d
    assert len(message.attributes) == 1
    assert message.attributes[0].type == stun.StunAttributeType.REQUESTED_TRANSPORT
    assert message.attributes[0].value == b"\x11\x00\x00\x00"
    assert not remaining


def test_decode_stun_message_2():
    message, remaining = stun.StunMessage.from_bytes(
        b"\000\001\000T!\022\244B5YSnBqpVwa9O\000\006\000\027pLyZHR:GwL3AHBovubLvCqn\000\200*\000\b\030\213\020Li{\366[\000%\000\000\000$\000\004n\000\036\377\000\b\000\024`+\307\374\r\020c\252\3058\034\313\226\251s\bs\232\226\f\200(\000\004\321b\352e"
    )
    assert stun.is_request(message.header.message_type)
    assert message.header.method == stun.MessageMethod.BINDING
    assert message.header.length == 84
    assert message.header.transaction_id == 0x3559536e427170567761394f
    assert len(message.attributes) == 6
    assert isinstance(message.attributes[0], stun.Username)
    assert isinstance(message.attributes[-2], stun.MessageIntegrity)
    assert isinstance(message.attributes[-1], stun.Fingerprint)
    assert message.attributes[0].username == "pLyZHR:GwL3AHBovubLvCqn"
    assert message.attributes[-2].hmac == b"`+\307\374\r\020c\252\3058\034\313\226\251s\bs\232\226\f"
    assert message.attributes[-1].crc32 == 0xd162ea65
    assert not remaining
