import stunpy as stun


def test_parse_mapped_address():
    data = b"\000\001\000\b\000\001\021\374F\307\200."
    parsed_address, _ = stun.MappedAddress.from_bytes(data[4:])
    assert parsed_address.address_family == stun.AddressFamily.IPv4
    assert parsed_address.port == 4604
    assert parsed_address.address == "70.199.128.46"
    assert bytes(parsed_address) == data[4:]


def test_parse_xor_mapped_address():
    data = b"\000 \000\b\000\0010\371g\325$l"
    parsed_address, _ = stun.XorMappedAddress.from_bytes(data[4:])
    assert parsed_address.address_family == stun.AddressFamily.IPv4
    assert parsed_address.port == 4587
    assert parsed_address.address == "70.199.128.46"
    assert bytes(parsed_address) == data[4:]


def test_parse_username():
    data = b"\000\006\000\027pLyZHR:GwL3AHBovubLvCqn\000"
    parsed_username, _ = stun.Username.from_bytes(data[4:], 23)
    assert len(parsed_username.username) == 23
    assert parsed_username.username == "pLyZHR:GwL3AHBovubLvCqn"
    assert bytes(parsed_username) == data[4:]


def test_error_code():
    data = b"\000\t\000\020\000\000\005\000SERVER ERROR"
    parsed_error, _ = stun.ErrorCode.from_bytes(data[4:])
    assert parsed_error.code == 500
    assert parsed_error.reason == "SERVER ERROR"
    assert bytes(parsed_error) == data[4:]
