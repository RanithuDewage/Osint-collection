from modules.reconnaissance.ports import assess_ports


def test_assess_ports_returns_mapping():
    result = assess_ports("127.0.0.1", [1, 2])

    assert isinstance(result, dict)
    assert set(result.keys()) == {1, 2}


def test_assess_ports_values_are_boolean():
    result = assess_ports("127.0.0.1", [1])

    assert isinstance(result[1], bool)
