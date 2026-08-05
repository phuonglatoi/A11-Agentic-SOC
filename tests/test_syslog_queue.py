from app.integrations.syslog import SyslogProtocol


class DummyDatabase:
    pass


class DummyPipeline:
    pass


def test_syslog_datagrams_are_bounded_by_queue():
    protocol = SyslogProtocol(
        DummyDatabase(),
        DummyPipeline(),
        queue_maxsize=2,
        worker_count=1,
    )

    protocol.datagram_received(b"first", ("192.0.2.10", 514))
    protocol.datagram_received(b"second", ("192.0.2.10", 514))
    protocol.datagram_received(b"third", ("192.0.2.10", 514))

    stats = protocol.stats()
    assert stats["received"] == 3
    assert stats["queue_size"] == 2
    assert stats["queue_maxsize"] == 2
    assert stats["dropped"] == 1
