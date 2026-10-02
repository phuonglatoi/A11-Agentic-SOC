from app.config import Settings


def test_syslog_worker_and_queue_limits_are_bounded(monkeypatch):
    monkeypatch.setenv("SYSLOG_QUEUE_MAXSIZE", "999999")
    monkeypatch.setenv("SYSLOG_WORKER_COUNT", "999")
    settings = Settings.from_env()
    assert settings.syslog_queue_maxsize == 10000
    assert settings.syslog_worker_count == 4


def test_invalid_syslog_limits_fall_back_to_safe_defaults(monkeypatch):
    monkeypatch.setenv("SYSLOG_QUEUE_MAXSIZE", "not-a-number")
    monkeypatch.setenv("SYSLOG_WORKER_COUNT", "not-a-number")
    settings = Settings.from_env()
    assert settings.syslog_queue_maxsize == 1000
    assert settings.syslog_worker_count == 1
