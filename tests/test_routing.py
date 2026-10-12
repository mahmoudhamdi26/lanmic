from __future__ import annotations

import lanmic


def test_mic_player_does_not_auto_link():
    argv = lanmic.PipeWireMic().player_argv(16000)
    assert argv[argv.index("--target") + 1] == "0"
    assert "node.name=lanmic-player" in argv


def test_speaker_record_target_requires_monitor(monkeypatch):
    speaker = lanmic.PipeWireSpeaker()
    monkeypatch.setattr(lanmic, "pactl_names", lambda kind: {"PhoneSpeaker.monitor"} if kind == "sources" else set())
    assert speaker.record_target() == "PhoneSpeaker.monitor"
    monkeypatch.setattr(lanmic, "pactl_names", lambda kind: set())
    assert speaker.record_target() is None


def test_speaker_recorder_does_not_auto_link():
    argv = lanmic.PipeWireSpeaker().recorder_argv(16000)
    assert argv[argv.index("--target") + 1] == "0"
    assert "node.name=lanmic-speaker" in argv
    assert "PhoneSpeaker.monitor" not in argv
