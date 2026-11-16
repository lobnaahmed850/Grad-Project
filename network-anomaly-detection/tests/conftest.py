import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT.parent))

from known_answer_pcap import write_known_answer  # noqa: E402


@pytest.fixture(scope="session")
def known_answer(tmp_path_factory):
    """A generated pcap and the correct answers for it."""
    prefix = tmp_path_factory.mktemp("known_answer") / "known_answer"
    pcap, answers = write_known_answer(prefix)
    return pcap, json.loads(answers.read_text())
