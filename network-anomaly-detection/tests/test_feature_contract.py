import numpy as np
import pandas as pd
import pytest

from src.feature_contract import (
    CONTRACT,
    PORTABLE_FEATURES,
    PORTABLE_WITH_TIMING,
    IncompatibleFlows,
    detect_flag_layout,
    require_compatible,
    validate_flows,
)
from src.flow_extractor import extract_flows
from src.lab_data import remap_flags, repair_first_packet


@pytest.fixture(scope="module")
def batches(known_answer):
    pcap, _ = known_answer
    return {
        profile: pd.concat([extract_flows(pcap, profile)] * 20, ignore_index=True)
        for profile in ("training", "v4_2018")
    }


def codes(flows):
    return {issue.code for issue in validate_flows(flows) if issue.severity == "error"}


def test_correct_flows_pass(batches):
    assert codes(batches["training"]) == set()
    require_compatible(batches["training"])


def test_defective_flows_are_rejected_with_specific_reasons(batches):
    assert codes(batches["v4_2018"]) == {
        "first_packet_backward", "forward_fields_never_set", "forward_window_missing", "flag_columns_differ",
    }
    with pytest.raises(IncompatibleFlows):
        require_compatible(batches["v4_2018"])


def test_repaired_flows_pass(batches):
    assert codes(remap_flags(repair_first_packet(batches["v4_2018"]))) == set()


def test_flags_fixed_alone_is_not_enough(batches):
    assert "first_packet_backward" in codes(remap_flags(batches["v4_2018"]))


def test_missing_columns_are_reported(batches):
    assert "missing_columns" in codes(batches["training"].drop(columns=["flow duration"]))


def test_wrong_time_units_are_caught(batches):
    seconds = batches["training"].copy()
    seconds["flow duration"] = seconds["flow duration"] / 1e6
    assert "units_differ" in codes(seconds)


def test_small_batches_skip_share_based_checks(known_answer):
    pcap, _ = known_answer
    assert validate_flows(extract_flows(pcap, "v4_2018")) == []


def test_flag_layout_detection(batches):
    assert detect_flag_layout(batches["training"]) == "training"
    assert detect_flag_layout(batches["v4_2018"]) == "named"


def test_undefined_values_warn_but_do_not_block(batches):
    flows = batches["training"].copy()
    flows.loc[0, "flow bytes/s"] = np.inf
    warnings = require_compatible(flows)
    assert "undefined_values" in {issue.code for issue in warnings}


def test_every_model_feature_has_a_contract_entry():
    assert len(CONTRACT) == 78
    assert set(PORTABLE_WITH_TIMING) <= set(CONTRACT)


def test_portable_features_avoid_every_known_problem():
    for name in PORTABLE_FEATURES:
        assert CONTRACT[name].status in {"same", "repairable", "renamed"}, name
    assert "destination port" not in PORTABLE_WITH_TIMING
