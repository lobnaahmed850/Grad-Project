import zipfile

import pytest

from parity_check import load_published


def test_feature_only_public_csv_has_explicit_identity_error(tmp_path):
    archive = tmp_path / "published.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("Friday.csv", "Destination Port,Flow Duration,Label\n80,100,BENIGN\n")
    with pytest.raises(ValueError, match="GeneratedLabelledFlows"):
        load_published(archive, "Friday")
