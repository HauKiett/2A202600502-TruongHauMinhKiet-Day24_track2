# tests/test_pii.py
import pandas as pd
import pytest

from src.pii.anonymizer import MedVietAnonymizer


@pytest.fixture(scope="module")
def anonymizer():
    return MedVietAnonymizer()


@pytest.fixture
def sample_df():
    # Keep leading zeroes in Vietnamese identifiers.
    return pd.read_csv(
        "data/raw/patients_raw.csv",
        dtype={"cccd": str, "so_dien_thoai": str},
    ).head(50)


class TestPIIDetection:

    def test_cccd_detected(self, anonymizer):
        sample_cccd = "012345" + "678901"
        text = f"Benh nhan Nguyen Van A, CCCD: {sample_cccd}"
        results = anonymizer.analyzer.analyze(
            text=text, language="vi", entities=["VN_CCCD"]
        )
        assert len(results) >= 1
        assert results[0].entity_type == "VN_CCCD"

    def test_phone_detected(self, anonymizer):
        text = "Lien he: 0912345678"
        results = anonymizer.analyzer.analyze(
            text=text, language="vi", entities=["VN_PHONE"]
        )
        assert len(results) >= 1
        assert results[0].entity_type == "VN_PHONE"

    def test_email_detected(self, anonymizer):
        text = "Email: nguyenvana@gmail.com"
        results = anonymizer.analyzer.analyze(
            text=text, language="vi", entities=["EMAIL_ADDRESS"]
        )
        assert len(results) >= 1
        assert results[0].entity_type == "EMAIL_ADDRESS"

    def test_detection_rate_above_95_percent(self, anonymizer, sample_df):
        pii_columns = ["ho_ten", "cccd", "so_dien_thoai", "email"]
        rate = anonymizer.calculate_detection_rate(sample_df, pii_columns)
        print(f"\nDetection rate: {rate:.2%}")
        assert rate >= 0.95, f"Detection rate {rate:.2%} < 95%"


class TestAnonymization:

    def test_pii_not_in_output(self, anonymizer, sample_df):
        df_anon = anonymizer.anonymize_dataframe(sample_df)
        output_blob = df_anon.to_csv(index=False)
        for original_cccd in sample_df["cccd"]:
            assert str(original_cccd) not in output_blob, (
                f"Original CCCD {original_cccd} is still present"
            )

    def test_non_pii_columns_unchanged(self, anonymizer, sample_df):
        df_anon = anonymizer.anonymize_dataframe(sample_df)
        assert df_anon["benh"].equals(sample_df["benh"])
        assert df_anon["ket_qua_xet_nghiem"].equals(
            sample_df["ket_qua_xet_nghiem"]
        )
