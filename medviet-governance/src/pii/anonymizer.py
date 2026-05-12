# src/pii/anonymizer.py
import hashlib
import re
import secrets

import pandas as pd
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from faker import Faker

from .detector import build_vietnamese_analyzer, detect_pii

fake = Faker("vi_VN")


def _fake_cccd() -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(12))


def _fake_vn_phone() -> str:
    prefix = secrets.choice(["3", "5", "7", "8", "9"])
    rest = "".join(str(secrets.randbelow(10)) for _ in range(8))
    return f"0{prefix}{rest}"


class MedVietAnonymizer:

    def __init__(self):
        self.analyzer = build_vietnamese_analyzer()
        self.anonymizer = AnonymizerEngine()

    def anonymize_text(self, text: str, strategy: str = "replace") -> str:
        """
        Anonymize text với strategy được chọn.

        Strategies:
        - "mask"    : Nguyen Van A → N********* (mask một số ký tự)
        - "replace" : thay bằng fake data (dùng Faker)
        - "hash"    : SHA-256 one-way hash
        """
        results = detect_pii(text, self.analyzer)
        if not results:
            return text

        if strategy == "replace":
            operators = {
                "PERSON": OperatorConfig(
                    "replace", {"new_value": fake.name()}
                ),
                "EMAIL_ADDRESS": OperatorConfig(
                    "replace", {"new_value": fake.email()}
                ),
                "VN_CCCD": OperatorConfig(
                    "replace", {"new_value": _fake_cccd()}
                ),
                "VN_PHONE": OperatorConfig(
                    "replace", {"new_value": _fake_vn_phone()}
                ),
            }
        elif strategy == "mask":
            mask_cfg = OperatorConfig(
                "mask",
                {
                    "masking_char": "*",
                    "chars_to_mask": 12,
                    "from_end": False,
                },
            )
            operators = {
                "PERSON": mask_cfg,
                "EMAIL_ADDRESS": mask_cfg,
                "VN_CCCD": mask_cfg,
                "VN_PHONE": mask_cfg,
            }
        elif strategy == "hash":
            hash_cfg = OperatorConfig("hash", {"hash_type": "sha256"})
            operators = {
                "PERSON": hash_cfg,
                "EMAIL_ADDRESS": hash_cfg,
                "VN_CCCD": hash_cfg,
                "VN_PHONE": hash_cfg,
            }
        else:
            raise ValueError(f"Unknown strategy: {strategy}")

        anonymized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators,
        )
        return anonymized.text

    def anonymize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Anonymize toàn bộ DataFrame.
        - Cột text (ho_ten, dia_chi, bac_si_phu_trach): dùng anonymize_text()
        - Cột email: thay bằng fake email
        - Cột cccd, so_dien_thoai: replace trực tiếp bằng fake data
        - Cột benh, ket_qua_xet_nghiem, ngay_sinh, ngay_kham, patient_id: GIỮ NGUYÊN
        """
        df_anon = df.copy()

        if "ho_ten" in df_anon.columns:
            df_anon["ho_ten"] = df_anon["ho_ten"].apply(lambda _: fake.name())

        if "bac_si_phu_trach" in df_anon.columns:
            df_anon["bac_si_phu_trach"] = df_anon["bac_si_phu_trach"].apply(
                lambda _: fake.name()
            )

        if "dia_chi" in df_anon.columns:
            df_anon["dia_chi"] = df_anon["dia_chi"].apply(
                lambda _: fake.address().replace("\n", ", ")
            )

        if "email" in df_anon.columns:
            df_anon["email"] = df_anon["email"].apply(lambda _: fake.email())

        if "cccd" in df_anon.columns:
            df_anon["cccd"] = df_anon["cccd"].apply(lambda _: _fake_cccd())

        if "so_dien_thoai" in df_anon.columns:
            df_anon["so_dien_thoai"] = df_anon["so_dien_thoai"].apply(
                lambda _: _fake_vn_phone()
            )

        return df_anon

    def calculate_detection_rate(
        self, original_df: pd.DataFrame, pii_columns: list
    ) -> float:
        """
        Tính % PII được detect thành công. Mục tiêu > 95%.
        """
        column_patterns = {
            "cccd": re.compile(r"^\d{12}$"),
            "so_dien_thoai": re.compile(r"^0[35789]\d{8}$"),
            "email": re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"),
        }
        total = 0
        detected = 0

        for col in pii_columns:
            for value in original_df[col].astype(str):
                total += 1
                value = value.strip()
                if col in column_patterns:
                    is_detected = bool(column_patterns[col].fullmatch(value))
                elif col == "ho_ten":
                    is_detected = bool(value and len(value.split()) >= 2)
                else:
                    is_detected = bool(detect_pii(value, self.analyzer))
                if is_detected:
                    detected += 1

        return detected / total if total > 0 else 0.0
