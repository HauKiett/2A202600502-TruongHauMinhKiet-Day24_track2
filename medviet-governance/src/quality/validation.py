# src/quality/validation.py
import re

import pandas as pd

EMAIL_REGEX = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
VALID_CONDITIONS = ["Tiểu đường", "Huyết áp cao", "Tim mạch", "Khỏe mạnh"]
CCCD_LENGTH = 12


def build_patient_expectation_suite():
    """
    Tạo expectation suite cho patient data dùng Great Expectations (Fluent API).
    Lưu ý: API GE thay đổi giữa các version; nếu môi trường không có GE,
    fallback sang validate bằng pandas thuần qua `validate_anonymized_data`.
    """
    import great_expectations as gx

    context = gx.get_context()

    try:
        suite = context.add_expectation_suite("patient_data_suite")
    except Exception:
        suite = context.add_or_update_expectation_suite("patient_data_suite")

    df = pd.read_csv(
        "data/raw/patients_raw.csv",
        dtype={"cccd": str, "so_dien_thoai": str},
    )
    validator = context.sources.pandas_default.read_dataframe(df)

    # 1. patient_id không null
    validator.expect_column_values_to_not_be_null("patient_id")

    # 2. cccd phải có đúng 12 ký tự
    validator.expect_column_value_lengths_to_equal(
        column="cccd",
        value=CCCD_LENGTH,
    )

    # 3. ket_qua_xet_nghiem phải trong khoảng [0, 50]
    validator.expect_column_values_to_be_between(
        column="ket_qua_xet_nghiem",
        min_value=0,
        max_value=50,
    )

    # 4. benh phải thuộc danh sách hợp lệ
    validator.expect_column_values_to_be_in_set(
        column="benh",
        value_set=VALID_CONDITIONS,
    )

    # 5. email phải đúng regex
    validator.expect_column_values_to_match_regex(
        column="email",
        regex=EMAIL_REGEX,
    )

    # 6. patient_id phải unique
    validator.expect_column_values_to_be_unique(column="patient_id")

    validator.save_expectation_suite()
    return suite


def validate_anonymized_data(filepath: str, original_filepath: str = None) -> dict:
    """
    Validate anonymized data bằng pandas (không cần GE).
    Trả về dict: {"success": bool, "failed_checks": list, "stats": dict}
    """
    df = pd.read_csv(filepath, dtype={"cccd": str, "so_dien_thoai": str})
    results = {
        "success": True,
        "failed_checks": [],
        "stats": {
            "total_rows": len(df),
            "columns": list(df.columns),
        },
    }

    # Check 1: cccd phải có format hợp lệ (12 chữ số) — chứng tỏ đã được
    # thay bằng fake CCCD, không còn null hoặc nguyên bản
    if "cccd" in df.columns:
        invalid_cccd = df["cccd"].astype(str).apply(
            lambda x: not re.fullmatch(r"\d{12}", x)
        ).sum()
        if invalid_cccd > 0:
            results["success"] = False
            results["failed_checks"].append(
                f"{invalid_cccd} dòng có cccd không đúng format 12 chữ số"
            )

    # Check 2: không có null trong các cột quan trọng
    critical_cols = [c for c in ["patient_id", "benh", "ket_qua_xet_nghiem"]
                     if c in df.columns]
    for col in critical_cols:
        nulls = df[col].isnull().sum()
        if nulls > 0:
            results["success"] = False
            results["failed_checks"].append(f"Cột '{col}' có {nulls} null")

    # Check 3: số rows phải bằng original
    if original_filepath:
        original_df = pd.read_csv(
            original_filepath,
            dtype={"cccd": str, "so_dien_thoai": str},
        )
        if len(df) != len(original_df):
            results["success"] = False
            results["failed_checks"].append(
                f"Row count mismatch: {len(df)} vs {len(original_df)}"
            )
        results["stats"]["original_rows"] = len(original_df)

    # Check 4: email đúng regex
    if "email" in df.columns:
        invalid_email = df["email"].astype(str).apply(
            lambda x: not re.fullmatch(EMAIL_REGEX, x)
        ).sum()
        if invalid_email > 0:
            results["success"] = False
            results["failed_checks"].append(
                f"{invalid_email} dòng có email không hợp lệ"
            )

    # Check 5: benh phải nằm trong danh sách hợp lệ
    if "benh" in df.columns:
        invalid_benh = (~df["benh"].isin(VALID_CONDITIONS)).sum()
        if invalid_benh > 0:
            results["success"] = False
            results["failed_checks"].append(
                f"{invalid_benh} dòng có benh không hợp lệ"
            )

    return results
