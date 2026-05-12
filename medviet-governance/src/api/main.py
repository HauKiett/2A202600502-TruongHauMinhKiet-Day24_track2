# src/api/main.py
from pathlib import Path

import pandas as pd
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse

from src.access.rbac import get_current_user, require_permission
from src.pii.anonymizer import MedVietAnonymizer

app = FastAPI(title="MedViet Data API", version="1.0.0")
anonymizer = MedVietAnonymizer()

DATA_PATH = Path("data/raw/patients_raw.csv")


def _load_raw_df() -> pd.DataFrame:
    if not DATA_PATH.exists():
        raise HTTPException(status_code=500, detail="Raw data file not found")
    return pd.read_csv(
        DATA_PATH,
        dtype={"cccd": str, "so_dien_thoai": str},
    )


# --- ENDPOINT 1 ---
@app.get("/api/patients/raw")
@require_permission(resource="patient_data", action="read")
async def get_raw_patients(
    current_user: dict = Depends(get_current_user),
):
    """Trả về raw patient data (chỉ admin)."""
    df = _load_raw_df().head(10)
    return JSONResponse(content={
        "user": current_user["username"],
        "count": len(df),
        "records": df.to_dict(orient="records"),
    })


# --- ENDPOINT 2 ---
@app.get("/api/patients/anonymized")
@require_permission(resource="training_data", action="read")
async def get_anonymized_patients(
    current_user: dict = Depends(get_current_user),
):
    """Trả về anonymized data (ml_engineer + admin)."""
    df = _load_raw_df().head(10)
    df_anon = anonymizer.anonymize_dataframe(df)
    return JSONResponse(content={
        "user": current_user["username"],
        "count": len(df_anon),
        "records": df_anon.to_dict(orient="records"),
    })


# --- ENDPOINT 3 ---
@app.get("/api/metrics/aggregated")
@require_permission(resource="aggregated_metrics", action="read")
async def get_aggregated_metrics(
    current_user: dict = Depends(get_current_user),
):
    """
    Trả về aggregated metrics (data_analyst, ml_engineer, admin).
    Số bệnh nhân theo từng loại bệnh — không chứa PII.
    """
    df = _load_raw_df()
    counts = df["benh"].value_counts().to_dict()
    avg_result = float(df["ket_qua_xet_nghiem"].mean())
    return JSONResponse(content={
        "user": current_user["username"],
        "total_patients": len(df),
        "by_condition": counts,
        "avg_test_result": round(avg_result, 2),
    })


# --- ENDPOINT 4 ---
@app.delete("/api/patients/{patient_id}")
@require_permission(resource="patient_data", action="delete")
async def delete_patient(
    patient_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Chỉ admin được xóa. Các role khác nhận 403."""
    return JSONResponse(content={
        "deleted": patient_id,
        "by": current_user["username"],
        "status": "ok",
    })


@app.get("/health")
async def health():
    return {"status": "ok", "service": "MedViet Data API"}
