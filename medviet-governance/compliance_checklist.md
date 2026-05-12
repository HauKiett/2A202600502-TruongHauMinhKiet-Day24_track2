# NĐ13/2023 Compliance Checklist — MedViet AI Platform

## A. Data Localization
- [x] Tất cả patient data lưu trên servers đặt tại Việt Nam (VNG Cloud / Viettel IDC, region `hcm-1`)
- [x] Backup cũng phải ở trong lãnh thổ VN (snapshot hằng đêm sang region `han-1`)
- [x] Log việc transfer data ra ngoài nếu có (kiểm soát bởi OPA rule `destination_country != "VN"`)

## B. Explicit Consent
- [x] Thu thập consent trước khi dùng data cho AI training (consent form ký số trước khi nhập viện)
- [x] Có mechanism để user rút consent (Right to Erasure) — endpoint `DELETE /api/patients/{id}` chỉ admin
- [x] Lưu consent record với timestamp (bảng `consent_log` với `patient_id`, `consent_type`, `granted_at`, `revoked_at`)

## C. Breach Notification (72h)
- [x] Có incident response plan (runbook tại `docs/incident_response.md`)
- [x] Alert tự động khi phát hiện breach (Prometheus alertmanager → Slack `#sec-alerts` + PagerDuty)
- [x] Quy trình báo cáo đến cơ quan có thẩm quyền trong 72h (Cục An toàn thông tin — Bộ TT&TT)

## D. DPO Appointment
- [x] Đã bổ nhiệm Data Protection Officer
- [x] DPO có thể liên hệ tại: **dpo@medviet.vn** — Mr. Nguyễn Văn DPO, SĐT: 0901234567

## E. Technical Controls (mapping từ requirements)

| NĐ13 Requirement   | Technical Control                                              | Status         | Owner          |
|--------------------|----------------------------------------------------------------|----------------|----------------|
| Data minimization  | PII anonymization pipeline (Presidio + custom VN recognizers)  | ✅ Done        | AI Team        |
| Access control     | RBAC (Casbin) + ABAC (OPA Rego policies)                       | ✅ Done        | Platform Team  |
| Encryption         | AES-256-GCM envelope encryption (KEK→DEK→Data); TLS 1.3        | ✅ Done        | Infra Team     |
| Audit logging      | Structured JSON logs → Loki, mọi API call ghi user+action+ts    | ✅ Done        | Platform Team  |
| Breach detection   | Prometheus alerts trên rate 4xx/5xx, login bất thường, exfiltration size > 100MB | ✅ Done | Security Team  |
| Secret management  | Pre-commit hook (git-secrets + bandit + pip-audit + custom scan) | ✅ Done       | Security Team  |
| Data quality       | Great Expectations suite chạy trong CI/CD trước khi train       | ✅ Done        | AI Team        |

## F. Technical Solutions cho từng control

### Audit logging
- Mọi endpoint FastAPI inject middleware ghi log JSON `{ts, user, ip, method, path, status, duration_ms}` → Loki.
- Retention 365 ngày (đáp ứng yêu cầu lưu vết NĐ13).
- Dashboard Grafana hiển thị tần suất truy cập theo role + alert khi 1 user truy cập > 1000 records/giờ.

### Breach detection
- **Anomaly rules** (Prometheus):
  - `rate(api_4xx_total[5m]) > 50` → brute force suspicion
  - `sum(api_response_size_bytes[10m]) by (user) > 100MB` → exfiltration suspicion
  - `count(login_failed_total[5m]) by (ip) > 10` → credential stuffing
- Alertmanager → Slack `#sec-alerts` (severity=warning) + PagerDuty (severity=critical) → trigger 72h breach notification clock.

### Encryption in transit
- Tất cả endpoint chỉ chấp nhận HTTPS (TLS 1.3 trở lên).
- mTLS giữa các microservice nội bộ (Istio service mesh).

### Secret management (defense in depth)
- Layer 1: `.gitignore` chặn commit `.env`, `*.key`, `.vault_key`.
- Layer 2: pre-commit hook (Bandit SAST + custom regex scan + git-secrets/pip-audit).
- Layer 3: GitHub Action chạy TruffleHog trên mọi PR.
- Layer 4: production secrets nằm trong HashiCorp Vault (rotation 90 ngày).
