package medviet.data_access

import future.keywords.if
import future.keywords.in

# Default: deny all
default allow := false

# Admin được phép tất cả
allow if {
    input.user.role == "admin"
}

# ML Engineer được đọc/ghi training data và model artifacts
allow if {
    input.user.role == "ml_engineer"
    input.resource in {"training_data", "model_artifacts"}
    input.action in {"read", "write"}
}

# ML Engineer KHÔNG được delete production data
deny if {
    input.user.role == "ml_engineer"
    input.resource == "production_data"
    input.action == "delete"
}

# ML Engineer KHÔNG được đọc raw PII
deny if {
    input.user.role == "ml_engineer"
    input.resource == "patient_data"
}

# Data Analyst chỉ được đọc aggregated metrics và viết reports
allow if {
    input.user.role == "data_analyst"
    input.resource == "aggregated_metrics"
    input.action == "read"
}

allow if {
    input.user.role == "data_analyst"
    input.resource == "reports"
    input.action == "write"
}

# Data Analyst KHÔNG được đọc raw PII
deny if {
    input.user.role == "data_analyst"
    input.resource == "patient_data"
}

# Intern chỉ được access sandbox
allow if {
    input.user.role == "intern"
    input.resource == "sandbox_data"
    input.action in {"read", "write"}
}

# Intern KHÔNG được access production
deny if {
    input.user.role == "intern"
    input.resource in {"patient_data", "training_data", "model_artifacts", "production_data"}
}

# Rule: không ai được export restricted data ra ngoài VN servers
deny if {
    input.data_classification == "restricted"
    input.destination_country != "VN"
}
