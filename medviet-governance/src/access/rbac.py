# src/access/rbac.py
import os
from functools import wraps
from typing import Optional

import casbin
from fastapi import HTTPException, Header

# Danh sách user giả lập (production dùng JWT + DB)
MOCK_USERS = {
    "token-alice": {"username": "alice", "role": "admin"},
    "token-bob":   {"username": "bob",   "role": "ml_engineer"},
    "token-carol": {"username": "carol", "role": "data_analyst"},
    "token-dave":  {"username": "dave",  "role": "intern"},
}

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
enforcer = casbin.Enforcer(
    os.path.join(_BASE_DIR, "model.conf"),
    os.path.join(_BASE_DIR, "policy.csv"),
)


def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    """
    Parse Bearer token và trả về user info.
    Raise HTTPException 401 nếu token không hợp lệ.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = authorization.split(" ")[1]
    user = MOCK_USERS.get(token)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    return user


def require_permission(resource: str, action: str):
    """
    Decorator kiểm tra RBAC permission.
    Dùng casbin enforcer để check (username, resource, action).
    Raise HTTPException 403 nếu không có quyền.

    Lưu ý: enforcer dùng `g(r.sub, p.sub)` để map user → role, nên
    truyền username (không phải role) làm subject.
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = kwargs.get("current_user")
            if current_user is None:
                raise HTTPException(status_code=401, detail="Not authenticated")

            username = current_user["username"]
            role = current_user["role"]

            allowed = enforcer.enforce(username, resource, action)

            if not allowed:
                raise HTTPException(
                    status_code=403,
                    detail=f"Role '{role}' cannot '{action}' on '{resource}'",
                )
            return await func(*args, **kwargs)
        return wrapper
    return decorator
