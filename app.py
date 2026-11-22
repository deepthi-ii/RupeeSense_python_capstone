"""RupeeSense — Python/Flask personal finance and shared-expenses website."""
from __future__ import annotations

import os
import secrets
from datetime import date
from functools import wraps
from typing import Any

import requests
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for

load_dotenv()

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("FLASK_HTTPS_ONLY", "false").lower() == "true",
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_ANON_KEY", "")
TIMEOUT = 25


def _headers(token: str | None = None, prefer: str | None = None) -> dict[str, str]:
    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {token or SUPABASE_KEY}",
        "Content-Type": "application/json",
    }
    if prefer:
        headers["Prefer"] = prefer
    return headers


def _error_message(response: requests.Response) -> str:
    try:
        payload = response.json()
        if isinstance(payload, dict):
            return str(payload.get("message") or payload.get("msg") or payload.get("error_description") or response.text)
    except ValueError:
        pass
    return response.text or f"Supabase request failed ({response.status_code})."


def supabase_request(
    resource: str,
    token: str | None = None,
    method: str = "GET",
    *,
    params: dict[str, str] | None = None,
    payload: Any = None,
    rpc: bool = False,
) -> Any:
    """Call Supabase REST, returning decoded JSON when available."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise RuntimeError("Supabase is not configured. Add SUPABASE_URL and SUPABASE_ANON_KEY to your .env file.")
    endpoint = f"{SUPABASE_URL}/rest/v1/{'rpc/' if rpc else ''}{resource}"
    response = requests.request(
        method,
        endpoint,
        headers=_headers(token, "return=representation" if method in {"POST", "PATCH", "DELETE"} else None),
        params=params,
        json=payload,
        timeout=TIMEOUT,
    )
    if not response.ok:
        raise RuntimeError(_error_message(response))
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def supabase_auth(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise RuntimeError("Supabase is not configured. Add SUPABASE_URL and SUPABASE_ANON_KEY to your .env file.")
    response = requests.post(
        f"{SUPABASE_URL}/auth/v1/{path}",
        headers=_headers(),
        json=payload,
        timeout=TIMEOUT,
    )
    if not response.ok:
        raise RuntimeError(_error_message(response))
    return response.json()


def current_token() -> str | None:
    return session.get("access_token")


def current_user() -> dict[str, Any] | None:
    return session.get("user")


def money(value: Any) -> str:
    try:
        return f"₹{float(value or 0):,.2f}"
    except (TypeError, ValueError):
        return "₹0.00"


app.jinja_env.filters["money"] = money


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_token() or not current_user():
            session.clear()
            flash("Please sign in to continue.", "info")
            return redirect(url_for("home"))
        return view(*args, **kwargs)
    return wrapped


def positive_amount(raw: str, field_name: str = "Amount") -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ValueError(f"{field_name} must be a valid number.")
    if value <= 0 or value > 100_000_000_000:
        raise ValueError(f"{field_name} must be greater than zero and within the allowed limit.")
    return round(value, 2)


def dashboard_context() -> dict[str, Any]:
    user = current_user()
    token = current_token()
    user_id = user["id"]
    transactions = supabase_request(
        "personal_transactions", token,
        params={"user_id": f"eq.{user_id}", "order": "txn_date.desc", "limit": "100"},
    ) or []
    goals = supabase_request(
        "savings_goals", token,
        params={"user_id": f"eq.{user_id}", "order": "created_at.desc"},
    ) or []
    memberships = supabase_request(
        "room_members", token,
        params={"user_id": f"eq.{user_id}", "select": "room_id,role"},
    ) or []
    rooms = []
    for membership in memberships:
        found = supabase_request(
            "rooms", token,
            params={"id": f"eq.{membership['room_id']}", "select": "id,name,description,invite_code,room_type"},
        ) or []
        if found:
            rooms.append(found[0])
    expenses = sum(float(item.get("amount", 0)) for item in transactions if item.get("type") == "expense")
    income = sum(float(item.get("amount", 0)) for item in transactions if item.get("type") == "income")
    return {
        "user": user, "transactions": transactions, "goals": goals, "rooms": rooms,
        "income": income, "expenses": expenses, "balance": income - expenses,
        "today": date.today().isoformat(),
    }


@app.get("/")
def home():
    if not current_user():
        return render_template("auth.html", mode="login", user=None)
    try:
        return render_template("dashboard.html", **dashboard_context())
    except Exception as exc:
        flash(str(exc), "error")
        return render_template(
            "dashboard.html", user=current_user(), transactions=[], goals=[], rooms=[],
            income=0, expenses=0, balance=0, today=date.today().isoformat(),
        )


@app.post("/auth")
def auth():
    mode = request.form.get("mode", "login")
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    if not email or not password:
        flash("Enter both your email address and password.", "error")
        return redirect(url_for("home"))
    try:
        if mode == "signup":
            result = supabase_auth("signup", {
                "email": email,
                "password": password,
                "data": {"full_name": request.form.get("full_name", "").strip()},
            })
        else:
            result = supabase_auth("token?grant_type=password", {"email": email, "password": password})
        if not result.get("access_token"):
            flash("Account created. If email confirmation is enabled, confirm your email, then sign in.", "info")
            return redirect(url_for("home"))
        session.clear()
        session["access_token"] = result["access_token"]
        session["user"] = result["user"]
        return redirect(url_for("home"))
    except Exception as exc:
        flash(str(exc), "error")
        return redirect(url_for("home"))


@app.post("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.post("/transaction")
@login_required
def add_transaction():
    form = request.form
    try:
        txn_type = form.get("type", "expense")
        if txn_type not in {"income", "expense"}:
            raise ValueError("Choose income or expense for the transaction type.")
        title = form.get("title", "").strip()
        if not title:
            raise ValueError("Enter a title for the transaction.")
        data = {
            "user_id": current_user()["id"], "type": txn_type, "title": title,
            "amount": positive_amount(form.get("amount", "")),
            "category": form.get("category", "Other").strip() or "Other",
            "txn_date": form.get("txn_date") or date.today().isoformat(),
            "payment_method": form.get("payment_method", "Other").strip() or "Other",
            "description": form.get("description", "").strip() or None,
        }
        supabase_request("personal_transactions", current_token(), "POST", payload=data)
        flash("Transaction added!", "success")
    except Exception as exc:
        flash(str(exc), "error")
    return redirect(url_for("home"))


@app.post("/goal")
@login_required
def add_goal():
    form = request.form
    try:
        name = form.get("name", "").strip()
        if not name:
            raise ValueError("Enter a name for your savings goal.")
        target = positive_amount(form.get("target_amount", ""), "Target amount")
        saved_raw = form.get("saved_amount", "0") or "0"
        saved = round(float(saved_raw), 2)
        if saved < 0 or saved > target:
            raise ValueError("Already saved must be zero or more, and cannot exceed the target amount.")
        data = {
            "user_id": current_user()["id"], "name": name,
            "target_amount": target, "saved_amount": saved,
            "target_date": form.get("target_date") or None,
        }
        supabase_request("savings_goals", current_token(), "POST", payload=data)
        flash("Savings goal created!", "success")
    except Exception as exc:
        flash(str(exc), "error")
    return redirect(url_for("home"))


@app.post("/room/create")
@login_required
def create_room():
    form = request.form
    try:
        name = form.get("name", "").strip()
        if not name:
            raise ValueError("Enter a name for your shared room.")
        code = secrets.token_hex(3).upper()
        result = supabase_request("rooms", current_token(), "POST", payload={
            "name": name, "description": form.get("description", "").strip(),
            "created_by": current_user()["id"], "invite_code": code,
            "room_type": form.get("room_type", "Shared living"),
        }) or []
        if not result:
            raise RuntimeError("The room was not created. Please try again.")
        room = result[0]
        supabase_request("room_members", current_token(), "POST", payload={
            "room_id": room["id"], "user_id": current_user()["id"], "role": "owner",
        })
        flash(f"Room created! Invite code: {code}", "success")
    except Exception as exc:
        flash(str(exc), "error")
    return redirect(url_for("home"))


@app.post("/room/join")
@login_required
def join_room():
    try:
        code = request.form.get("invite_code", "").strip().upper()
        if not code:
            raise ValueError("Enter a room invite code.")
        supabase_request("join_room_by_code", current_token(), "POST", payload={"p_code": code}, rpc=True)
        flash("Joined room successfully!", "success")
    except Exception as exc:
        flash(str(exc), "error")
    return redirect(url_for("home"))


@app.get("/room/<room_id>")
@login_required
def room_detail(room_id: str):
    try:
        membership = supabase_request("room_members", current_token(), params={
            "room_id": f"eq.{room_id}", "user_id": f"eq.{current_user()['id']}", "select": "room_id",
        }) or []
        if not membership:
            flash("You do not have access to that shared room.", "error")
            return redirect(url_for("home"))
        rooms = supabase_request("rooms", current_token(), params={"id": f"eq.{room_id}"}) or []
        if not rooms:
            flash("That shared room could not be found.", "error")
            return redirect(url_for("home"))
        members = supabase_request("room_members", current_token(), params={
            "room_id": f"eq.{room_id}", "select": "user_id,role",
        }) or []
        expenses = supabase_request("group_expenses", current_token(), params={
            "room_id": f"eq.{room_id}", "order": "expense_date.desc",
        }) or []
        profiles = supabase_request("profiles", current_token(), params={"select": "id,full_name"}) or []
        return render_template(
            "room.html", room=rooms[0], members=members, expenses=expenses,
            profiles=profiles, today=date.today().isoformat(), user=current_user(),
        )
    except Exception as exc:
        flash(str(exc), "error")
        return redirect(url_for("home"))


@app.post("/room/<room_id>/expense")
@login_required
def add_room_expense(room_id: str):
    form = request.form
    try:
        members = supabase_request("room_members", current_token(), params={
            "room_id": f"eq.{room_id}", "user_id": f"eq.{current_user()['id']}", "select": "user_id",
        }) or []
        if not members:
            raise PermissionError("You are not a member of this room.")
        all_members = supabase_request("room_members", current_token(), params={
            "room_id": f"eq.{room_id}", "select": "user_id",
        }) or []
        title = form.get("title", "").strip()
        if not title:
            raise ValueError("Enter a name for the group expense.")
        amount = positive_amount(form.get("amount", ""))
        created = supabase_request("group_expenses", current_token(), "POST", payload={
            "room_id": room_id, "created_by": current_user()["id"],
            "paid_by": current_user()["id"], "title": title, "amount": amount,
            "category": form.get("category", "Other").strip() or "Other",
            "expense_date": form.get("expense_date") or date.today().isoformat(),
            "split_type": "equal",
        }) or []
        if not created:
            raise RuntimeError("The group expense could not be saved.")
        expense_id = created[0]["id"]
        count = len(all_members)
        if count:
            each = round(amount / count, 2)
            splits = []
            for index, member in enumerate(all_members):
                share = each if index < count - 1 else round(amount - each * (count - 1), 2)
                splits.append({"expense_id": expense_id, "user_id": member["user_id"], "amount": share})
            supabase_request("expense_splits", current_token(), "POST", payload=splits)
        flash("Group expense saved and split equally.", "success")
    except Exception as exc:
        flash(str(exc), "error")
    return redirect(url_for("room_detail", room_id=room_id))


@app.get("/health")
def health():
    return {"status": "ok", "application": "RupeeSense Python"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG", "false").lower() == "true")
