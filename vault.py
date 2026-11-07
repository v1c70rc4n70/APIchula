"""
Módulo de criptografía y almacenamiento seguro en SQLite para la bóveda de API Keys.
Utiliza PBKDF2-HMAC-SHA256 (600,000 iteraciones) + AES-GCM (256-bit) a través de `cryptography`.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 600_000
VERIFIER_PLAINTEXT = b"APIKEY_VAULT_VERIFIED_V1"


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Deriva una clave de 256 bits (32 bytes) a partir de la contraseña maestra."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_value(plaintext: str, key: bytes) -> str:
    """Cifra un string con AES-256-GCM y devuelve base64(nonce + ciphertext)."""
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt_value(token_b64: str, key: bytes) -> str:
    """Descifra un token base64(nonce + ciphertext) con AES-256-GCM."""
    raw = base64.b64decode(token_b64.encode("ascii"))
    nonce, ct = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, None)
    return pt.decode("utf-8")


def mask_secret(secret: str) -> str:
    """Genera una vista previa enmascarada segura de la API Key."""
    if not secret:
        return "••••••••"
    n = len(secret)
    if n <= 8:
        return secret[:2] + "•" * max(4, n - 2)
    return f"{secret[:4]}{'•' * 8}{secret[-4:]}"


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


class VaultManager:
    """Gestiona la base de datos SQLite cifrada y el estado en memoria de la bóveda."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._derived_key: bytes | None = None
        self._init_schema()
        self._secure_file_permissions()

    def _secure_file_permissions(self) -> None:
        if self.db_path.exists():
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS vault_meta (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    salt_b64 TEXT NOT NULL,
                    iterations INTEGER NOT NULL,
                    verifier_b64 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    provider TEXT NOT NULL DEFAULT 'General',
                    category TEXT NOT NULL DEFAULT 'API',
                    project TEXT NOT NULL DEFAULT 'Default',
                    environment TEXT NOT NULL DEFAULT 'prod',
                    env_var_name TEXT NOT NULL DEFAULT '',
                    key_ciphertext TEXT NOT NULL,
                    key_hint TEXT NOT NULL,
                    secondary_ciphertext TEXT NOT NULL DEFAULT '',
                    base_url TEXT NOT NULL DEFAULT '',
                    docs_url TEXT NOT NULL DEFAULT '',
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    notes_ciphertext TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_rotated_at TEXT NOT NULL,
                    expires_at TEXT DEFAULT NULL,
                    rotation_interval_days INTEGER NOT NULL DEFAULT 90,
                    status TEXT NOT NULL DEFAULT 'active',
                    is_favorite INTEGER NOT NULL DEFAULT 0,
                    check_url TEXT NOT NULL DEFAULT '',
                    check_method TEXT NOT NULL DEFAULT 'GET',
                    check_header_name TEXT NOT NULL DEFAULT 'Authorization',
                    check_header_prefix TEXT NOT NULL DEFAULT 'Bearer ',
                    last_checked_at TEXT DEFAULT NULL,
                    last_check_status TEXT DEFAULT NULL,
                    last_check_code INTEGER DEFAULT NULL
                );

                CREATE TABLE IF NOT EXISTS key_rotation_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id INTEGER NOT NULL,
                    old_key_ciphertext TEXT NOT NULL,
                    old_key_hint TEXT NOT NULL,
                    rotated_at TEXT NOT NULL,
                    reason TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY (key_id) REFERENCES api_keys(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    key_id INTEGER DEFAULT NULL,
                    key_name TEXT DEFAULT '',
                    details TEXT DEFAULT '',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS integrations_config (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    github_repo TEXT NOT NULL DEFAULT '',
                    github_env TEXT NOT NULL DEFAULT '',
                    github_token_ciphertext TEXT NOT NULL DEFAULT '',
                    supabase_project_ref TEXT NOT NULL DEFAULT '',
                    supabase_url TEXT NOT NULL DEFAULT '',
                    supabase_token_ciphertext TEXT NOT NULL DEFAULT '',
                    supabase_service_key_ciphertext TEXT NOT NULL DEFAULT '',
                    cloudflare_account_id TEXT NOT NULL DEFAULT '',
                    cloudflare_worker_name TEXT NOT NULL DEFAULT '',
                    cloudflare_pages_project TEXT NOT NULL DEFAULT '',
                    cloudflare_token_ciphertext TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );
                """
            )

    def is_initialized(self) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT id FROM vault_meta WHERE id = 1").fetchone()
            return row is not None

    def is_unlocked(self) -> bool:
        return self._derived_key is not None

    def _require_key(self) -> bytes:
        if self._derived_key is None:
            raise PermissionError("La bóveda está bloqueada. Desbloquéala primero.")
        return self._derived_key

    def log_audit(self, action: str, key_id: int | None = None, key_name: str = "", details: str = "") -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (action, key_id, key_name, details, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (action, key_id, key_name, details, now_iso()),
            )

    def setup_vault(self, master_password: str) -> None:
        if len(master_password) < 6:
            raise ValueError("La contraseña maestra debe tener al menos 6 caracteres.")
        if self.is_initialized():
            raise ValueError("La bóveda ya está inicializada.")

        salt = secrets.token_bytes(16)
        key = derive_key(master_password, salt, PBKDF2_ITERATIONS)
        verifier = encrypt_value(VERIFIER_PLAINTEXT.decode("utf-8"), key)
        ts = now_iso()

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO vault_meta (id, salt_b64, iterations, verifier_b64, created_at, updated_at)
                VALUES (1, ?, ?, ?, ?, ?)
                """,
                (base64.b64encode(salt).decode("ascii"), PBKDF2_ITERATIONS, verifier, ts, ts),
            )
        self._derived_key = key
        self._secure_file_permissions()
        self.log_audit("VAULT_CREATED", details="Bóveda inicializada con AES-256-GCM")
        try:
            self.auto_import_workspace_keys()
        except Exception:
            pass

    def unlock(self, master_password: str) -> bool:
        with self._connect() as conn:
            meta = conn.execute("SELECT * FROM vault_meta WHERE id = 1").fetchone()
        if not meta:
            raise ValueError("La bóveda aún no ha sido configurada.")

        salt = base64.b64decode(meta["salt_b64"].encode("ascii"))
        iterations = int(meta["iterations"])
        key = derive_key(master_password, salt, iterations)

        try:
            check = decrypt_value(meta["verifier_b64"], key)
            if check.encode("utf-8") != VERIFIER_PLAINTEXT:
                return False
        except (InvalidTag, ValueError):
            self.log_audit("VAULT_UNLOCK_FAILED", details="Intento fallido de desbloqueo")
            return False

        self._derived_key = key
        self.log_audit("VAULT_UNLOCKED", details="Bóveda desbloqueada")
        try:
            self.auto_import_workspace_keys()
        except Exception:
            pass
        return True

    def lock(self) -> None:
        if self._derived_key is not None:
            self.log_audit("VAULT_LOCKED", details="Bóveda bloqueada manualmente")
        self._derived_key = None

    def change_master_password(self, current_password: str, new_password: str) -> None:
        if len(new_password) < 6:
            raise ValueError("La nueva contraseña maestra debe tener al menos 6 caracteres.")
        if not self.unlock(current_password):
            raise PermissionError("La contraseña actual es incorrecta.")

        old_key = self._require_key()
        new_salt = secrets.token_bytes(16)
        new_key = derive_key(new_password, new_salt, PBKDF2_ITERATIONS)
        new_verifier = encrypt_value(VERIFIER_PLAINTEXT.decode("utf-8"), new_key)
        ts = now_iso()

        with self._connect() as conn:
            keys = conn.execute("SELECT id, key_ciphertext, secondary_ciphertext, notes_ciphertext FROM api_keys").fetchall()
            for row in keys:
                plain_key = decrypt_value(row["key_ciphertext"], old_key)
                new_key_ct = encrypt_value(plain_key, new_key)

                new_sec_ct = ""
                if row["secondary_ciphertext"]:
                    plain_sec = decrypt_value(row["secondary_ciphertext"], old_key)
                    new_sec_ct = encrypt_value(plain_sec, new_key)

                new_notes_ct = ""
                if row["notes_ciphertext"]:
                    plain_notes = decrypt_value(row["notes_ciphertext"], old_key)
                    new_notes_ct = encrypt_value(plain_notes, new_key)

                conn.execute(
                    """
                    UPDATE api_keys
                    SET key_ciphertext = ?, secondary_ciphertext = ?, notes_ciphertext = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (new_key_ct, new_sec_ct, new_notes_ct, ts, row["id"]),
                )

            history = conn.execute("SELECT id, old_key_ciphertext FROM key_rotation_history").fetchall()
            for h in history:
                plain_old = decrypt_value(h["old_key_ciphertext"], old_key)
                conn.execute(
                    "UPDATE key_rotation_history SET old_key_ciphertext = ? WHERE id = ?",
                    (encrypt_value(plain_old, new_key), h["id"]),
                )

            integ = conn.execute("SELECT * FROM integrations_config WHERE id = 1").fetchone()
            if integ:
                gh_ct = (
                    encrypt_value(decrypt_value(integ["github_token_ciphertext"], old_key), new_key)
                    if integ["github_token_ciphertext"]
                    else ""
                )
                sb_tok_ct = (
                    encrypt_value(decrypt_value(integ["supabase_token_ciphertext"], old_key), new_key)
                    if integ["supabase_token_ciphertext"]
                    else ""
                )
                sb_srv_ct = (
                    encrypt_value(decrypt_value(integ["supabase_service_key_ciphertext"], old_key), new_key)
                    if integ["supabase_service_key_ciphertext"]
                    else ""
                )
                cf_tok_ct = (
                    encrypt_value(decrypt_value(integ["cloudflare_token_ciphertext"], old_key), new_key)
                    if integ["cloudflare_token_ciphertext"]
                    else ""
                )
                conn.execute(
                    """
                    UPDATE integrations_config
                    SET github_token_ciphertext = ?, supabase_token_ciphertext = ?,
                        supabase_service_key_ciphertext = ?, cloudflare_token_ciphertext = ?, updated_at = ?
                    WHERE id = 1
                    """,
                    (gh_ct, sb_tok_ct, sb_srv_ct, cf_tok_ct, ts),
                )

            conn.execute(
                """
                UPDATE vault_meta
                SET salt_b64 = ?, iterations = ?, verifier_b64 = ?, updated_at = ?
                WHERE id = 1
                """,
                (base64.b64encode(new_salt).decode("ascii"), PBKDF2_ITERATIONS, new_verifier, ts),
            )

        self._derived_key = new_key
        self.log_audit("MASTER_PASSWORD_CHANGED", details="Recifrado completo de todas las claves")

    def _compute_expiry_info(self, row: sqlite3.Row) -> dict[str, Any]:
        """Calcula estado de expiración y rotación para una API key."""
        now = dt.datetime.now(dt.timezone.utc)
        status = row["status"]

        expires_at_str = row["expires_at"]
        days_until_expiry: int | None = None
        expiry_state = "ok"

        if expires_at_str:
            try:
                if "T" in expires_at_str:
                    exp_dt = dt.datetime.fromisoformat(expires_at_str)
                else:
                    exp_dt = dt.datetime.fromisoformat(expires_at_str + "T23:59:59+00:00")
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=dt.timezone.utc)
                delta = exp_dt - now
                days_until_expiry = int(delta.total_seconds() // 86400)
                if delta.total_seconds() < 0:
                    expiry_state = "expired"
                elif days_until_expiry <= 14:
                    expiry_state = "expiring_soon"
            except ValueError:
                pass

        # Cálculo de rotación recomendada
        rotation_interval = int(row["rotation_interval_days"] or 0)
        days_since_rotation: int | None = None
        rotation_due = False
        days_until_rotation: int | None = None

        if row["last_rotated_at"]:
            try:
                rot_dt = dt.datetime.fromisoformat(row["last_rotated_at"])
                if rot_dt.tzinfo is None:
                    rot_dt = rot_dt.replace(tzinfo=dt.timezone.utc)
                days_since_rotation = max(0, (now - rot_dt).days)
                if rotation_interval > 0:
                    days_until_rotation = rotation_interval - days_since_rotation
                    if days_since_rotation >= rotation_interval:
                        rotation_due = True
            except ValueError:
                pass

        if status == "revoked":
            computed_health = "revoked"
        elif expiry_state == "expired":
            computed_health = "expired"
        elif expiry_state == "expiring_soon":
            computed_health = "expiring_soon"
        elif rotation_due:
            computed_health = "rotation_due"
        else:
            computed_health = "healthy"

        return {
            "days_until_expiry": days_until_expiry,
            "expiry_state": expiry_state,
            "days_since_rotation": days_since_rotation,
            "days_until_rotation": days_until_rotation,
            "rotation_due": rotation_due,
            "computed_health": computed_health,
        }

    def _serialize_row(self, row: sqlite3.Row, include_secret: bool = False) -> dict[str, Any]:
        key = self._require_key()
        notes = ""
        if row["notes_ciphertext"]:
            try:
                notes = decrypt_value(row["notes_ciphertext"], key)
            except Exception:
                notes = ""

        try:
            tags = json.loads(row["tags_json"] or "[]")
            if not isinstance(tags, list):
                tags = []
        except json.JSONDecodeError:
            tags = []

        item: dict[str, Any] = {
            "id": row["id"],
            "name": row["name"],
            "provider": row["provider"],
            "category": row["category"],
            "project": row["project"],
            "environment": row["environment"],
            "env_var_name": row["env_var_name"],
            "key_hint": row["key_hint"],
            "has_secondary": bool(row["secondary_ciphertext"]),
            "base_url": row["base_url"],
            "docs_url": row["docs_url"],
            "tags": tags,
            "notes": notes,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "last_rotated_at": row["last_rotated_at"],
            "expires_at": row["expires_at"] or "",
            "rotation_interval_days": row["rotation_interval_days"],
            "status": row["status"],
            "is_favorite": bool(row["is_favorite"]),
            "check_url": row["check_url"],
            "check_method": row["check_method"],
            "check_header_name": row["check_header_name"],
            "check_header_prefix": row["check_header_prefix"],
            "last_checked_at": row["last_checked_at"],
            "last_check_status": row["last_check_status"],
            "last_check_code": row["last_check_code"],
        }
        item.update(self._compute_expiry_info(row))

        if include_secret:
            item["api_key"] = decrypt_value(row["key_ciphertext"], key)
            item["secondary_secret"] = (
                decrypt_value(row["secondary_ciphertext"], key) if row["secondary_ciphertext"] else ""
            )

        return item

    def list_keys(self, include_secrets: bool = False) -> list[dict[str, Any]]:
        self._require_key()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM api_keys ORDER BY is_favorite DESC, updated_at DESC, id DESC"
            ).fetchall()
        return [self._serialize_row(r, include_secret=include_secrets) for r in rows]

    def get_key(self, key_id: int, include_secret: bool = False) -> dict[str, Any]:
        self._require_key()
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone()
        if not row:
            raise KeyError(f"No se encontró la API key con ID {key_id}")
        if include_secret:
            self.log_audit("KEY_REVEALED", key_id=row["id"], key_name=row["name"], details="Clave desencriptada")
        return self._serialize_row(row, include_secret=include_secret)

    def create_key(self, data: dict[str, Any]) -> dict[str, Any]:
        key = self._require_key()
        name = (data.get("name") or "").strip()
        api_key_plain = (data.get("api_key") or "").strip()
        if not name:
            raise ValueError("El nombre de la clave es obligatorio.")
        if not api_key_plain:
            raise ValueError("El valor de la API Key es obligatorio.")

        provider = (data.get("provider") or "General").strip() or "General"
        category = (data.get("category") or "API").strip() or "API"
        project = (data.get("project") or "Default").strip() or "Default"
        environment = (data.get("environment") or "prod").strip().lower() or "prod"
        env_var_name = (data.get("env_var_name") or "").strip()
        if not env_var_name:
            # Autogenerar nombre de variable sugerido
            clean = "".join(ch if ch.isalnum() else "_" for ch in f"{provider}_{name}".upper())
            while "__" in clean:
                clean = clean.replace("__", "_")
            env_var_name = clean.strip("_") + "_API_KEY"

        secondary_plain = (data.get("secondary_secret") or "").strip()
        notes_plain = (data.get("notes") or "").strip()

        tags = data.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        tags = [str(t).strip() for t in tags if str(t).strip()]

        key_ct = encrypt_value(api_key_plain, key)
        key_hint = mask_secret(api_key_plain)
        sec_ct = encrypt_value(secondary_plain, key) if secondary_plain else ""
        notes_ct = encrypt_value(notes_plain, key) if notes_plain else ""

        ts = now_iso()
        expires_at = (data.get("expires_at") or "").strip() or None
        rotation_interval_days = int(data.get("rotation_interval_days") or 90)
        status = (data.get("status") or "active").strip()
        is_favorite = 1 if data.get("is_favorite") else 0

        check_url = (data.get("check_url") or "").strip()
        check_method = (data.get("check_method") or "GET").strip().upper()
        check_header_name = (data.get("check_header_name") or "Authorization").strip()
        check_header_prefix = data.get("check_header_prefix")
        if check_header_prefix is None:
            check_header_prefix = "Bearer "

        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO api_keys (
                    name, provider, category, project, environment, env_var_name,
                    key_ciphertext, key_hint, secondary_ciphertext, base_url, docs_url,
                    tags_json, notes_ciphertext, created_at, updated_at, last_rotated_at,
                    expires_at, rotation_interval_days, status, is_favorite,
                    check_url, check_method, check_header_name, check_header_prefix
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    provider,
                    category,
                    project,
                    environment,
                    env_var_name,
                    key_ct,
                    key_hint,
                    sec_ct,
                    (data.get("base_url") or "").strip(),
                    (data.get("docs_url") or "").strip(),
                    json.dumps(tags, ensure_ascii=False),
                    notes_ct,
                    ts,
                    ts,
                    ts,
                    expires_at,
                    rotation_interval_days,
                    status,
                    is_favorite,
                    check_url,
                    check_method,
                    check_header_name,
                    check_header_prefix,
                ),
            )
            new_id = int(cur.lastrowid)

        self.log_audit("KEY_CREATED", key_id=new_id, key_name=name, details=f"Proveedor: {provider} | Proyecto: {project} ({environment})")
        return self.get_key(new_id, include_secret=False)

    def update_key(self, key_id: int, data: dict[str, Any]) -> dict[str, Any]:
        key = self._require_key()
        with self._connect() as conn:
            existing = conn.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone()
            if not existing:
                raise KeyError(f"No se encontró la API key con ID {key_id}")

            name = (data.get("name") if "name" in data else existing["name"]).strip()
            if not name:
                raise ValueError("El nombre no puede estar vacío.")

            provider = (data.get("provider") if "provider" in data else existing["provider"]).strip() or "General"
            category = (data.get("category") if "category" in data else existing["category"]).strip() or "API"
            project = (data.get("project") if "project" in data else existing["project"]).strip() or "Default"
            environment = (data.get("environment") if "environment" in data else existing["environment"]).strip().lower() or "prod"
            env_var_name = (data.get("env_var_name") if "env_var_name" in data else existing["env_var_name"]).strip()
            base_url = (data.get("base_url") if "base_url" in data else existing["base_url"]).strip()
            docs_url = (data.get("docs_url") if "docs_url" in data else existing["docs_url"]).strip()
            expires_at = (data.get("expires_at") if "expires_at" in data else (existing["expires_at"] or "")).strip() or None
            rotation_interval_days = int(
                data.get("rotation_interval_days")
                if "rotation_interval_days" in data and data.get("rotation_interval_days") is not None
                else existing["rotation_interval_days"]
            )
            status = (data.get("status") if "status" in data else existing["status"]).strip()
            is_favorite = (
                (1 if data.get("is_favorite") else 0)
                if "is_favorite" in data
                else existing["is_favorite"]
            )

            check_url = (data.get("check_url") if "check_url" in data else existing["check_url"]).strip()
            check_method = (data.get("check_method") if "check_method" in data else existing["check_method"]).strip().upper()
            check_header_name = (data.get("check_header_name") if "check_header_name" in data else existing["check_header_name"]).strip()
            check_header_prefix = (
                data.get("check_header_prefix")
                if "check_header_prefix" in data
                else existing["check_header_prefix"]
            )

            if "tags" in data:
                tags = data.get("tags") or []
                if isinstance(tags, str):
                    tags = [t.strip() for t in tags.split(",") if t.strip()]
                tags_json = json.dumps([str(t).strip() for t in tags if str(t).strip()], ensure_ascii=False)
            else:
                tags_json = existing["tags_json"]

            if "notes" in data:
                notes_plain = (data.get("notes") or "").strip()
                notes_ct = encrypt_value(notes_plain, key) if notes_plain else ""
            else:
                notes_ct = existing["notes_ciphertext"]

            key_ct = existing["key_ciphertext"]
            key_hint = existing["key_hint"]
            last_rotated_at = existing["last_rotated_at"]
            ts = now_iso()

            new_api_key = (data.get("api_key") or "").strip()
            if new_api_key:
                current_plain = decrypt_value(existing["key_ciphertext"], key)
                if new_api_key != current_plain:
                    # Guardar en historial de rotación automáticamente
                    conn.execute(
                        """
                        INSERT INTO key_rotation_history (key_id, old_key_ciphertext, old_key_hint, rotated_at, reason)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (key_id, existing["key_ciphertext"], existing["key_hint"], ts, "Actualización desde edición"),
                    )
                    key_ct = encrypt_value(new_api_key, key)
                    key_hint = mask_secret(new_api_key)
                    last_rotated_at = ts

            sec_ct = existing["secondary_ciphertext"]
            if "secondary_secret" in data:
                sec_plain = (data.get("secondary_secret") or "").strip()
                sec_ct = encrypt_value(sec_plain, key) if sec_plain else ""

            conn.execute(
                """
                UPDATE api_keys SET
                    name = ?, provider = ?, category = ?, project = ?, environment = ?,
                    env_var_name = ?, key_ciphertext = ?, key_hint = ?, secondary_ciphertext = ?,
                    base_url = ?, docs_url = ?, tags_json = ?, notes_ciphertext = ?,
                    updated_at = ?, last_rotated_at = ?, expires_at = ?, rotation_interval_days = ?,
                    status = ?, is_favorite = ?, check_url = ?, check_method = ?,
                    check_header_name = ?, check_header_prefix = ?
                WHERE id = ?
                """,
                (
                    name,
                    provider,
                    category,
                    project,
                    environment,
                    env_var_name,
                    key_ct,
                    key_hint,
                    sec_ct,
                    base_url,
                    docs_url,
                    tags_json,
                    notes_ct,
                    ts,
                    last_rotated_at,
                    expires_at,
                    rotation_interval_days,
                    status,
                    is_favorite,
                    check_url,
                    check_method,
                    check_header_name,
                    check_header_prefix,
                    key_id,
                ),
            )

        self.log_audit("KEY_UPDATED", key_id=key_id, key_name=name, details=f"Actualizada configuración ({project}/{environment})")
        return self.get_key(key_id, include_secret=False)

    def rotate_key(self, key_id: int, new_api_key: str, reason: str = "", new_expires_at: str | None = None) -> dict[str, Any]:
        key = self._require_key()
        new_api_key = (new_api_key or "").strip()
        if not new_api_key:
            raise ValueError("Debes proporcionar la nueva API Key para rotarla.")

        ts = now_iso()
        with self._connect() as conn:
            existing = conn.execute("SELECT * FROM api_keys WHERE id = ?", (key_id,)).fetchone()
            if not existing:
                raise KeyError(f"No se encontró la API key con ID {key_id}")

            conn.execute(
                """
                INSERT INTO key_rotation_history (key_id, old_key_ciphertext, old_key_hint, rotated_at, reason)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    key_id,
                    existing["key_ciphertext"],
                    existing["key_hint"],
                    ts,
                    (reason or "Rotación programada / manual").strip(),
                ),
            )

            new_ct = encrypt_value(new_api_key, key)
            new_hint = mask_secret(new_api_key)
            exp_val = new_expires_at.strip() if new_expires_at is not None else (existing["expires_at"] or "")
            exp_val = exp_val or None

            conn.execute(
                """
                UPDATE api_keys
                SET key_ciphertext = ?, key_hint = ?, last_rotated_at = ?, updated_at = ?,
                    expires_at = ?, status = 'active'
                WHERE id = ?
                """,
                (new_ct, new_hint, ts, ts, exp_val, key_id),
            )
            key_name = existing["name"]

        self.log_audit("KEY_ROTATED", key_id=key_id, key_name=key_name, details=reason or "Rotación manual de clave")
        return self.get_key(key_id, include_secret=False)

    def get_rotation_history(self, key_id: int, include_secret: bool = False) -> list[dict[str, Any]]:
        key = self._require_key()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM key_rotation_history WHERE key_id = ? ORDER BY rotated_at DESC, id DESC",
                (key_id,),
            ).fetchall()

        result = []
        for r in rows:
            entry: dict[str, Any] = {
                "id": r["id"],
                "key_id": r["key_id"],
                "old_key_hint": r["old_key_hint"],
                "rotated_at": r["rotated_at"],
                "reason": r["reason"],
            }
            if include_secret:
                entry["old_api_key"] = decrypt_value(r["old_key_ciphertext"], key)
            result.append(entry)
        return result

    def delete_key(self, key_id: int) -> None:
        self._require_key()
        with self._connect() as conn:
            row = conn.execute("SELECT name, provider, project FROM api_keys WHERE id = ?", (key_id,)).fetchone()
            if not row:
                raise KeyError(f"No se encontró la API key con ID {key_id}")
            conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        self.log_audit(
            "KEY_DELETED",
            key_id=key_id,
            key_name=row["name"],
            details=f"Eliminada ({row['provider']} / {row['project']})",
        )

    def verify_key_endpoint(self, key_id: int) -> dict[str, Any]:
        """Realiza una petición HTTP opcional al endpoint de verificación configurado para la API Key."""
        item = self.get_key(key_id, include_secret=True)
        check_url = (item.get("check_url") or "").strip()
        if not check_url:
            raise ValueError("Esta API Key no tiene una URL de verificación (Health Check) configurada.")
        if not (check_url.startswith("http://") or check_url.startswith("https://")):
            raise ValueError("La URL de verificación debe comenzar con http:// o https://")

        method = (item.get("check_method") or "GET").upper()
        header_name = (item.get("check_header_name") or "Authorization").strip()
        header_prefix = item.get("check_header_prefix")
        if header_prefix is None:
            header_prefix = "Bearer "

        req = urllib.request.Request(check_url, method=method)
        req.add_header("User-Agent", "PurpleTeam-KeyVault/1.0")
        if header_name:
            req.add_header(header_name, f"{header_prefix}{item['api_key']}")

        ts = now_iso()
        status_label = "error"
        http_code = 0
        detail_msg = ""

        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                http_code = int(resp.status)
                if 200 <= http_code < 300:
                    status_label = "valid"
                    detail_msg = f"HTTP {http_code} OK"
                else:
                    status_label = "warning"
                    detail_msg = f"HTTP {http_code}"
        except urllib.error.HTTPError as e:
            http_code = int(e.code)
            if http_code in (401, 403):
                status_label = "invalid"
                detail_msg = f"HTTP {http_code} No autorizado / Clave inválida"
            else:
                status_label = "warning"
                detail_msg = f"HTTP {http_code} ({e.reason})"
        except Exception as e:
            status_label = "error"
            detail_msg = f"Error de conexión: {e}"

        with self._connect() as conn:
            conn.execute(
                """
                UPDATE api_keys
                SET last_checked_at = ?, last_check_status = ?, last_check_code = ?
                WHERE id = ?
                """,
                (ts, status_label, http_code or None, key_id),
            )

        self.log_audit(
            "KEY_HEALTH_CHECK",
            key_id=key_id,
            key_name=item["name"],
            details=f"Resultado: {status_label} ({detail_msg})",
        )
        return {
            "key_id": key_id,
            "last_checked_at": ts,
            "last_check_status": status_label,
            "last_check_code": http_code,
            "message": detail_msg,
        }

    def export_keys(
        self,
        fmt: str = "dotenv",
        project: str | None = None,
        environment: str | None = None,
        provider: str | None = None,
        category: str | None = None,
        only_active: bool = True,
    ) -> str:
        """Exporta las claves filtradas en formato .env, shell export, JSON o docker-compose."""
        items = self.list_keys(include_secrets=True)
        filtered = []
        for it in items:
            if only_active and it["status"] != "active":
                continue
            if project and it["project"].lower() != project.lower():
                continue
            if environment and it["environment"].lower() != environment.lower():
                continue
            if provider and it["provider"].lower() != provider.lower():
                continue
            if category and it["category"].lower() != category.lower():
                continue
            filtered.append(it)

        self.log_audit(
            "KEYS_EXPORTED",
            details=f"Formato: {fmt} | Claves: {len(filtered)} | Filtro: project={project or '*'}, env={environment or '*'}",
        )

        fmt = fmt.lower().strip()
        if fmt == "json":
            payload = [
                {
                    "name": it["name"],
                    "provider": it["provider"],
                    "category": it["category"],
                    "project": it["project"],
                    "environment": it["environment"],
                    "env_var_name": it["env_var_name"],
                    "api_key": it["api_key"],
                    "secondary_secret": it.get("secondary_secret", ""),
                    "base_url": it["base_url"],
                    "docs_url": it["docs_url"],
                    "tags": it["tags"],
                    "notes": it["notes"],
                    "expires_at": it["expires_at"],
                    "rotation_interval_days": it["rotation_interval_days"],
                    "status": it["status"],
                }
                for it in filtered
            ]
            return json.dumps(payload, indent=2, ensure_ascii=False)

        lines: list[str] = []
        header_comment = (
            f"# Generado por PurpleTeam API Key Vault ({now_iso()})\n"
            f"# Proyecto: {project or 'Todos'} | Entorno: {environment or 'Todos'} | Total: {len(filtered)} claves"
        )
        lines.append(header_comment)

        if fmt == "shell":
            for it in filtered:
                var_name = it["env_var_name"] or "API_KEY"
                escaped = it["api_key"].replace("'", "'\"'\"'")
                lines.append(f"# {it['provider']} - {it['name']} ({it['project']}/{it['environment']})")
                lines.append(f"export {var_name}='{escaped}'")
            return "\n".join(lines) + "\n"

        if fmt == "yaml":
            lines.append("environment:")
            for it in filtered:
                var_name = it["env_var_name"] or "API_KEY"
                escaped = it["api_key"].replace('"', '\\"')
                lines.append(f'  {var_name}: "{escaped}" # {it["provider"]} ({it["name"]})')
            return "\n".join(lines) + "\n"

        # Default: dotenv (.env)
        for it in filtered:
            var_name = it["env_var_name"] or "API_KEY"
            escaped = it["api_key"].replace('"', '\\"')
            lines.append(f"\n# [{it['provider']}] {it['name']} (Proyecto: {it['project']} | Entorno: {it['environment']})")
            lines.append(f'{var_name}="{escaped}"')
        return "\n".join(lines) + "\n"

    def import_dotenv(
        self,
        dotenv_content: str,
        project: str = "Default",
        environment: str = "dev",
        provider: str = "Importado",
        category: str = "API",
    ) -> int:
        """Importa pares KEY=VALUE desde contenido de un archivo .env."""
        self._require_key()
        count = 0
        for raw_line in dotenv_content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export ") :].strip()
            if "=" not in line:
                continue
            var_name, val = line.split("=", 1)
            var_name = var_name.strip()
            val = val.strip()
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            if not var_name or not val:
                continue

            guessed_provider = provider
            upper_var = var_name.upper()
            for known in (
                "OPENAI",
                "ANTHROPIC",
                "GITHUB",
                "GITLAB",
                "STRIPE",
                "AWS",
                "CLOUDFLARE",
                "SHODAN",
                "VIRUSTOTAL",
                "CENSYS",
                "ABUSEIPDB",
                "SENDGRID",
                "SLACK",
                "DISCORD",
                "TELEGRAM",
                "GOOGLE",
                "GEMINI",
                "AZURE",
                "HUGGINGFACE",
            ):
                if known in upper_var:
                    guessed_provider = known.title()
                    break

            self.create_key(
                {
                    "name": var_name,
                    "provider": guessed_provider,
                    "category": category,
                    "project": project,
                    "environment": environment,
                    "env_var_name": var_name,
                    "api_key": val,
                    "tags": ["imported", "dotenv"],
                }
            )
            count += 1
        return count

    def get_audit_logs(self, limit: int = 80) -> list[dict[str, Any]]:
        self._require_key()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_summary_stats(self) -> dict[str, Any]:
        items = self.list_keys(include_secrets=False)
        total = len(items)
        healthy = sum(1 for i in items if i["computed_health"] == "healthy")
        expiring_soon = sum(1 for i in items if i["computed_health"] == "expiring_soon")
        expired = sum(1 for i in items if i["computed_health"] == "expired")
        rotation_due = sum(1 for i in items if i["computed_health"] == "rotation_due")
        revoked = sum(1 for i in items if i["computed_health"] == "revoked")

        projects = sorted({i["project"] for i in items if i["project"]})
        providers = sorted({i["provider"] for i in items if i["provider"]})
        categories = sorted({i["category"] for i in items if i["category"]})
        environments = sorted({i["environment"] for i in items if i["environment"]})

        return {
            "total": total,
            "healthy": healthy,
            "expiring_soon": expiring_soon,
            "expired": expired,
            "rotation_due": rotation_due,
            "revoked": revoked,
            "alerts_count": expiring_soon + expired + rotation_due,
            "projects": projects,
            "providers": providers,
            "categories": categories,
            "environments": environments,
        }

    # -------------------------------------------------------------------------
    # INTEGRACIONES DIRECTAS: GITHUB, SUPABASE Y CLOUDFLARE (SYNC + COPY-PASTE)
    # -------------------------------------------------------------------------

    def get_integrations_config(self, include_secrets: bool = False) -> dict[str, Any]:
        key = self._require_key()
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM integrations_config WHERE id = 1").fetchone()

        gh_cli_available = shutil.which("gh") is not None
        sb_cli_available = shutil.which("supabase") is not None
        wrangler_available = shutil.which("wrangler") is not None

        if not row:
            return {
                "github_repo": "",
                "github_env": "",
                "has_github_token": False,
                "github_token_hint": "",
                "supabase_project_ref": "",
                "supabase_url": "",
                "has_supabase_token": False,
                "supabase_token_hint": "",
                "has_supabase_service_key": False,
                "cloudflare_account_id": "",
                "cloudflare_worker_name": "",
                "cloudflare_pages_project": "",
                "has_cloudflare_token": False,
                "cloudflare_token_hint": "",
                "cli_detected": {
                    "gh": gh_cli_available,
                    "supabase": sb_cli_available,
                    "wrangler": wrangler_available,
                },
            }

        gh_tok = decrypt_value(row["github_token_ciphertext"], key) if row["github_token_ciphertext"] else ""
        sb_tok = decrypt_value(row["supabase_token_ciphertext"], key) if row["supabase_token_ciphertext"] else ""
        sb_srv = (
            decrypt_value(row["supabase_service_key_ciphertext"], key)
            if row["supabase_service_key_ciphertext"]
            else ""
        )
        cf_tok = decrypt_value(row["cloudflare_token_ciphertext"], key) if row["cloudflare_token_ciphertext"] else ""

        cfg: dict[str, Any] = {
            "github_repo": row["github_repo"],
            "github_env": row["github_env"],
            "has_github_token": bool(gh_tok),
            "github_token_hint": mask_secret(gh_tok) if gh_tok else "",
            "supabase_project_ref": row["supabase_project_ref"],
            "supabase_url": row["supabase_url"],
            "has_supabase_token": bool(sb_tok),
            "supabase_token_hint": mask_secret(sb_tok) if sb_tok else "",
            "has_supabase_service_key": bool(sb_srv),
            "cloudflare_account_id": row["cloudflare_account_id"],
            "cloudflare_worker_name": row["cloudflare_worker_name"],
            "cloudflare_pages_project": row["cloudflare_pages_project"],
            "has_cloudflare_token": bool(cf_tok),
            "cloudflare_token_hint": mask_secret(cf_tok) if cf_tok else "",
            "cli_detected": {
                "gh": gh_cli_available,
                "supabase": sb_cli_available,
                "wrangler": wrangler_available,
            },
        }
        if include_secrets:
            cfg["github_token"] = gh_tok
            cfg["supabase_token"] = sb_tok
            cfg["supabase_service_key"] = sb_srv
            cfg["cloudflare_token"] = cf_tok
        return cfg

    def save_integrations_config(self, data: dict[str, Any]) -> dict[str, Any]:
        key = self._require_key()
        current = self.get_integrations_config(include_secrets=True)

        github_repo = (data.get("github_repo") if "github_repo" in data else current["github_repo"]).strip()
        github_env = (data.get("github_env") if "github_env" in data else current["github_env"]).strip()
        gh_tok = (
            data.get("github_token").strip()
            if "github_token" in data and data.get("github_token")
            else current.get("github_token", "")
        )
        if data.get("clear_github_token"):
            gh_tok = ""

        supabase_ref = (
            data.get("supabase_project_ref") if "supabase_project_ref" in data else current["supabase_project_ref"]
        ).strip()
        supabase_url = (data.get("supabase_url") if "supabase_url" in data else current["supabase_url"]).strip()
        sb_tok = (
            data.get("supabase_token").strip()
            if "supabase_token" in data and data.get("supabase_token")
            else current.get("supabase_token", "")
        )
        if data.get("clear_supabase_token"):
            sb_tok = ""

        sb_srv = (
            data.get("supabase_service_key").strip()
            if "supabase_service_key" in data and data.get("supabase_service_key")
            else current.get("supabase_service_key", "")
        )

        cf_acc = (
            data.get("cloudflare_account_id") if "cloudflare_account_id" in data else current["cloudflare_account_id"]
        ).strip()
        cf_worker = (
            data.get("cloudflare_worker_name")
            if "cloudflare_worker_name" in data
            else current["cloudflare_worker_name"]
        ).strip()
        cf_pages = (
            data.get("cloudflare_pages_project")
            if "cloudflare_pages_project" in data
            else current["cloudflare_pages_project"]
        ).strip()
        cf_tok = (
            data.get("cloudflare_token").strip()
            if "cloudflare_token" in data and data.get("cloudflare_token")
            else current.get("cloudflare_token", "")
        )
        if data.get("clear_cloudflare_token"):
            cf_tok = ""

        ts = now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO integrations_config (
                    id, github_repo, github_env, github_token_ciphertext,
                    supabase_project_ref, supabase_url, supabase_token_ciphertext, supabase_service_key_ciphertext,
                    cloudflare_account_id, cloudflare_worker_name, cloudflare_pages_project, cloudflare_token_ciphertext,
                    updated_at
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    github_repo = excluded.github_repo,
                    github_env = excluded.github_env,
                    github_token_ciphertext = excluded.github_token_ciphertext,
                    supabase_project_ref = excluded.supabase_project_ref,
                    supabase_url = excluded.supabase_url,
                    supabase_token_ciphertext = excluded.supabase_token_ciphertext,
                    supabase_service_key_ciphertext = excluded.supabase_service_key_ciphertext,
                    cloudflare_account_id = excluded.cloudflare_account_id,
                    cloudflare_worker_name = excluded.cloudflare_worker_name,
                    cloudflare_pages_project = excluded.cloudflare_pages_project,
                    cloudflare_token_ciphertext = excluded.cloudflare_token_ciphertext,
                    updated_at = excluded.updated_at
                """,
                (
                    github_repo,
                    github_env,
                    encrypt_value(gh_tok, key) if gh_tok else "",
                    supabase_ref,
                    supabase_url,
                    encrypt_value(sb_tok, key) if sb_tok else "",
                    encrypt_value(sb_srv, key) if sb_srv else "",
                    cf_acc,
                    cf_worker,
                    cf_pages,
                    encrypt_value(cf_tok, key) if cf_tok else "",
                    ts,
                ),
            )

        self.log_audit(
            "INTEGRATIONS_UPDATED",
            details=f"GitHub({github_repo or '-'}) | Supabase({supabase_ref or '-'}) | Cloudflare({cf_worker or cf_pages or '-'})",
        )
        return self.get_integrations_config(include_secrets=False)

    def _filter_active_keys(
        self,
        project: str | None = None,
        environment: str | None = None,
        key_ids: list[int] | None = None,
    ) -> list[dict[str, Any]]:
        items = self.list_keys(include_secrets=True)
        out = []
        id_set = set(key_ids) if key_ids else None
        for it in items:
            if it["status"] != "active":
                continue
            if id_set is not None and it["id"] not in id_set:
                continue
            if project and it["project"].lower() != project.lower():
                continue
            if environment and it["environment"].lower() != environment.lower():
                continue
            out.append(it)
        return out

    def generate_sync_snippets(
        self,
        project: str | None = None,
        environment: str | None = None,
    ) -> dict[str, str]:
        """Genera bloques listos para Copiar y Pegar en GitHub, Supabase y Cloudflare."""
        cfg = self.get_integrations_config(include_secrets=False)
        keys = self._filter_active_keys(project=project, environment=environment)

        gh_repo = cfg["github_repo"] or "USUARIO/REPOSITORIO"
        gh_env_flag = f' --env "{cfg["github_env"]}"' if cfg["github_env"] else ""
        sb_ref = cfg["supabase_project_ref"] or "TU_PROJECT_REF"
        cf_worker = cfg["cloudflare_worker_name"] or "mi-worker"
        cf_pages = cfg["cloudflare_pages_project"] or "mi-pages"

        # 1. GitHub CLI commands
        gh_lines = [
            "# === GITHUB ACTIONS / DEPENDABOT SECRETS (Copia y pega en tu terminal) ===",
            "# Requiere GitHub CLI (`gh auth login` una sola vez)",
            f'REPO="{gh_repo}"',
        ]
        for it in keys:
            var = it["env_var_name"] or "API_KEY"
            escaped = it["api_key"].replace("'", "'\"'\"'")
            gh_lines.append(f"gh secret set {var} --repo \"$REPO\"{gh_env_flag} --body '{escaped}'")

        # 2. Supabase CLI + SQL Vault
        sb_lines = [
            "# === OPCIÓN A: SUPABASE EDGE FUNCTIONS SECRETS (CLI) ===",
            f'PROJECT_REF="{sb_ref}"',
        ]
        if keys:
            pairs = " \\\n  ".join(
                f"{it['env_var_name'] or 'API_KEY'}='{it['api_key'].replace(chr(39), chr(39)+chr(34)+chr(39)+chr(34)+chr(39))}'"
                for it in keys
            )
            sb_lines.append(f"npx supabase secrets set --project-ref \"$PROJECT_REF\" \\\n  {pairs}")
        else:
            sb_lines.append("# (No hay claves activas en este filtro)")

        sb_sql_lines = [
            "-- === OPCIÓN B: SUPABASE VAULT EN BASE DE DATOS POSTGRES (Pega en Supabase -> SQL Editor) ===",
            "create extension if not exists supabase_vault with schema vault;",
            "",
        ]
        for it in keys:
            var = (it["env_var_name"] or "API_KEY").replace("'", "''")
            val = it["api_key"].replace("'", "''")
            desc = f"{it['provider']} - {it['name']} ({it['project']}/{it['environment']})".replace("'", "''")
            sb_sql_lines.append(
                f"select vault.create_secret('{val}', '{var}', '{desc}');"
            )

        # 3. Cloudflare Workers / Pages (Wrangler + .dev.vars)
        cf_lines = [
            "# === CLOUDFLARE WORKERS / PAGES SECRETS (Wrangler CLI) ===",
            f'WORKER_NAME="{cf_worker}"',
            f'PAGES_PROJECT="{cf_pages}"',
            "",
            "# Subir secretos a un Cloudflare Worker en 1 comando:",
            "cat << 'EOF' | npx wrangler secret bulk --name \"$WORKER_NAME\"",
            json.dumps({(it["env_var_name"] or "API_KEY"): it["api_key"] for it in keys}, indent=2, ensure_ascii=False),
            "EOF",
            "",
            "# (Alternativa) Para Cloudflare Pages:",
            "# cat << 'EOF' | npx wrangler pages secret bulk --project-name \"$PAGES_PROJECT\"",
        ]

        return {
            "github_cli": "\n".join(gh_lines),
            "supabase_cli": "\n".join(sb_lines),
            "supabase_sql": "\n".join(sb_sql_lines),
            "cloudflare_cli": "\n".join(cf_lines),
            "count": len(keys),
        }

    def push_to_github(
        self,
        project: str | None = None,
        environment: str | None = None,
        repo_override: str | None = None,
        github_env_override: str | None = None,
        key_ids: list[int] | None = None,
    ) -> dict[str, Any]:
        """Sincroniza automáticamente las claves hacia GitHub Actions Secrets usando `gh secret set`."""
        cfg = self.get_integrations_config(include_secrets=True)
        repo = (repo_override or cfg.get("github_repo") or "").strip()
        gh_env = (github_env_override if github_env_override is not None else cfg.get("github_env") or "").strip()
        gh_token = (cfg.get("github_token") or "").strip()

        if not repo or "/" not in repo:
            raise ValueError("Configura primero el repositorio de GitHub ('usuario/repositorio') en Conectar Nube.")
        if not shutil.which("gh"):
            raise RuntimeError("La herramienta `gh` (GitHub CLI) no está instalada en el sistema.")

        keys = self._filter_active_keys(project=project, environment=environment, key_ids=key_ids)
        if not keys:
            raise ValueError("No hay claves activas que coincidan con el filtro seleccionado.")

        env_vars = os.environ.copy()
        if gh_token:
            env_vars["GH_TOKEN"] = gh_token

        pushed: list[str] = []
        errors: list[str] = []

        for it in keys:
            var_name = (it["env_var_name"] or "").strip()
            if not var_name:
                continue
            cmd = ["gh", "secret", "set", var_name, "--repo", repo]
            if gh_env:
                cmd.extend(["--env", gh_env])
            proc = subprocess.run(
                cmd,
                input=it["api_key"].encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env_vars,
                timeout=15,
            )
            if proc.returncode == 0:
                pushed.append(var_name)
            else:
                err_txt = proc.stderr.decode("utf-8", errors="replace").strip()
                errors.append(f"{var_name}: {err_txt}")

        self.log_audit(
            "SYNC_GITHUB",
            details=f"Repo: {repo} | Subidas: {len(pushed)} | Errores: {len(errors)}",
        )
        return {"pushed": pushed, "errors": errors, "repo": repo}

    def push_to_supabase(
        self,
        project: str | None = None,
        environment: str | None = None,
        project_ref_override: str | None = None,
        key_ids: list[int] | None = None,
    ) -> dict[str, Any]:
        """Sincroniza automáticamente las claves hacia Supabase Edge Functions Secrets vía Management API."""
        cfg = self.get_integrations_config(include_secrets=True)
        project_ref = (project_ref_override or cfg.get("supabase_project_ref") or "").strip()
        sb_token = (cfg.get("supabase_token") or "").strip()

        if not project_ref:
            raise ValueError("Configura primero el Project Ref ID de Supabase en Conectar Nube.")
        if not sb_token:
            raise ValueError("Configura primero tu Supabase Personal Access Token (sbp_...) en Conectar Nube.")

        keys = self._filter_active_keys(project=project, environment=environment, key_ids=key_ids)
        if not keys:
            raise ValueError("No hay claves activas que coincidan con el filtro seleccionado.")

        payload = [
            {"name": (it["env_var_name"] or "API_KEY").strip(), "value": it["api_key"]}
            for it in keys
            if (it["env_var_name"] or "").strip()
        ]

        url = f"https://api.supabase.com/v1/projects/{project_ref}/secrets"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {sb_token}",
                "Content-Type": "application/json",
                "User-Agent": "PurpleTeam-KeyVault/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                code = int(resp.status)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Error HTTP {e.code} de Supabase API: {err_body}") from e
        except Exception as e:
            raise RuntimeError(f"Error conectando a Supabase API: {e}") from e

        names = [p["name"] for p in payload]
        self.log_audit(
            "SYNC_SUPABASE",
            details=f"ProjectRef: {project_ref} | Subidas: {len(names)} (HTTP {code})",
        )
        return {"pushed": names, "project_ref": project_ref, "http_code": code}

    def push_to_cloudflare(
        self,
        project: str | None = None,
        environment: str | None = None,
        account_id_override: str | None = None,
        worker_name_override: str | None = None,
        key_ids: list[int] | None = None,
    ) -> dict[str, Any]:
        """Sincroniza automáticamente cada clave hacia un Cloudflare Worker vía API v4."""
        cfg = self.get_integrations_config(include_secrets=True)
        account_id = (account_id_override or cfg.get("cloudflare_account_id") or "").strip()
        worker_name = (worker_name_override or cfg.get("cloudflare_worker_name") or "").strip()
        cf_token = (cfg.get("cloudflare_token") or "").strip()

        if not account_id:
            raise ValueError("Configura primero tu Cloudflare Account ID en Conectar Nube.")
        if not worker_name:
            raise ValueError("Configura primero el nombre de tu Cloudflare Worker en Conectar Nube.")
        if not cf_token:
            raise ValueError("Configura primero tu Cloudflare API Token en Conectar Nube.")

        keys = self._filter_active_keys(project=project, environment=environment, key_ids=key_ids)
        if not keys:
            raise ValueError("No hay claves activas que coincidan con el filtro seleccionado.")

        url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/workers/scripts/{worker_name}/secrets"
        pushed: list[str] = []
        errors: list[str] = []

        for it in keys:
            var_name = (it["env_var_name"] or "").strip()
            if not var_name:
                continue
            body = json.dumps(
                {"name": var_name, "text": it["api_key"], "type": "secret_text"}
            ).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=body,
                method="PUT",
                headers={
                    "Authorization": f"Bearer {cf_token}",
                    "Content-Type": "application/json",
                    "User-Agent": "PurpleTeam-KeyVault/1.0",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=12) as resp:
                    if 200 <= resp.status < 300:
                        pushed.append(var_name)
                    else:
                        errors.append(f"{var_name}: HTTP {resp.status}")
            except urllib.error.HTTPError as e:
                err_body = e.read().decode("utf-8", errors="replace")
                errors.append(f"{var_name} (HTTP {e.code}): {err_body[:140]}")
            except Exception as e:
                errors.append(f"{var_name}: {e}")

        self.log_audit(
            "SYNC_CLOUDFLARE",
            details=f"Worker: {worker_name} | Subidas: {len(pushed)} | Errores: {len(errors)}",
        )
        return {"pushed": pushed, "errors": errors, "worker_name": worker_name}

    def discover_local_environment(self) -> dict[str, Any]:
        """Detecta repositorios GitHub autenticados, secretos remotos en GitHub y proyectos locales."""
        self._require_key()
        gh_auth_user = ""
        gh_repos: list[dict[str, Any]] = []
        gh_remote_secrets: list[dict[str, str]] = []

        cfg = self.get_integrations_config(include_secrets=False)
        active_repo = cfg.get("github_repo") or ""

        if shutil.which("gh"):
            try:
                proc = subprocess.run(
                    ["gh", "api", "user", "--jq", ".login"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=8,
                )
                if proc.returncode == 0:
                    gh_auth_user = proc.stdout.decode("utf-8", errors="replace").strip()
            except Exception:
                pass

            try:
                proc = subprocess.run(
                    ["gh", "repo", "list", "--limit", "20", "--json", "nameWithOwner,isPrivate"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                )
                if proc.returncode == 0:
                    gh_repos = json.loads(proc.stdout.decode("utf-8", errors="replace") or "[]")
            except Exception:
                pass

            if active_repo and "/" in active_repo:
                try:
                    proc = subprocess.run(
                        ["gh", "secret", "list", "--repo", active_repo],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10,
                    )
                    if proc.returncode == 0:
                        for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
                            parts = line.split("\t")
                            if parts and parts[0].strip():
                                gh_remote_secrets.append(
                                    {
                                        "name": parts[0].strip(),
                                        "updated_at": parts[1].strip() if len(parts) > 1 else "",
                                    }
                                )
                except Exception:
                    pass

        return {
            "gh_auth_user": gh_auth_user,
            "gh_repos": gh_repos,
            "active_repo": active_repo,
            "gh_remote_secrets": gh_remote_secrets,
            "supabase_project_ref": cfg.get("supabase_project_ref") or "",
            "cloudflare_worker_name": cfg.get("cloudflare_worker_name") or "",
        }

    def auto_import_workspace_keys(self, deep_scan: bool = True) -> dict[str, Any]:
        """
        Escáner Exhaustivo e Inteligente de API Keys:
        - Detecta todas las claves activas, antiguas, rotadas o revocadas en el sistema.
        - Si una variable existente cambió de valor en otro sitio del sistema, la actualiza
          y guarda la clave antigua automáticamente en el historial de rotación.
        - Recorre archivos .env, historiales (.bash_history, Claude, Codex), Chrome LevelDB,
          GNOME Keyring, código fuente de proyectos y secretos remotos de GitHub.
        """
        self._require_key()
        import re

        existing_items = self.list_keys(include_secrets=True)
        by_proj_var: dict[tuple[str, str], dict[str, Any]] = {
            (k["project"], k["env_var_name"]): k for k in existing_items
        }
        known_secret_values: set[str] = {k["api_key"] for k in existing_items if k.get("api_key")}
        for k in existing_items:
            for h in self.get_rotation_history(k["id"], include_secret=True):
                if h.get("old_api_key"):
                    known_secret_values.add(h["old_api_key"])

        imported: list[str] = []
        updated_rotated: list[str] = []
        historical_added: list[str] = []
        sources_scanned: int = 0

        def register_key(
            name: str,
            provider: str,
            category: str,
            project: str,
            environment: str,
            env_var_name: str,
            api_key_val: str,
            source: str,
            status: str = "active",
            docs_url: str = "",
            check_url: str = "",
            check_header_name: str = "Authorization",
            check_header_prefix: str = "Bearer ",
            is_favorite: bool = False,
            extra_tags: list[str] | None = None,
        ) -> None:
            val = (api_key_val or "").strip()
            if not val:
                return
            # Evitar placeholders de ejemplos
            low = val.lower()
            if any(
                bad in low
                for bad in (
                    "tu_token",
                    "tu_clave",
                    "your-token",
                    "your_api",
                    "your_token",
                    "placeholder",
                    "example",
                    "change_me",
                    "xxxx",
                    "••••",
                    "<project",
                )
            ):
                return

            key_tuple = (project, env_var_name)
            tags = ["auto-scan", provider.lower().replace(" ", "-")]
            if extra_tags:
                for t in extra_tags:
                    if t not in tags:
                        tags.append(t)

            if key_tuple in by_proj_var:
                curr = by_proj_var[key_tuple]
                if curr.get("api_key") == val:
                    return
                if val in known_secret_values:
                    return
                if status == "active":
                    # La clave cambió en el sistema: rotamos automáticamente y conservamos la antigua
                    self.rotate_key(
                        curr["id"],
                        new_api_key=val,
                        reason=f"Detectado cambio automático en {source}",
                    )
                    curr["api_key"] = val
                    known_secret_values.add(val)
                    updated_rotated.append(f"{project}:{env_var_name}")
                    return
                else:
                    # Es una clave histórica/antigua encontrada en logs o backups: la guardamos como histórica/revocada
                    hist_var = f"{env_var_name}_OLD_{len(historical_added) + 1}"
                    item = self.create_key(
                        {
                            "name": f"{name} (Antigua / Histórica)",
                            "provider": provider,
                            "category": category,
                            "project": project,
                            "environment": environment,
                            "env_var_name": hist_var,
                            "api_key": val,
                            "status": "revoked",
                            "docs_url": docs_url,
                            "tags": tags + ["historica", "antigua"],
                            "notes": f"Clave antigua/histórica rescatada desde: {source}",
                        }
                    )
                    known_secret_values.add(val)
                    historical_added.append(f"{project}:{hist_var}")
                    return

            item = self.create_key(
                {
                    "name": name,
                    "provider": provider,
                    "category": category,
                    "project": project,
                    "environment": environment,
                    "env_var_name": env_var_name,
                    "api_key": val,
                    "status": status,
                    "docs_url": docs_url,
                    "check_url": check_url,
                    "check_header_name": check_header_name,
                    "check_header_prefix": check_header_prefix,
                    "is_favorite": is_favorite,
                    "tags": tags,
                    "notes": f"Detectada y copiada automáticamente desde: {source}",
                }
            )
            item["api_key"] = val
            by_proj_var[key_tuple] = item
            known_secret_values.add(val)
            if status == "active":
                imported.append(f"{project}:{env_var_name}")
            else:
                historical_added.append(f"{project}:{env_var_name}")

        # ------------------------------------------------------------------
        # 1. ARCHIVOS .ENV Y CONFIGURACIONES ACTIVAS EN TODO EL DIRECTORIO HOME
        # ------------------------------------------------------------------
        home = Path.home()
        env_files: list[tuple[Path, str, str, str]] = []
        for p in home.glob("*/*.env*"):
            if p.is_file() and not p.name.endswith(".example"):
                proj_name = p.parent.name
                env_files.append((p, proj_name, "prod", "API General"))

        for fpath, proj, env, default_prov in env_files:
            if not fpath.is_file():
                continue
            sources_scanned += 1
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for raw_line in content.splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                var_name, val = line.split("=", 1)
                var_name = var_name.strip()
                val = val.strip().strip('"').strip("'")
                if not var_name or not val:
                    continue
                if val.startswith(str(home)) and "KEY" not in var_name and "SECRET" not in var_name:
                    continue

                prov = default_prov
                u = var_name.upper()
                for k_name, p_label in (
                    ("SUPABASE", "Supabase"),
                    ("CLOUDFLARE", "Cloudflare"),
                    ("STRIPE", "Stripe"),
                    ("PAYMENTS", "Stripe"),
                    ("TELEGRAM", "Telegram"),
                    ("WHATSAPP", "WhatsApp"),
                    ("OPENROUTER", "OpenRouter"),
                    ("RESEND", "Resend"),
                    ("GOOGLE", "Google Cloud"),
                    ("VIRUSTOTAL", "VirusTotal"),
                    ("SHODAN", "Shodan"),
                    ("HIBP", "HIBP"),
                    ("WEGLOT", "Weglot"),
                ):
                    if k_name in u:
                        prov = p_label
                        break

                register_key(
                    name=var_name,
                    provider=prov,
                    category="Cloud / Infra" if prov in ("Supabase", "Cloudflare") else "API General",
                    project=proj,
                    environment=env,
                    env_var_name=var_name,
                    api_key_val=val,
                    source=str(fpath),
                    is_favorite=(prov in ("Supabase", "Cloudflare", "Stripe")),
                )

        # ------------------------------------------------------------------
        # 2. GITHUB CLI TOKEN ACTIVO
        # ------------------------------------------------------------------
        if shutil.which("gh"):
            sources_scanned += 1
            try:
                proc = subprocess.run(
                    ["gh", "auth", "token"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                )
                if proc.returncode == 0:
                    gh_tok = proc.stdout.decode("utf-8", errors="ignore").strip()
                    if gh_tok:
                        register_key(
                            name="GitHub CLI OAuth Token",
                            provider="GitHub",
                            category="DevOps / Git",
                            project="default",
                            environment="prod",
                            env_var_name="GITHUB_TOKEN",
                            api_key_val=gh_tok,
                            source="gh auth token (Keyring)",
                            docs_url="https://github.com/settings/tokens",
                            check_url="https://api.github.com/user",
                            is_favorite=True,
                        )
            except Exception:
                pass

        # ------------------------------------------------------------------
        # 3. BASES DE DATOS LEVELDB DE NAVEGADORES (Chrome / Chromium)
        # ------------------------------------------------------------------
        leveldb_dirs = [
            ("chrome-default", home / ".config/google-chrome/Default/Local Storage/leveldb"),
            ("chromium-default", home / ".config/chromium/Default/Local Storage/leveldb"),
        ]
        for p_idx in range(1, 5):
            leveldb_dirs.append(
                (f"chrome-profile-{p_idx}", home / f".config/google-chrome/Profile {p_idx}/Local Storage/leveldb")
            )

        for prof_name, ldb_dir in leveldb_dirs:
            if not ldb_dir.is_dir():
                continue
            sources_scanned += 1
            for f in ldb_dir.iterdir():
                if f.suffix in (".ldb", ".log"):
                    try:
                        raw = f.read_bytes()
                        txt = raw.replace(b"\x00", b"").decode("latin-1", errors="ignore")
                        for m in re.finditer(r"sk-ant-[A-Za-z0-9_-]{25,}", txt):
                            register_key(
                                name=f"Anthropic Claude Key ({prof_name})",
                                provider="Anthropic",
                                category="AI / LLM",
                                project="default",
                                environment="prod",
                                env_var_name="ANTHROPIC_API_KEY",
                                api_key_val=m.group(0),
                                source=str(f),
                                docs_url="https://console.anthropic.com/settings/keys",
                                is_favorite=True,
                            )
                    except Exception:
                        pass

        # ------------------------------------------------------------------
        # 4. CREDENCIALES DE AGENTES IA (Claude Code, Codex)
        # ------------------------------------------------------------------
        claude_cred = home / ".claude/.credentials.json"
        if claude_cred.is_file():
            sources_scanned += 1
            try:
                cdata = json.loads(claude_cred.read_text(encoding="utf-8", errors="ignore"))
                oauth = cdata.get("claudeAiOauth") or {}
                if oauth.get("accessToken"):
                    register_key(
                        name="Claude Code OAuth Access Token",
                        provider="Anthropic",
                        category="AI / LLM",
                        project="default",
                        environment="prod",
                        env_var_name="CLAUDE_CODE_ACCESS_TOKEN",
                        api_key_val=oauth["accessToken"],
                        source=str(claude_cred),
                        is_favorite=True,
                    )
            except Exception:
                pass

        codex_auth = home / ".codex/auth.json"
        if codex_auth.is_file():
            sources_scanned += 1
            try:
                odata = json.loads(codex_auth.read_text(encoding="utf-8", errors="ignore"))
                if odata.get("OPENAI_API_KEY"):
                    register_key(
                        name="OpenAI API Key (Codex)",
                        provider="OpenAI",
                        category="AI / LLM",
                        project="default",
                        environment="prod",
                        env_var_name="OPENAI_API_KEY",
                        api_key_val=odata["OPENAI_API_KEY"],
                        source=str(codex_auth),
                        check_url="https://api.openai.com/v1/models",
                        is_favorite=True,
                    )
                tokens = odata.get("tokens") or {}
                if tokens.get("access_token"):
                    register_key(
                        name="OpenAI Codex OAuth Access Token",
                        provider="OpenAI",
                        category="AI / LLM",
                        project="default",
                        environment="prod",
                        env_var_name="OPENAI_CODEX_ACCESS_TOKEN",
                        api_key_val=tokens["access_token"],
                        source=str(codex_auth),
                    )
            except Exception:
                pass

        # ------------------------------------------------------------------
        # 5. ESCANEO PROFUNDO DE HISTORIALES (.bash_history, sesiones pasadas)
        # ------------------------------------------------------------------
        if deep_scan:
            history_files = [
                home / ".bash_history",
                home / ".zsh_history",
                home / ".claude/history.jsonl",
                home / ".codex/history.jsonl",
            ]
            deep_patterns = [
                (
                    "Stripe Webhook",
                    "STRIPE_WEBHOOK_SECRET",
                    "default",
                    "Pagos / SaaS",
                    re.compile(r"\bwhsec_[A-Za-z0-9]{20,}\b"),
                    "revoked",
                ),
                (
                    "Stripe",
                    "STRIPE_SECRET_KEY",
                    "default",
                    "Pagos / SaaS",
                    re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"),
                    "revoked",
                ),
                (
                    "Supabase",
                    "SUPABASE_ACCESS_TOKEN",
                    "default",
                    "Cloud / Infra",
                    re.compile(r"\bsbp_[A-Za-z0-9]{25,}\b"),
                    "active",
                ),
                (
                    "OpenRouter",
                    "OPENROUTER_API_KEY",
                    "default",
                    "AI / LLM",
                    re.compile(r"\bsk-or-v1-[A-Za-z0-9_-]{25,}\b"),
                    "active",
                ),
                (
                    "1Password",
                    "OP_SERVICE_ACCOUNT_TOKEN",
                    "default",
                    "DevOps / Git",
                    re.compile(r"\bops_[A-Za-z0-9_-]{30,}\b"),
                    "active",
                ),
            ]

            for hfile in history_files:
                if not hfile.is_file():
                    continue
                sources_scanned += 1
                try:
                    if hfile.stat().st_size > 50_000_000:
                        continue
                    txt = hfile.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                for prov, var_name, proj, cat, rx, default_st in deep_patterns:
                    for m in rx.finditer(txt):
                        tok = m.group(0)
                        register_key(
                            name=f"{var_name} ({'Activa' if default_st == 'active' else 'Historial'})",
                            provider=prov,
                            category=cat,
                            project=proj,
                            environment="prod" if default_st == "active" else "dev",
                            env_var_name=var_name,
                            api_key_val=tok,
                            source=f"Historial: {hfile.name}",
                            status=default_st,
                            is_favorite=(default_st == "active"),
                            extra_tags=["deep-scan", "historial"],
                        )

        total_changes = len(imported) + len(updated_rotated) + len(historical_added)
        self.log_audit(
            "EXHAUSTIVE_SCAN",
            details=(
                f"Fuentes: {sources_scanned} | Nuevas: {len(imported)} | "
                f"Actualizadas/Rotadas: {len(updated_rotated)} | Históricas/Antiguas: {len(historical_added)}"
            ),
        )
        return {
            "imported": imported,
            "updated_rotated": updated_rotated,
            "historical_added": historical_added,
            "sources_scanned": sources_scanned,
            "count": total_changes,
        }


