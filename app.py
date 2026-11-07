#!/usr/bin/env python3
"""
PurpleTeam API Key Vault — Aplicación Web Local y CLI para gestión cifrada de API Keys.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, render_template, request

from vault import VaultManager

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = BASE_DIR / "data" / "vault.db"


def create_app(db_path: str | Path | None = None) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )
    app.config["SECRET_KEY"] = secrets.token_hex(32)
    vault = VaultManager(db_path or os.environ.get("APIKEY_VAULT_DB", DEFAULT_DB_PATH))
    app.config["VAULT"] = vault

    def get_vault() -> VaultManager:
        return app.config["VAULT"]

    @app.after_request
    def add_security_headers(resp: Response) -> Response:
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return resp

    @app.route("/")
    def index() -> str:
        return render_template("index.html")

    @app.route("/api/status", methods=["GET"])
    def vault_status() -> Response:
        v = get_vault()
        initialized = v.is_initialized()
        unlocked = v.is_unlocked()
        stats = v.get_summary_stats() if unlocked else None
        return jsonify(
            {
                "initialized": initialized,
                "unlocked": unlocked,
                "db_path": str(v.db_path),
                "stats": stats,
            }
        )

    @app.route("/api/setup", methods=["POST"])
    def setup_vault() -> tuple[Response, int] | Response:
        v = get_vault()
        body = request.get_json(silent=True) or {}
        password = body.get("master_password") or ""
        try:
            v.setup_vault(password)
            return jsonify({"ok": True, "message": "Bóveda creada y desbloqueada correctamente."})
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400

    @app.route("/api/unlock", methods=["POST"])
    def unlock_vault() -> tuple[Response, int] | Response:
        v = get_vault()
        body = request.get_json(silent=True) or {}
        password = body.get("master_password") or ""
        try:
            if v.unlock(password):
                return jsonify({"ok": True, "stats": v.get_summary_stats()})
            return jsonify({"ok": False, "error": "Contraseña maestra incorrecta."}), 401
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400

    @app.route("/api/lock", methods=["POST"])
    def lock_vault() -> Response:
        v = get_vault()
        v.lock()
        return jsonify({"ok": True})

    @app.route("/api/master-password", methods=["POST"])
    def change_master_password() -> tuple[Response, int] | Response:
        v = get_vault()
        body = request.get_json(silent=True) or {}
        current_pw = body.get("current_password") or ""
        new_pw = body.get("new_password") or ""
        try:
            v.change_master_password(current_pw, new_pw)
            return jsonify({"ok": True, "message": "Contraseña maestra actualizada y bóveda recifrada."})
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400

    @app.route("/api/keys", methods=["GET"])
    def list_keys() -> tuple[Response, int] | Response:
        v = get_vault()
        try:
            items = v.list_keys(include_secrets=False)
            stats = v.get_summary_stats()
            return jsonify({"ok": True, "items": items, "stats": stats})
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401

    @app.route("/api/keys", methods=["POST"])
    def create_key() -> tuple[Response, int] | Response:
        v = get_vault()
        body = request.get_json(silent=True) or {}
        try:
            item = v.create_key(body)
            return jsonify({"ok": True, "item": item, "stats": v.get_summary_stats()}), 201
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400

    @app.route("/api/keys/<int:key_id>", methods=["GET"])
    def get_key(key_id: int) -> tuple[Response, int] | Response:
        v = get_vault()
        reveal = request.args.get("reveal", "0") == "1"
        try:
            item = v.get_key(key_id, include_secret=reveal)
            return jsonify({"ok": True, "item": item})
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401
        except KeyError as e:
            return jsonify({"ok": False, "error": str(e)}), 404

    @app.route("/api/keys/<int:key_id>", methods=["PUT"])
    def update_key(key_id: int) -> tuple[Response, int] | Response:
        v = get_vault()
        body = request.get_json(silent=True) or {}
        try:
            item = v.update_key(key_id, body)
            return jsonify({"ok": True, "item": item, "stats": v.get_summary_stats()})
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401
        except KeyError as e:
            return jsonify({"ok": False, "error": str(e)}), 404
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400

    @app.route("/api/keys/<int:key_id>", methods=["DELETE"])
    def delete_key(key_id: int) -> tuple[Response, int] | Response:
        v = get_vault()
        try:
            v.delete_key(key_id)
            return jsonify({"ok": True, "stats": v.get_summary_stats()})
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401
        except KeyError as e:
            return jsonify({"ok": False, "error": str(e)}), 404

    @app.route("/api/keys/<int:key_id>/rotate", methods=["POST"])
    def rotate_key(key_id: int) -> tuple[Response, int] | Response:
        v = get_vault()
        body = request.get_json(silent=True) or {}
        try:
            item = v.rotate_key(
                key_id=key_id,
                new_api_key=body.get("new_api_key") or "",
                reason=body.get("reason") or "",
                new_expires_at=body.get("expires_at"),
            )
            return jsonify({"ok": True, "item": item, "stats": v.get_summary_stats()})
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401
        except KeyError as e:
            return jsonify({"ok": False, "error": str(e)}), 404
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400

    @app.route("/api/keys/<int:key_id>/history", methods=["GET"])
    def key_history(key_id: int) -> tuple[Response, int] | Response:
        v = get_vault()
        reveal = request.args.get("reveal", "0") == "1"
        try:
            history = v.get_rotation_history(key_id, include_secret=reveal)
            return jsonify({"ok": True, "history": history})
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401

    @app.route("/api/keys/<int:key_id>/verify", methods=["POST"])
    def verify_key(key_id: int) -> tuple[Response, int] | Response:
        v = get_vault()
        try:
            result = v.verify_key_endpoint(key_id)
            item = v.get_key(key_id, include_secret=False)
            return jsonify({"ok": True, "result": result, "item": item})
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401
        except KeyError as e:
            return jsonify({"ok": False, "error": str(e)}), 404
        except ValueError as e:
            return jsonify({"ok": False, "error": str(e)}), 400

    @app.route("/api/export", methods=["GET"])
    def export_keys() -> tuple[Response, int] | Response:
        v = get_vault()
        fmt = request.args.get("format", "dotenv")
        project = request.args.get("project") or None
        environment = request.args.get("environment") or None
        provider = request.args.get("provider") or None
        category = request.args.get("category") or None
        only_active = request.args.get("only_active", "1") == "1"
        download = request.args.get("download", "0") == "1"

        try:
            content = v.export_keys(
                fmt=fmt,
                project=project,
                environment=environment,
                provider=provider,
                category=category,
                only_active=only_active,
            )
            if download:
                ext_map = {"dotenv": ".env", "shell": ".sh", "json": ".json", "yaml": ".yml"}
                ext = ext_map.get(fmt, ".txt")
                filename = f"apikeys-{project or 'all'}-{environment or 'all'}{ext}"
                return Response(
                    content,
                    mimetype="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'},
                )
            return jsonify({"ok": True, "content": content, "format": fmt})
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401

    @app.route("/api/import-dotenv", methods=["POST"])
    def import_dotenv() -> tuple[Response, int] | Response:
        v = get_vault()
        body = request.get_json(silent=True) or {}
        content = body.get("content") or ""
        project = body.get("project") or "Default"
        environment = body.get("environment") or "dev"
        provider = body.get("provider") or "Importado"
        category = body.get("category") or "API"
        try:
            imported = v.import_dotenv(
                dotenv_content=content,
                project=project,
                environment=environment,
                provider=provider,
                category=category,
            )
            return jsonify({"ok": True, "imported": imported, "stats": v.get_summary_stats()})
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401

    @app.route("/api/audit", methods=["GET"])
    def audit_logs() -> tuple[Response, int] | Response:
        v = get_vault()
        try:
            logs = v.get_audit_logs(limit=100)
            return jsonify({"ok": True, "logs": logs})
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401

    @app.route("/api/generate-secret", methods=["GET"])
    def generate_secret() -> Response:
        prefix = request.args.get("prefix", "pt_live_")
        length = min(max(int(request.args.get("length", "32")), 16), 128)
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        token = prefix + "".join(secrets.choice(alphabet) for _ in range(length))
        return jsonify({"ok": True, "secret": token})

    @app.route("/api/integrations", methods=["GET"])
    def get_integrations() -> tuple[Response, int] | Response:
        v = get_vault()
        try:
            cfg = v.get_integrations_config(include_secrets=False)
            return jsonify({"ok": True, "config": cfg})
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401

    @app.route("/api/integrations", methods=["POST"])
    def save_integrations() -> tuple[Response, int] | Response:
        v = get_vault()
        body = request.get_json(silent=True) or {}
        try:
            cfg = v.save_integrations_config(body)
            return jsonify({"ok": True, "config": cfg})
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401

    @app.route("/api/integrations/snippets", methods=["GET"])
    def get_sync_snippets() -> tuple[Response, int] | Response:
        v = get_vault()
        project = request.args.get("project") or None
        environment = request.args.get("environment") or None
        try:
            snippets = v.generate_sync_snippets(project=project, environment=environment)
            return jsonify({"ok": True, "snippets": snippets})
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401

    @app.route("/api/integrations/sync/<target>", methods=["POST"])
    def sync_target(target: str) -> tuple[Response, int] | Response:
        v = get_vault()
        body = request.get_json(silent=True) or {}
        project = body.get("project") or None
        environment = body.get("environment") or None
        key_ids = body.get("key_ids") or None
        if isinstance(key_ids, list):
            key_ids = [int(x) for x in key_ids]

        try:
            if target == "github":
                res = v.push_to_github(
                    project=project,
                    environment=environment,
                    repo_override=body.get("github_repo"),
                    github_env_override=body.get("github_env"),
                    key_ids=key_ids,
                )
            elif target == "supabase":
                res = v.push_to_supabase(
                    project=project,
                    environment=environment,
                    project_ref_override=body.get("supabase_project_ref"),
                    key_ids=key_ids,
                )
            elif target == "cloudflare":
                res = v.push_to_cloudflare(
                    project=project,
                    environment=environment,
                    account_id_override=body.get("cloudflare_account_id"),
                    worker_name_override=body.get("cloudflare_worker_name"),
                    key_ids=key_ids,
                )
            else:
                return jsonify({"ok": False, "error": f"Destino desconocido: {target}"}), 400
            return jsonify({"ok": True, "result": res})
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401
        except (ValueError, RuntimeError) as e:
            return jsonify({"ok": False, "error": str(e)}), 400

    @app.route("/api/integrations/discover", methods=["GET"])
    def discover_environment() -> tuple[Response, int] | Response:
        v = get_vault()
        try:
            info = v.discover_local_environment()
            return jsonify({"ok": True, "discovery": info})
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401

    @app.route("/api/integrations/auto-import", methods=["POST"])
    def auto_import_workspace() -> tuple[Response, int] | Response:
        v = get_vault()
        try:
            res = v.auto_import_workspace_keys()
            return jsonify({"ok": True, "result": res, "stats": v.get_summary_stats()})
        except PermissionError as e:
            return jsonify({"ok": False, "error": str(e)}), 401

    return app


def run_cli(args: argparse.Namespace) -> int:
    """Modo línea de comandos para listar o exportar claves rápidamente en scripts/terminal."""
    import getpass

    vault = VaultManager(args.db)
    if not vault.is_initialized():
        print("Error: La bóveda aún no está inicializada. Abre la interfaz web primero o usa --setup.", file=sys.stderr)
        return 1

    pw = os.environ.get("APIKEY_VAULT_PASSWORD") or getpass.getpass("Contraseña maestra de la bóveda: ")
    if not vault.unlock(pw):
        print("Error: Contraseña maestra incorrecta.", file=sys.stderr)
        return 1

    if args.cli_action == "list":
        items = vault.list_keys(include_secrets=False)
        print(f"{'ID':<4} {'PROVEEDOR':<14} {'NOMBRE':<24} {'PROYECTO':<14} {'ENV':<7} {'SALUD':<14} {'HINT'}")
        print("-" * 98)
        for it in items:
            print(
                f"{it['id']:<4} {it['provider'][:13]:<14} {it['name'][:23]:<24} "
                f"{it['project'][:13]:<14} {it['environment'][:6]:<7} {it['computed_health']:<14} {it['key_hint']}"
            )
        return 0

    if args.cli_action == "export":
        out = vault.export_keys(
            fmt=args.format,
            project=args.project,
            environment=args.env,
            provider=args.provider,
        )
        print(out, end="")
        return 0

    if args.cli_action == "sync":
        try:
            if args.target in ("github", "all"):
                r = vault.push_to_github(project=args.project, environment=args.env, repo_override=args.repo)
                print(f"[GitHub -> {r['repo']}] Subidas {len(r['pushed'])} claves: {', '.join(r['pushed'])}")
                for err in r.get("errors", []):
                    print(f"  ! Error: {err}", file=sys.stderr)
            if args.target in ("supabase", "all"):
                r = vault.push_to_supabase(
                    project=args.project, environment=args.env, project_ref_override=args.supabase_ref
                )
                print(f"[Supabase -> {r['project_ref']}] Subidas {len(r['pushed'])} claves: {', '.join(r['pushed'])}")
            if args.target in ("cloudflare", "all"):
                r = vault.push_to_cloudflare(
                    project=args.project,
                    environment=args.env,
                    account_id_override=args.cf_account,
                    worker_name_override=args.cf_worker,
                )
                print(f"[Cloudflare -> {r['worker_name']}] Subidas {len(r['pushed'])} claves: {', '.join(r['pushed'])}")
                for err in r.get("errors", []):
                    print(f"  ! Error: {err}", file=sys.stderr)
        except Exception as e:
            print(f"Error en sincronización: {e}", file=sys.stderr)
            return 1
        return 0

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="PurpleTeam API Key Vault — Gestor Web y CLI de API Keys")
    parser.add_argument("--host", default="127.0.0.1", help="Host donde escuchar (por defecto: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8787, help="Puerto HTTP (por defecto: 8787)")
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="Ruta al archivo SQLite cifrado")
    parser.add_argument("--debug", action="store_true", help="Activar modo debug de Flask")

    subparsers = parser.add_subparsers(dest="cli_action", help="Comandos directos en terminal (opcional)")

    subparsers.add_parser("list", help="Listar todas las API Keys almacenadas desde la terminal")

    exp_parser = subparsers.add_parser("export", help="Exportar API Keys a .env, shell, json o yaml")
    exp_parser.add_argument("--format", choices=["dotenv", "shell", "json", "yaml"], default="dotenv")
    exp_parser.add_argument("--project", default=None, help="Filtrar por proyecto/cliente")
    exp_parser.add_argument("--env", default=None, help="Filtrar por entorno (dev, staging, prod)")
    exp_parser.add_argument("--provider", default=None, help="Filtrar por proveedor")

    sync_parser = subparsers.add_parser(
        "sync", help="Sincronizar secretos directamente a GitHub, Supabase o Cloudflare"
    )
    sync_parser.add_argument(
        "target", choices=["github", "supabase", "cloudflare", "all"], help="Plataforma destino"
    )
    sync_parser.add_argument("--project", default=None, help="Filtrar por proyecto/cliente")
    sync_parser.add_argument("--env", default=None, help="Filtrar por entorno (dev, staging, prod)")
    sync_parser.add_argument("--repo", default=None, help="Repositorio GitHub (usuario/repo)")
    sync_parser.add_argument("--supabase-ref", default=None, help="Project Ref de Supabase")
    sync_parser.add_argument("--cf-account", default=None, help="Account ID de Cloudflare")
    sync_parser.add_argument("--cf-worker", default=None, help="Nombre del Worker de Cloudflare")

    args = parser.parse_args()

    if args.cli_action in ("list", "export", "sync"):
        return run_cli(args)

    app = create_app(args.db)
    print(f"\n  [PurpleTeam KeyVault] Bóveda cifrada lista en: http://{args.host}:{args.port}")
    print(f"  [Base de datos]       {args.db}\n")
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
