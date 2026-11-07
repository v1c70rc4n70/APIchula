# PurpleTeam KeyVault — Gestor Local Cifrado de API Keys

Aplicación web local (con soporte CLI) para almacenar, clasificar, rotar, verificar y exportar todas tus API Keys de forma segura.

## Características principales

1. **Bóveda Cifrada (Zero-Plaintext en disco)**
   - Derivación de clave mediante **PBKDF2-HMAC-SHA256** (600,000 iteraciones + salt aleatorio de 128 bits).
   - Cifrado autenticado **AES-256-GCM** para cada API Key, secretos secundarios, notas e historial de claves.
   - Bloqueo instantáneo en memoria y cambio de contraseña maestra con recifrado completo.
   - Archivo SQLite local protegido con permisos `0600` (`data/vault.db`).

2. **Organización por Categorías, Proyectos/Clientes y Entornos**
   - Clasifica por **Proveedor** (plantillas rápidas para OpenAI, Anthropic, GitHub, Shodan, VirusTotal, Cloudflare, AWS, Stripe, etc.).
   - Filtra por **Proyecto / Cliente** (ej. `mi-app`, `cliente-a`), **Categoría** (`AI / LLM`, `OSINT / Sec`, `Cloud / Infra`, etc.), **Entorno** (`prod`, `staging`, `dev`, `lab`) y **Etiquetas** (`#redteam`, `#recon`).

3. **Exportación e Importación Rápida (`.env`, Bash, JSON, Docker YAML)**
   - Copia directamente la API Key o el par `VARIABLE="VALOR"` con un clic.
   - Exportador interactivo filtrable por proyecto y entorno a formato `.env`, `export VAR='VAL'` para terminal, JSON o YAML.
   - Importador directo de archivos `.env` existentes con detección automática de proveedor.

4. **Control de Expiración, Rotación y Comprobación HTTP (Health Check)**
   - Alertas automáticas para claves vencidas, próximas a caducar (≤ 14 días) o que superaron su ciclo de rotación (ej. 90 días).
   - Flujo de **Rotación de Claves** que archiva la clave antigua cifrada en un historial consultable.
   - Botón **🩺 Probar (Health Check)** para verificar en vivo si la API Key responde `200 OK` o `401 Unauthorized` contra el endpoint del proveedor.
   - Registro completo de **Auditoría** de accesos y modificaciones.

---

## Uso rápido

### 1. Iniciar la aplicación web

```bash
~/apikey-manager/run.sh
# Por defecto abre en: http://127.0.0.1:8787
```

O especificando otro puerto/ruta de base de datos:

```bash
python3 ~/apikey-manager/app.py --port 8787 --db ~/apikey-manager/data/vault.db
```

### 2. Uso desde la terminal (CLI)

También puedes consultar o inyectar variables de entorno directamente en tus scripts sin abrir el navegador:

```bash
# Listar resumen de claves en la terminal
~/apikey-manager/run.sh list

# Exportar variables de un proyecto/entorno a un archivo .env
~/apikey-manager/run.sh export --format dotenv --project default --env prod > .env

# Cargar las variables directamente en tu sesión actual de bash/zsh
eval "$(APIKEY_VAULT_PASSWORD='tu_master_password' ~/apikey-manager/run.sh export --format shell --project default)"
```
