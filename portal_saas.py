import os
import base64
import hashlib
import hmac
import html
import re
import secrets
import smtplib
import uuid
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote_plus

import pandas as pd
import psycopg
import streamlit as st
from PIL import Image
from psycopg.rows import dict_row
from zoneinfo import ZoneInfo


@st.cache_resource
def get_connection():
    database_url = None

    if "database" in st.secrets and "url" in st.secrets["database"]:
        database_url = st.secrets["database"]["url"]
    else:
        database_url = os.getenv("DATABASE_URL")

    if not database_url:
        raise RuntimeError("DATABASE_URL não configurado.")

    return psycopg.connect(
        database_url,
        row_factory=dict_row,
        autocommit=True,
    )


def get_conn():
    return get_connection()


def reset_connection():
    get_connection.clear()
    return get_connection()


class SafeConnProxy:
    def execute(self, *args, **kwargs):
        try:
            return get_conn().execute(*args, **kwargs)
        except Exception:
            return reset_connection().execute(*args, **kwargs)

    def cursor(self, *args, **kwargs):
        try:
            return get_conn().cursor(*args, **kwargs)
        except Exception:
            return reset_connection().cursor(*args, **kwargs)


def run_query(sql, params=None, fetchone=False, fetchall=False):
    try:
        with get_conn().cursor() as cur:
            cur.execute(sql, params or ())
            if fetchone:
                return cur.fetchone()
            if fetchall:
                return cur.fetchall()
            return None
    except Exception:
        reset_connection()
        with get_conn().cursor() as cur:
            cur.execute(sql, params or ())
            if fetchone:
                return cur.fetchone()
            if fetchall:
                return cur.fetchall()
            return None


def obter_usuarios_empresa(empresa_id):
    return conn.execute(
        """
        SELECT id, nome, email, usuario, perfil, ativo, created_at
        FROM usuarios
        WHERE empresa_id = %s
        ORDER BY nome, usuario
        """,
        (empresa_id,),
    ).fetchall()


def obter_usuario_empresa_por_id(usuario_id, empresa_id):
    return conn.execute(
        """
        SELECT id, empresa_id, nome, email, usuario, perfil, ativo, created_at
        FROM usuarios
        WHERE id = %s
          AND empresa_id = %s
        LIMIT 1
        """,
        (usuario_id, empresa_id),
    ).fetchone()


def criar_usuario_empresa(empresa_id, nome, email, usuario, senha, perfil):
    if not validar_limite_usuarios_empresa(empresa_id):
        raise ValueError("Limite de usuários atingido para esta empresa.")

    usuario_existente = conn.execute(
        """
        SELECT 1
        FROM usuarios
        WHERE empresa_id = %s
          AND (usuario = %s OR email = %s)
        LIMIT 1
        """,
        (empresa_id, usuario.strip(), email.strip().lower()),
    ).fetchone()

    if usuario_existente:
        raise ValueError("Já existe um usuário ou e-mail cadastrado nesta empresa.")

    conn.execute(
        """
        INSERT INTO usuarios
        (empresa_id, nome, email, usuario, senha_hash, perfil, ativo, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """,
        (
            empresa_id,
            nome.strip(),
            email.strip().lower(),
            usuario.strip(),
            gerar_hash_senha(senha.strip()),
            perfil,
        ),
    )


def criar_empresa_onboarding(nome_empresa, cnpj=None, plano="starter"):
    nome_empresa = (nome_empresa or "").strip()
    cnpj_limpo = re.sub(r"\D", "", cnpj or "")

    if not nome_empresa:
        raise ValueError("Informe o nome da empresa.")

    if cnpj_limpo:
        empresa_existente = conn.execute(
            """
            SELECT id
            FROM empresas
            WHERE cnpj = %s
            LIMIT 1
            """,
            (cnpj_limpo,),
        ).fetchone()
        if empresa_existente:
            raise ValueError("Já existe uma empresa cadastrada com este CNPJ.")
    else:
        empresa_existente = conn.execute(
            """
            SELECT id
            FROM empresas
            WHERE LOWER(TRIM(fantasia)) = LOWER(TRIM(%s))
            LIMIT 1
            """,
            (nome_empresa,),
        ).fetchone()
        if empresa_existente:
            raise ValueError("Já existe uma empresa cadastrada com este nome.")

    limites = {
        "starter": {"usuarios": 10, "colaboradores": 100},
        "pro": {"usuarios": 25, "colaboradores": 300},
        "enterprise": {"usuarios": None, "colaboradores": None},
    }
    plano = (plano or "starter").lower()
    if plano not in limites:
        plano = "starter"

    resultado = conn.execute(
        """
        INSERT INTO empresas (
            razao_social,
            fantasia,
            cnpj,
            ativo,
            plano,
            limite_colaboradores,
            limite_usuarios
        )
        VALUES (%s, %s, %s, TRUE, %s, %s, %s)
        RETURNING id
        """,
        (
            nome_empresa,
            nome_empresa,
            cnpj_limpo or None,
            plano,
            limites[plano]["colaboradores"],
            limites[plano]["usuarios"],
        ),
    ).fetchone()

    return resultado["id"]


def atualizar_usuario_empresa(
    usuario_id, empresa_id, nome, email, usuario, perfil, ativo, nova_senha=None
):
    usuario_existente = conn.execute(
        """
        SELECT 1
        FROM usuarios
        WHERE empresa_id = %s
          AND id <> %s
          AND (usuario = %s OR email = %s)
        LIMIT 1
        """,
        (empresa_id, usuario_id, usuario.strip(), email.strip().lower()),
    ).fetchone()

    if usuario_existente:
        raise ValueError("Já existe outro usuário ou e-mail cadastrado nesta empresa.")

    if nova_senha and nova_senha.strip():
        conn.execute(
            """
            UPDATE usuarios
            SET nome = %s,
                email = %s,
                usuario = %s,
                perfil = %s,
                ativo = %s,
                senha_hash = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
              AND empresa_id = %s
            """,
            (
                nome.strip(),
                email.strip().lower(),
                usuario.strip(),
                perfil,
                ativo,
                gerar_hash_senha(nova_senha.strip()),
                usuario_id,
                empresa_id,
            ),
        )
    else:
        conn.execute(
            """
            UPDATE usuarios
            SET nome = %s,
                email = %s,
                usuario = %s,
                perfil = %s,
                ativo = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
              AND empresa_id = %s
            """,
            (
                nome.strip(),
                email.strip().lower(),
                usuario.strip(),
                perfil,
                ativo,
                usuario_id,
                empresa_id,
            ),
        )


def formatar_cnpj(cnpj):
    cnpj = re.sub(r"\D", "", cnpj or "")
    if len(cnpj) == 14:
        return f"{cnpj[:2]}.{cnpj[2:5]}.{cnpj[5:8]}/{cnpj[8:12]}-{cnpj[12:]}"
    return cnpj


def formatar_cpf(cpf):
    cpf = re.sub(r"\D", "", cpf or "")
    if len(cpf) == 11:
        return f"{cpf[:3]}.{cpf[3:6]}.{cpf[6:9]}-{cpf[9:]}"
    return cpf


def validar_cnpj(cnpj):
    return len(re.sub(r"\D", "", cnpj or "")) == 14


def validar_cpf(cpf):
    return len(re.sub(r"\D", "", cpf or "")) == 11


st.set_page_config(page_title="Gestão RH", layout="wide")

BASE_DIR = Path(__file__).parent
APP_DATA_DIR = Path.home() / ".businessvision"
APP_DATA_DIR.mkdir(parents=True, exist_ok=True)

logo_candidates = [
    BASE_DIR / "app" / "imagens" / "logo.png",
    BASE_DIR / "app" / "imagens" / "Logo.png",
    BASE_DIR / "imagens" / "logo.png",
    BASE_DIR / "imagens" / "Logo.png",
    BASE_DIR / "Logo.png",
    BASE_DIR / "logo.png",
    BASE_DIR.parent / "app" / "imagens" / "logo.png",
    BASE_DIR.parent / "app" / "imagens" / "Logo.png",
    BASE_DIR.parent / "Logo.png",
    BASE_DIR.parent / "logo.png",
]
logo_path = next((p for p in logo_candidates if p.exists()), None)

APP_TZ = ZoneInfo("America/Santarem")
conn = SafeConnProxy()

PASSWORD_SCHEME = "pbkdf2_sha256"
PASSWORD_ITERATIONS = 390000
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "8"))
CONVITE_EXPIRACAO_HORAS = int(os.getenv("CONVITE_EXPIRACAO_HORAS", "72"))


def obter_secret(path, default=None):
    try:
        cursor = st.secrets
        for key in path:
            cursor = cursor[key]
        return cursor
    except Exception:
        return default


def obter_app_base_url():
    return (obter_secret(["APP_BASE_URL"]) or os.getenv("APP_BASE_URL") or "").strip()


def obter_email_config():
    cfg = obter_secret(["email"], {}) or {}
    return {
        "host": (cfg.get("host") or os.getenv("SMTP_HOST") or "").strip(),
        "port": int(cfg.get("port") or os.getenv("SMTP_PORT") or 587),
        "user": (cfg.get("user") or os.getenv("SMTP_USER") or "").strip(),
        "password": (cfg.get("password") or os.getenv("SMTP_PASSWORD") or "").strip(),
        "from_name": (
            cfg.get("from_name") or os.getenv("SMTP_FROM_NAME") or "Gestão RH"
        ).strip(),
        "from_email": (
            cfg.get("from_email") or os.getenv("SMTP_FROM_EMAIL") or ""
        ).strip(),
    }


def get_empresa_id():
    empresa_id = st.session_state.get("empresa_id")
    if not empresa_id:
        raise RuntimeError("Sessão sem empresa_id.")
    return empresa_id


def get_user_id():
    user_id = st.session_state.get("user_id")
    if not user_id:
        raise RuntimeError("Sessão sem user_id.")
    return user_id


def get_perfil():
    perfil = st.session_state.get("perfil")
    if not perfil:
        raise RuntimeError("Sessão sem perfil.")
    return perfil


def exigir_perfil(*perfis):
    perfil = st.session_state.get("perfil")
    if perfil not in perfis:
        st.error("Você não possui permissão para acessar esta funcionalidade.")
        st.stop()


def obter_usuario_por_login(login):
    return conn.execute(
        """
        SELECT
            u.id,
            u.empresa_id,
            u.nome,
            u.email,
            u.usuario,
            u.senha_hash,
            u.perfil,
            u.ativo,
            e.fantasia AS empresa_nome,
            e.ativo AS empresa_ativa,
            e.plano
        FROM usuarios u
        JOIN empresas e ON e.id = u.empresa_id
        WHERE (u.usuario = %s OR u.email = %s)
          AND u.ativo = TRUE
          AND e.ativo = TRUE
        LIMIT 1
        """,
        (login, login),
    ).fetchone()


def autenticar_usuario(login_digitado, senha_digitada):
    usuario = obter_usuario_por_login(login_digitado)

    if not usuario:
        return None

    if not verificar_senha(senha_digitada, usuario["senha_hash"]):
        return None

    return usuario


def registrar_sessao_usuario(usuario, menu_inicial=None):
    perfil = usuario["perfil"]
    menu_padrao = menu_inicial or (
        "Dashboard RH" if perfil in ("admin", "gestor") else "Nova Solicitação"
    )
    token = criar_sessao_login(
        usuario=usuario["usuario"],
        perfil=perfil,
        menu=menu_padrao,
        user_id=usuario["id"],
        empresa_id=usuario["empresa_id"],
    )
    st.session_state.logado = True
    st.session_state.user_id = usuario["id"]
    st.session_state.empresa_id = usuario["empresa_id"]
    st.session_state.empresa_nome = usuario.get("empresa_nome") or ""
    st.session_state.usuario = usuario["usuario"]
    st.session_state.nome_usuario = usuario.get("nome") or usuario["usuario"]
    st.session_state.perfil = perfil
    st.session_state.plano = usuario.get("plano") or ""
    st.session_state.menu_atual = menu_padrao
    st.session_state.token_sessao = token
    persistir_query_params()


def email_configurada():
    cfg = obter_email_config()
    return all(
        [cfg["host"], cfg["port"], cfg["user"], cfg["password"], cfg["from_email"]]
    )


def enviar_email_convite(destinatario, nome, link):
    cfg = obter_email_config()

    if not all(
        [cfg["host"], cfg["port"], cfg["user"], cfg["password"], cfg["from_email"]]
    ):
        return False, "Configuração de e-mail não encontrada em st.secrets['email']."

    assunto = "Convite - Gestão RH"

    html_body = f"""
<html>
  <body style="margin:0; padding:0; background:#0B1E33;">

    <table width="100%" cellpadding="0" cellspacing="0" style="background:#0B1E33; padding:30px 0;">
      <tr>
        <td align="center">

          <table width="500" cellpadding="0" cellspacing="0" style="background:#0F2744; border-radius:10px; padding:30px;">

            <!-- LOGO -->
            <tr>
              <td align="center" style="padding-bottom:20px;">
                <img src="SUA_URL_DA_LOGO_AQUI" width="100" />
              </td>
            </tr>

            <!-- TÍTULO -->
            <tr>
              <td align="center" style="color:#ffffff; font-size:20px; font-weight:bold;">
                Convite para acesso ao portal
              </td>
            </tr>

            <!-- TEXTO -->
            <tr>
              <td align="center" style="color:#cfe3ff; font-size:14px; padding-top:15px;">
                Olá, {nome}.<br><br>
                Você recebeu um convite para concluir seu cadastro no Gestão RH.
              </td>
            </tr>

            <!-- BOTÃO -->
            <tr>
              <td align="center" style="padding:25px 0;">
                <a href="{link}" 
                   style="background:#17427A;
                          color:#ffffff;
                          padding:12px 20px;
                          text-decoration:none;
                          border-radius:6px;
                          font-weight:bold;
                          display:inline-block;">
                  Concluir cadastro
                </a>
              </td>
            </tr>

            <!-- LINK -->
            <tr>
              <td align="center" style="color:#8fb3ff; font-size:12px;">
                Caso o botão não funcione, copie o link:<br><br>
                <span style="word-break:break-all;">{link}</span>
              </td>
            </tr>

            <!-- DIVISOR -->
            <tr>
              <td style="padding:25px 0;">
                <hr style="border:0; border-top:1px solid #1f3b5c;">
              </td>
            </tr>

            <!-- RODAPÉ -->
            <tr>
              <td align="center" style="color:#7ea6d9; font-size:12px;">
                Gestão RH<br>
                Plataforma de gestão de pessoas<br><br>
                Este e-mail foi enviado automaticamente.
              </td>
            </tr>

          </table>

        </td>
      </tr>
    </table>

  </body>
</html>
"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = assunto
    msg["From"] = f'{cfg["from_name"]} <{cfg["from_email"]}>'
    msg["To"] = destinatario
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(cfg["user"], cfg["password"])
            server.sendmail(cfg["user"], [destinatario], msg.as_string())

        return True, "E-mail enviado com sucesso."

    except smtplib.SMTPAuthenticationError as exc:
        return False, f"Falha SMTP (credenciais inválidas). Detalhe: {exc}"

    except Exception as exc:
        return False, f"Falha ao enviar e-mail: {exc}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = assunto
    msg["From"] = f'{cfg["from_name"]} <{cfg["from_email"]}>'
    msg["To"] = destinatario
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        with smtplib.SMTP(cfg["host"], cfg["port"], timeout=30) as server:
            server.starttls()
            server.login(cfg["user"], cfg["password"])
            server.sendmail(cfg["from_email"], [destinatario], msg.as_string())
        return True, "E-mail enviado com sucesso."
    except Exception as exc:
        return False, f"Falha ao enviar e-mail: {exc}"


def obter_admin_config():
    admin_user = (
        obter_secret(["admin", "user"]) or os.getenv("ADMIN_USER") or ""
    ).strip()

    admin_password_hash = (
        obter_secret(["admin", "password_hash"])
        or os.getenv("ADMIN_PASSWORD_HASH")
        or ""
    ).strip()

    admin_password_plain = (
        obter_secret(["admin", "password"]) or os.getenv("ADMIN_PASSWORD") or ""
    ).strip()

    return {
        "user": admin_user,
        "password_hash": admin_password_hash,
        "password_plain": admin_password_plain,
    }


def senha_esta_hasheada(valor):
    return isinstance(valor, str) and valor.startswith(f"{PASSWORD_SCHEME}$")


def gerar_hash_senha(senha):
    if not isinstance(senha, str) or not senha.strip():
        raise ValueError("Senha inválida para geração de hash.")

    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        senha.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_ITERATIONS,
    )
    return f"{PASSWORD_SCHEME}${PASSWORD_ITERATIONS}${salt}${dk.hex()}"


def verificar_senha(senha_informada, senha_armazenada):
    if not senha_armazenada or not isinstance(senha_armazenada, str):
        return False

    if senha_esta_hasheada(senha_armazenada):
        try:
            _, iteracoes, salt, hash_salvo = senha_armazenada.split("$", 3)
            dk = hashlib.pbkdf2_hmac(
                "sha256",
                (senha_informada or "").encode("utf-8"),
                salt.encode("utf-8"),
                int(iteracoes),
            )
            return hmac.compare_digest(dk.hex(), hash_salvo)
        except Exception:
            return False

    return hmac.compare_digest(senha_armazenada, senha_informada or "")


def autenticar_admin(usuario_digitado, senha_digitada):
    config = obter_admin_config()
    admin_user = config["user"]
    admin_password_hash = config["password_hash"]
    admin_password_plain = config["password_plain"]

    if not admin_user or usuario_digitado != admin_user:
        return False

    if admin_password_hash:
        return verificar_senha(senha_digitada, admin_password_hash)

    if admin_password_plain:
        return hmac.compare_digest(admin_password_plain, senha_digitada or "")

    return False


def obter_cliente_por_usuario(usuario):
    return conn.execute(
        """
        SELECT id, usuario, senha, nome, ativo, cpf, empresa_id, funcao, email
        FROM clientes
        WHERE usuario = %s
        LIMIT 1
        """,
        (usuario,),
    ).fetchone()


def autenticar_cliente(usuario_digitado, senha_digitada):
    cliente = obter_cliente_por_usuario(usuario_digitado)

    if not cliente or not bool(cliente["ativo"]):
        return None

    senha_salva = cliente["senha"] or ""
    autenticado = verificar_senha(senha_digitada, senha_salva)

    if autenticado and not senha_esta_hasheada(senha_salva):
        conn.execute(
            "UPDATE clientes SET senha = %s WHERE id = %s",
            (gerar_hash_senha(senha_digitada), cliente["id"]),
        )
        cliente = obter_cliente_por_usuario(usuario_digitado)

    return cliente if autenticado else None


def obter_atendente_por_usuario(usuario):
    return conn.execute(
        """
        SELECT id, nome, usuario, senha, email, ativo, created_at
        FROM atendentes
        WHERE usuario = %s
        LIMIT 1
        """,
        (usuario,),
    ).fetchone()


def autenticar_atendente(usuario_digitado, senha_digitada):
    atendente = obter_atendente_por_usuario(usuario_digitado)
    if not atendente or not bool(atendente["ativo"]):
        return None

    if verificar_senha(senha_digitada, atendente["senha"] or ""):
        return atendente
    return None


def validar_upload_imagem(arquivo):
    nome = (arquivo.name or "").lower()
    ext_permitidas = {".png", ".jpg", ".jpeg"}
    ext = Path(nome).suffix.lower()

    if ext not in ext_permitidas:
        return False, "Tipo de arquivo inválido. Envie apenas PNG, JPG ou JPEG."

    tamanho = len(arquivo.getvalue())
    limite = MAX_UPLOAD_MB * 1024 * 1024
    if tamanho > limite:
        return (
            False,
            f"O arquivo {arquivo.name} excede o limite de {MAX_UPLOAD_MB} MB.",
        )

    return True, ""


admin_config = obter_admin_config()
admin_user = admin_config["user"]


def carregar_logo():
    try:
        if logo_path and logo_path.exists():
            return Image.open(logo_path)
    except Exception:
        pass
    return None


def carregar_logo_base64():
    try:
        if logo_path and logo_path.exists():
            return base64.b64encode(logo_path.read_bytes()).decode()
    except Exception:
        pass
    return None


logo = carregar_logo()
logo_b64 = carregar_logo_base64()


def aplicar_estilo_login():
    st.markdown(
        """
        <style>
        .stApp {
            background: linear-gradient(135deg, #0f172a, #1e3a8a);
        }

        .block-container {
            max-width: 1400px;
            padding-top: 2rem !important;
            padding-bottom: 2rem !important;
        }

        input {
            border-radius: 8px !important;
        }

        button[kind="primary"] {
            background-color: #1e40af !important;
            color: white !important;
            border-radius: 8px !important;
        }
        </style>
    """,
        unsafe_allow_html=True,
    )


def agora():
    return datetime.now(APP_TZ)


def agora_str():
    return agora().strftime("%Y-%m-%d %H:%M:%S")


def coluna_existe(nome_tabela, nome_coluna):
    row = conn.execute(
        """
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = %s
          AND column_name = %s
        LIMIT 1
        """,
        (nome_tabela, nome_coluna),
    ).fetchone()
    return row is not None


def criar_tabelas():
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS empresas (
            id BIGSERIAL PRIMARY KEY,
            cnpj TEXT,
            razao_social TEXT,
            fantasia TEXT,
            cep TEXT,
            logradouro TEXT,
            numero TEXT,
            bairro TEXT,
            cidade TEXT,
            ativo BOOLEAN DEFAULT TRUE
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS usuarios (
            id BIGSERIAL PRIMARY KEY,
            empresa_id BIGINT NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
            nome TEXT NOT NULL,
            email TEXT NOT NULL,
            usuario TEXT NOT NULL,
            senha_hash TEXT NOT NULL,
            perfil TEXT NOT NULL,
            ativo BOOLEAN DEFAULT TRUE,
            ultimo_login_em TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (empresa_id, email),
            UNIQUE (empresa_id, usuario)
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS clientes (
            id BIGSERIAL PRIMARY KEY,
            usuario TEXT UNIQUE,
            senha TEXT,
            nome TEXT,
            ativo BOOLEAN DEFAULT TRUE
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS solicitacoes (
            id BIGSERIAL PRIMARY KEY,
            cliente TEXT,
            titulo TEXT,
            descricao TEXT,
            prioridade TEXT,
            status TEXT,
            complexidade TEXT,
            resposta TEXT,
            data_criacao TIMESTAMP,
            inicio_atendimento TIMESTAMP,
            fim_atendimento TIMESTAMP
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS anexos (
            id BIGSERIAL PRIMARY KEY,
            solicitacao_id BIGINT NOT NULL REFERENCES solicitacoes(id) ON DELETE CASCADE,
            nome_arquivo TEXT,
            observacao TEXT,
            imagem BYTEA,
            data_criacao TIMESTAMP
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sessoes_login (
            token TEXT PRIMARY KEY,
            usuario TEXT NOT NULL,
            usuario_id BIGINT,
            empresa_id BIGINT,
            menu TEXT,
            perfil TEXT,
            data_criacao TIMESTAMP
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS atendentes (
            id BIGSERIAL PRIMARY KEY,
            nome TEXT NOT NULL,
            usuario TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            email TEXT,
            ativo BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS convites_cadastro (
            id BIGSERIAL PRIMARY KEY,
            nome TEXT NOT NULL,
            email TEXT NOT NULL,
            empresa_id BIGINT REFERENCES empresas(id),
            tipo_usuario TEXT NOT NULL,
            token TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'pendente',
            observacao TEXT,
            usuario_sugerido TEXT,
            enviado_em TIMESTAMP,
            expiracao_em TIMESTAMP,
            utilizado_em TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS filiais (
            id BIGSERIAL PRIMARY KEY,
            empresa_id BIGINT REFERENCES empresas(id),
            nome TEXT NOT NULL,
            cidade TEXT,
            uf TEXT,
            licenca TEXT,
            ativo BOOLEAN DEFAULT TRUE
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS setores (
            id BIGSERIAL PRIMARY KEY,
            empresa_id BIGINT REFERENCES empresas(id),
            nome TEXT NOT NULL,
            ativo BOOLEAN DEFAULT TRUE
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS cargos (
            id BIGSERIAL PRIMARY KEY,
            empresa_id BIGINT REFERENCES empresas(id),
            nome TEXT NOT NULL,
            ativo BOOLEAN DEFAULT TRUE
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS colaboradores (
            id BIGSERIAL PRIMARY KEY,
            empresa_id BIGINT REFERENCES empresas(id),
            matricula TEXT,
            nome TEXT NOT NULL,
            cpf TEXT,
            data_nascimento DATE,
            data_admissao DATE,
            data_desligamento DATE,
            email TEXT,
            telefone TEXT,
            filial_id BIGINT REFERENCES filiais(id),
            setor_id BIGINT REFERENCES setores(id),
            cargo_id BIGINT REFERENCES cargos(id),
            status TEXT DEFAULT 'Ativo',
            ativo BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    if not coluna_existe("filiais", "licenca"):
        conn.execute("ALTER TABLE filiais ADD COLUMN licenca TEXT")
    if not coluna_existe("filiais", "empresa_id"):
        conn.execute(
            "ALTER TABLE filiais ADD COLUMN empresa_id BIGINT REFERENCES empresas(id)"
        )
    if not coluna_existe("setores", "empresa_id"):
        conn.execute(
            "ALTER TABLE setores ADD COLUMN empresa_id BIGINT REFERENCES empresas(id)"
        )
    if not coluna_existe("cargos", "empresa_id"):
        conn.execute(
            "ALTER TABLE cargos ADD COLUMN empresa_id BIGINT REFERENCES empresas(id)"
        )
    if not coluna_existe("colaboradores", "empresa_id"):
        conn.execute(
            "ALTER TABLE colaboradores ADD COLUMN empresa_id BIGINT REFERENCES empresas(id)"
        )

    if not coluna_existe("clientes", "cpf"):
        conn.execute("ALTER TABLE clientes ADD COLUMN cpf TEXT")
    if not coluna_existe("clientes", "empresa_id"):
        conn.execute(
            "ALTER TABLE clientes ADD COLUMN empresa_id BIGINT REFERENCES empresas(id)"
        )
    if not coluna_existe("clientes", "funcao"):
        conn.execute("ALTER TABLE clientes ADD COLUMN funcao TEXT")
    if not coluna_existe("clientes", "email"):
        conn.execute("ALTER TABLE clientes ADD COLUMN email TEXT")

    if not coluna_existe("empresas", "ativo"):
        conn.execute("ALTER TABLE empresas ADD COLUMN ativo BOOLEAN DEFAULT TRUE")
    if not coluna_existe("empresas", "plano"):
        conn.execute("ALTER TABLE empresas ADD COLUMN plano TEXT DEFAULT 'starter'")
    if not coluna_existe("empresas", "limite_colaboradores"):
        conn.execute("ALTER TABLE empresas ADD COLUMN limite_colaboradores INTEGER")
    if not coluna_existe("empresas", "limite_usuarios"):
        conn.execute("ALTER TABLE empresas ADD COLUMN limite_usuarios INTEGER")

    for coluna in [
        "cliente_id",
        "empresa_id",
        "atendente_id",
        "atribuido_em",
        "complexidade",
        "resposta",
        "data_criacao",
        "inicio_atendimento",
        "fim_atendimento",
    ]:
        if not coluna_existe("solicitacoes", coluna):
            if coluna in ["cliente_id", "empresa_id", "atendente_id"]:
                conn.execute(f"ALTER TABLE solicitacoes ADD COLUMN {coluna} BIGINT")
            elif coluna in [
                "data_criacao",
                "inicio_atendimento",
                "fim_atendimento",
                "atribuido_em",
            ]:
                conn.execute(f"ALTER TABLE solicitacoes ADD COLUMN {coluna} TIMESTAMP")
            else:
                conn.execute(f"ALTER TABLE solicitacoes ADD COLUMN {coluna} TEXT")

    if not coluna_existe("sessoes_login", "menu"):
        conn.execute("ALTER TABLE sessoes_login ADD COLUMN menu TEXT")
    if not coluna_existe("sessoes_login", "perfil"):
        conn.execute("ALTER TABLE sessoes_login ADD COLUMN perfil TEXT")
    if not coluna_existe("sessoes_login", "usuario_id"):
        conn.execute("ALTER TABLE sessoes_login ADD COLUMN usuario_id BIGINT")
    if not coluna_existe("sessoes_login", "empresa_id"):
        conn.execute("ALTER TABLE sessoes_login ADD COLUMN empresa_id BIGINT")

    if not coluna_existe("convites_cadastro", "observacao"):
        conn.execute("ALTER TABLE convites_cadastro ADD COLUMN observacao TEXT")
    if not coluna_existe("convites_cadastro", "usuario_sugerido"):
        conn.execute("ALTER TABLE convites_cadastro ADD COLUMN usuario_sugerido TEXT")


RUN_DB_BOOTSTRAP = os.getenv("RUN_DB_BOOTSTRAP", "false").lower() == "true"
if RUN_DB_BOOTSTRAP:
    criar_tabelas()


def init_state():
    defaults = {
        "logado": False,
        "user_id": None,
        "empresa_id": None,
        "empresa_nome": "",
        "usuario": "",
        "nome_usuario": "",
        "perfil": "",
        "plano": "",
        "menu_atual": "Dashboard RH",
        "titulo": "",
        "descricao": "",
        "mostrar_legenda": False,
        "limpar_campos_nova_solicitacao": False,
        "token_sessao": None,
        "modo_acesso": "login",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


init_state()


def gerar_usuario(nome):
    partes = [p for p in re.split(r"\s+", (nome or "").strip().lower()) if p]
    if not partes:
        return ""
    usuario = f"{partes[0]}_{partes[-1]}" if len(partes) > 1 else partes[0]
    return re.sub(r"[^a-z0-9_]", "", usuario)


def criar_sessao_login(
    usuario, perfil, menu="Dashboard RH", user_id=None, empresa_id=None
):
    token = str(uuid.uuid4())
    conn.execute(
        """
        INSERT INTO sessoes_login (token, usuario, usuario_id, empresa_id, menu, perfil, data_criacao)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (token)
        DO UPDATE SET
            usuario = EXCLUDED.usuario,
            usuario_id = EXCLUDED.usuario_id,
            empresa_id = EXCLUDED.empresa_id,
            menu = EXCLUDED.menu,
            perfil = EXCLUDED.perfil,
            data_criacao = EXCLUDED.data_criacao
        """,
        (token, usuario, user_id, empresa_id, menu, perfil, agora()),
    )
    return token


def atualizar_menu_sessao(token, menu):
    if not token:
        return
    conn.execute(
        "UPDATE sessoes_login SET menu = %s WHERE token = %s",
        (menu, token),
    )


def obter_sessao(token):
    if not token:
        return None
    return conn.execute(
        """
        SELECT token, usuario, usuario_id, empresa_id, menu, perfil, data_criacao
        FROM sessoes_login
        WHERE token = %s
        """,
        (token,),
    ).fetchone()


def excluir_sessao(token):
    if not token:
        return
    conn.execute("DELETE FROM sessoes_login WHERE token = %s", (token,))


def restaurar_login():
    token = st.query_params.get("token")
    if not token:
        return
    sessao = obter_sessao(token)
    if not sessao:
        return

    usuario = None
    if sessao.get("usuario_id"):
        usuario = conn.execute(
            """
            SELECT
                u.id,
                u.empresa_id,
                u.nome,
                u.email,
                u.usuario,
                u.perfil,
                u.ativo,
                e.fantasia AS empresa_nome,
                e.plano,
                e.ativo AS empresa_ativa
            FROM usuarios u
            JOIN empresas e ON e.id = u.empresa_id
            WHERE u.id = %s
              AND u.ativo = TRUE
              AND e.ativo = TRUE
            LIMIT 1
            """,
            (sessao["usuario_id"],),
        ).fetchone()

    if not usuario and sessao.get("usuario"):
        usuario = obter_usuario_por_login(sessao["usuario"])

    if not usuario:
        return

    st.session_state.logado = True
    st.session_state.user_id = usuario["id"]
    st.session_state.empresa_id = usuario["empresa_id"]
    st.session_state.empresa_nome = usuario.get("empresa_nome") or ""
    st.session_state.usuario = usuario["usuario"]
    st.session_state.nome_usuario = usuario.get("nome") or usuario["usuario"]
    st.session_state.perfil = usuario["perfil"]
    st.session_state.plano = usuario.get("plano") or ""
    st.session_state.menu_atual = sessao["menu"] or (
        "Dashboard RH"
        if usuario["perfil"] in ("admin", "gestor")
        else "Nova Solicitação"
    )
    st.session_state.token_sessao = token


def persistir_query_params():
    if st.session_state.get("token_sessao"):
        st.query_params["token"] = st.session_state.token_sessao
    else:
        if "token" in st.query_params:
            del st.query_params["token"]


if not st.session_state.logado:
    restaurar_login()
    persistir_query_params()

if not st.session_state.logado:
    aplicar_estilo_login()
    ...
    st.stop()

    modo_acesso = st.session_state.get("modo_acesso", "login")

    st.markdown(
        """
        <style>
        .login-shell {
        min-height: calc(100vh - 4rem);
        display: flex;
        align-items: center;
    }
            .login-brand {
            min-height: 760px;
            border-radius: 28px;
            padding: 56px 48px;
            background: linear-gradient(160deg, #071728 0%, #0b2d55 55%, #123c71 100%);
            color: #f3f7fb;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            border: 1px solid rgba(255,255,255,0.08);
            box-shadow: 0 20px 60px rgba(0,0,0,0.25);
        }
        .login-brand h1 {
            font-size: 42px;
            line-height: 1.05;
            margin: 26px 0 14px 0;
            color: #ffffff;
            font-weight: 800;
        }
        .login-brand p {
            font-size: 17px;
            line-height: 1.7;
            color: #d7e6f7;
            margin: 0 0 22px 0;
        }
        .login-brand ul {
            list-style: none;
            padding: 0;
            margin: 24px 0 0 0;
        }
        .login-brand li {
            margin: 0 0 14px 0;
            color: #e7f0fb;
            font-size: 15px;
        }
        .login-brand .brand-kicker {
            color: #8fc2ff;
            font-weight: 700;
            letter-spacing: .08em;
            text-transform: uppercase;
            font-size: 12px;
        }
        .login-brand .brand-footer {
            color: #aac7e8;
            font-size: 13px;
        }
        .login-panel-wrap {
            min-height: 760px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-panel {
            width: 100%;
            max-width: 520px;
            background: rgba(5, 22, 38, 0.72);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 24px;
            padding: 34px 30px 28px 30px;
            box-shadow: 0 18px 54px rgba(0,0,0,0.22);
        }
        .login-panel h2 {
            margin: 0 0 8px 0;
            text-align: center;
            color: #ffffff;
            font-size: 18px;
            font-weight: 800;
            letter-spacing: .02em;
        }
        .login-panel .sub {
            text-align: center;
            color: #c8d8eb;
            font-size: 14px;
            margin-bottom: 18px;
        }
        .login-mode-row {
            margin-bottom: 18px;
        }
        @media (max-width: 980px) {
            .login-brand, .login-panel-wrap {
                min-height: auto;
            }
            .login-brand {
                padding: 36px 28px;
            }
            .login-brand h1 {
                font-size: 34px;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="login-shell">', unsafe_allow_html=True)
    col_left, col_right = st.columns([1.05, 0.95], gap="large")

    with col_left:
        st.markdown('<div class="login-brand">', unsafe_allow_html=True)
        if logo_b64:
            st.markdown(
                f"""
                <div>
                    <img src='data:image/png;base64,{logo_b64}' style='max-width:180px; width:100%; height:auto;'>
                </div>
                """,
                unsafe_allow_html=True,
            )
        st.markdown(
            """
            <div>
                <div class="brand-kicker">Plataforma corporativa</div>
                <h1>Gestão RH para empresas que exigem controle.</h1>
                <p>Centralize estrutura organizacional, usuários, colaboradores e indicadores em um ambiente seguro, profissional e preparado para crescer com a operação.</p>
                <ul>
                    <li>✔ Controle do quadro em tempo real</li>
                    <li>✔ Estrutura por filiais, setores e cargos</li>
                    <li>✔ Acesso segregado por empresa</li>
                </ul>
            </div>
            <div class="brand-footer">Ambiente seguro, arquitetura SaaS e gestão orientada por dados.</div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with col_right:
        st.markdown(
            '<div class="login-panel-wrap"><div class="login-panel">',
            unsafe_allow_html=True,
        )

        bt1, bt2 = st.columns(2)
        with bt1:
            if st.button(
                "Entrar",
                key="btn_modo_login",
                use_container_width=True,
                type="primary" if modo_acesso == "login" else "secondary",
            ):
                st.session_state.modo_acesso = "login"
                st.rerun()
        with bt2:
            if st.button(
                "Criar conta",
                key="btn_modo_cadastro",
                use_container_width=True,
                type="primary" if modo_acesso == "cadastro" else "secondary",
            ):
                st.session_state.modo_acesso = "cadastro"
                st.rerun()

        if modo_acesso == "cadastro":
            st.markdown("<h2>Crie sua conta</h2>", unsafe_allow_html=True)
            st.markdown(
                "<div class='sub'>Crie sua empresa e seu acesso administrador.</div>",
                unsafe_allow_html=True,
            )

            nome_empresa = st.text_input("Nome da empresa", key="cad_empresa_nome")
            cnpj_empresa = st.text_input("CNPJ (opcional)", key="cad_empresa_cnpj")
            nome_admin = st.text_input("Seu nome", key="cad_admin_nome")
            email_admin = st.text_input("Seu e-mail", key="cad_admin_email")
            usuario_admin_cad = st.text_input("Usuário", key="cad_admin_usuario")
            senha_admin_cad = st.text_input(
                "Senha", type="password", key="cad_admin_senha"
            )
            confirmar_senha_admin_cad = st.text_input(
                "Confirmar senha", type="password", key="cad_admin_senha_confirmar"
            )

            if st.button(
                "Criar minha conta",
                key="btn_criar_minha_conta",
                use_container_width=True,
            ):
                if not nome_empresa.strip():
                    st.error("Informe o nome da empresa.")
                elif cnpj_empresa.strip() and not validar_cnpj(cnpj_empresa.strip()):
                    st.error("CNPJ inválido.")
                elif not nome_admin.strip():
                    st.error("Informe seu nome.")
                elif not email_admin.strip():
                    st.error("Informe seu e-mail.")
                elif not usuario_admin_cad.strip():
                    st.error("Informe o usuário administrador.")
                elif len(senha_admin_cad.strip()) < 6:
                    st.error("A senha deve ter pelo menos 6 caracteres.")
                elif senha_admin_cad != confirmar_senha_admin_cad:
                    st.error("As senhas não conferem.")
                else:
                    try:
                        empresa_id_nova = criar_empresa_onboarding(
                            nome_empresa=nome_empresa,
                            cnpj=cnpj_empresa,
                            plano="starter",
                        )
                        criar_usuario_empresa(
                            empresa_id=empresa_id_nova,
                            nome=nome_admin,
                            email=email_admin,
                            usuario=usuario_admin_cad,
                            senha=senha_admin_cad,
                            perfil="admin",
                        )
                        usuario_criado = obter_usuario_por_login(
                            usuario_admin_cad.strip()
                        )
                        if not usuario_criado:
                            raise ValueError(
                                "Conta criada, mas não foi possível localizar o usuário para login."
                            )
                        registrar_sessao_usuario(usuario_criado)
                        st.success("Conta criada com sucesso.")
                        st.rerun()
                    except ValueError as exc:
                        st.error(str(exc))
                    except Exception as exc:
                        st.error(f"Erro ao criar conta: {exc}")
        else:
            st.markdown("<h2>Acessar plataforma</h2>", unsafe_allow_html=True)
            st.markdown(
                "<div class='sub'>Entre com seu e-mail ou usuário corporativo.</div>",
                unsafe_allow_html=True,
            )

            usuario_input = st.text_input(
                "E-mail ou usuário",
                placeholder="Digite seu e-mail ou usuário",
                key="login_usuario_input",
            )
            senha_input = st.text_input(
                "Senha",
                type="password",
                placeholder="Digite sua senha",
                key="login_senha_input",
            )

            if st.button("Entrar", key="btn_login_submit", use_container_width=True):
                usuario_digitado = usuario_input.strip()
                senha_digitada = senha_input.strip()

                if not usuario_digitado or not senha_digitada:
                    st.error("Informe usuário e senha.")
                else:
                    usuario = autenticar_usuario(usuario_digitado, senha_digitada)
                    if usuario:
                        registrar_sessao_usuario(usuario)
                        st.rerun()
                    elif autenticar_admin(usuario_digitado, senha_digitada):
                        st.error(
                            "O acesso master legado não está habilitado neste fluxo SaaS. Cadastre este usuário na tabela usuarios."
                        )
                    else:
                        st.error("Usuário ou senha inválidos.")

            st.caption("Ambiente seguro e preparado para empresas.")

        st.markdown("</div></div>", unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()


def validar_limite_usuarios_empresa(empresa_id):
    empresa = conn.execute(
        """
        SELECT limite_usuarios
        FROM empresas
        WHERE id = %s
        LIMIT 1
        """,
        (empresa_id,),
    ).fetchone()

    total = conn.execute(
        """
        SELECT COUNT(*) AS total
        FROM usuarios
        WHERE empresa_id = %s
        """,
        (empresa_id,),
    ).fetchone()

    limite = empresa["limite_usuarios"] if empresa else None
    quantidade = total["total"] if total else 0

    if limite is None:
        return True

    return quantidade < limite


def validar_limite_colaboradores(empresa_id):
    empresa = conn.execute(
        """
        SELECT limite_colaboradores
        FROM empresas
        WHERE id = %s
        LIMIT 1
        """,
        (empresa_id,),
    ).fetchone()

    total = conn.execute(
        """
        SELECT COUNT(*) AS total
        FROM colaboradores
        WHERE empresa_id = %s
          AND ativo = TRUE
        """,
        (empresa_id,),
    ).fetchone()

    limite = empresa["limite_colaboradores"] if empresa else None
    quantidade = total["total"] if total else 0

    if limite is None:
        return True

    return quantidade < limite


def validar_limite_colaboradores(empresa_id):
    empresa = conn.execute(
        """
        SELECT limite_colaboradores
        FROM empresas
        WHERE id = %s
        LIMIT 1
        """,
        (empresa_id,),
    ).fetchone()

    total = conn.execute(
        """
        SELECT COUNT(*) AS total
        FROM colaboradores
        WHERE empresa_id = %s
          AND ativo = TRUE
        """,
        (empresa_id,),
    ).fetchone()

    limite = empresa["limite_colaboradores"] if empresa else None
    quantidade = total["total"] if total else 0

    if limite is None:
        return True

    return quantidade < limite


def aplicar_design_portal():
    st.markdown(
        """
        <style>
        .stApp {
            background: linear-gradient(180deg, #020b16 0%, #04111f 100%);
            color: #EAF2FF;
        }
        [data-testid="stHeader"] { background: transparent; }
        .block-container {
            padding-top: 1.15rem;
            padding-bottom: 1.8rem;
            max-width: 1380px;
        }
        section[data-testid="stSidebar"] {
            background: linear-gradient(180deg, #03101d 0%, #051424 100%);
            border-right: 1px solid rgba(120,145,170,0.12);
            min-width: 290px !important;
            max-width: 290px !important;
        }
        section[data-testid="stSidebar"] * { color: #EAF2FF !important; }
        .stTextInput > div > div > input,
        .stTextArea textarea,
        .stSelectbox > div > div,
        .stNumberInput input {
            background: rgba(255,255,255,0.03) !important;
            color: #EAF2FF !important;
            border: 1px solid rgba(120,145,170,0.18) !important;
            border-radius: 10px !important;
            box-shadow: none !important;
        }
        .stButton > button {
            width: 100%;
            border-radius: 12px;
            font-weight: 700;
            border: 1px solid rgba(84,138,226,0.28);
            background: linear-gradient(180deg, #17427A 0%, #10335F 100%);
            color: #FFFFFF;
            box-shadow: none;
        }
        section[data-testid="stSidebar"] .stButton > button[kind="secondary"] {
            background: transparent !important;
            border: 1px solid transparent !important;
            color: #B9C8D9 !important;
            text-align: left !important;
            justify-content: flex-start !important;
            min-height: 40px;
            padding-left: 10px !important;
            margin-bottom: 8px;
        }
        section[data-testid="stSidebar"] .stButton > button[kind="primary"] {
            background: rgba(38,79,150,0.72) !important;
            border: 1px solid rgba(120,166,255,0.15) !important;
            color: #FFFFFF !important;
            text-align: left !important;
            justify-content: flex-start !important;
            min-height: 40px;
            padding-left: 10px !important;
            margin-bottom: 8px;
        }
        .bv-sidebar-top { display:flex; align-items:center; gap:10px; margin:4px 0 18px 0; }
        .bv-sidebar-logo { width:34px; height:34px; flex-shrink:0; }
        .bv-sidebar-title { font-size:16px; font-weight:700; color:#F7FBFF; line-height:1.2; }
        .bv-menu-heading { font-size:11px; letter-spacing:.08em; font-weight:700; color:#7F93A8; margin:8px 0 10px 0; text-transform:uppercase; }
        .bv-menu-icon-wrap { width:100%; min-height:40px; display:flex; align-items:center; justify-content:center; color:#B9C8D9; border-radius:12px; margin-bottom:8px; }
        .bv-menu-icon-wrap.active { background: rgba(38,79,150,0.72); color:#FFFFFF; border: 1px solid rgba(120,166,255,0.15); }
        .bv-sidebar-divider { height:1px; background: rgba(120,145,170,0.16); margin:16px 0 18px 0; }
        .bv-user-card { display:flex; align-items:center; gap:12px; margin-top:14px; margin-bottom:12px; }
        .bv-user-avatar { width:44px; height:44px; border-radius:50%; background:#2B59C3; display:flex; align-items:center; justify-content:center; color:#FFFFFF; font-weight:700; font-size:17px; flex-shrink:0; }
        .bv-user-label { font-size:12px; color:#8FA5BC; line-height:1.2; }
        .bv-user-name { font-size:15px; font-weight:700; color:#EAF2FF; line-height:1.3; word-break: break-word; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def svg_menu_icon(kind):
    icons = {
        "dashboard": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><rect x="3.5" y="3.5" width="7" height="7" rx="1.2" stroke="currentColor" stroke-width="1.8"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.2" stroke="currentColor" stroke-width="1.8"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.2" stroke="currentColor" stroke-width="1.8"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.2" stroke="currentColor" stroke-width="1.8"/></svg>',
        "demandas": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><rect x="5" y="3.5" width="14" height="17" rx="2" stroke="currentColor" stroke-width="1.8"/><line x1="8" y1="8" x2="16" y2="8" stroke="currentColor" stroke-width="1.8"/><line x1="8" y1="12" x2="16" y2="12" stroke="currentColor" stroke-width="1.8"/></svg>',
        "nova": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><line x1="12" y1="5" x2="12" y2="19" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><line x1="5" y1="12" x2="19" y2="12" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
        "clientes": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><circle cx="9" cy="8" r="3" stroke="currentColor" stroke-width="1.8"/><path d="M3 19c0-3.2 2.9-5.3 6-5.3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="17" cy="8" r="3" stroke="currentColor" stroke-width="1.8"/><path d="M21 19c0-3.2-2.9-5.3-6-5.3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
        "atendentes": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="7" r="3.2" stroke="currentColor" stroke-width="1.8"/><path d="M5 19c0-3.6 3.3-5.8 7-5.8s7 2.2 7 5.8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
        "cadastros": '<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M4 7.5h16M7 4.5v6M17 4.5v6M6.5 20h11a2 2 0 0 0 2-2v-8.5a2 2 0 0 0-2-2h-11a2 2 0 0 0-2 2V18a2 2 0 0 0 2 2Z" stroke="currentColor" stroke-width="1.8"/><path d="M9 14h6M12 11v6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
        "swap": '<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M8 7H19M19 7L15.5 3.5M19 7L15.5 10.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M16 17H5M5 17L8.5 13.5M5 17L8.5 20.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    }
    return icons.get(kind, icons["demandas"])


def render_sidebar_menu(menu_options, current_menu, logo_b64):
    icon_map = {
        "Dashboard RH": "dashboard",
        "Quadro de Funcionários": "demandas",
        "Cadastro de Colaboradores": "clientes",
        "Cadastro de Filiais": "clientes",
        "Cadastro de Setores": "cadastros",
        "Cadastro de Cargos": "atendentes",
        "Usuários da Empresa": "clientes",
    }

    if logo_b64:
        st.markdown(
            f'<div class="bv-sidebar-top"><img class="bv-sidebar-logo" src="data:image/png;base64,{logo_b64}"><div class="bv-sidebar-title">Gestão RH</div></div>',
            unsafe_allow_html=True,
        )

    st.markdown('<div class="bv-menu-heading">Menu</div>', unsafe_allow_html=True)

    for item in menu_options:
        is_active = item == current_menu
        col_icon, col_button = st.columns([0.18, 0.82], vertical_alignment="center")

        with col_icon:
            st.markdown(
                f'<div class="bv-menu-icon-wrap{" active" if is_active else ""}">{svg_menu_icon(icon_map.get(item, "demandas"))}</div>',
                unsafe_allow_html=True,
            )

        with col_button:
            if st.button(
                item,
                key=f"menu_btn_{item}",
                use_container_width=True,
                type="primary" if is_active else "secondary",
            ):
                st.session_state.menu_atual = item
                atualizar_menu_sessao(st.session_state.get("token_sessao"), item)
                persistir_query_params()
                st.rerun()


aplicar_design_portal()

header_logo_col, header_title_col = st.columns([0.8, 8])

with header_logo_col:
    if logo_b64:
        st.markdown(
            f"""
            <div style="display:flex; align-items:center; height:72px;">
                <img src="data:image/png;base64,{logo_b64}" style="max-width:72px; max-height:72px;">
            </div>
            """,
            unsafe_allow_html=True,
        )

with header_title_col:
    st.markdown(
        "<h1 style='margin-bottom:0;'>Gestão RH</h1>",
        unsafe_allow_html=True,
    )

st.markdown(
    "<hr style='border:1px solid rgba(120,145,170,0.12); margin-top:0;'>",
    unsafe_allow_html=True,
)
st.caption("Gestão de pessoas, indicadores e performance em um único lugar")

empresa_contexto = st.session_state.get("empresa_nome") or "Empresa não identificada"
plano_contexto = st.session_state.get("plano") or "não definido"
st.caption(f"Empresa: {empresa_contexto} • Plano: {plano_contexto}")

menu_options_admin = [
    "Dashboard RH",
    "Quadro de Funcionários",
    "Cadastro de Colaboradores",
    "Cadastro de Filiais",
    "Cadastro de Setores",
    "Cadastro de Cargos",
    "Usuários da Empresa",
]

menu_options_gestor = [
    "Dashboard RH",
    "Quadro de Funcionários",
    "Cadastro de Colaboradores",
    "Cadastro de Filiais",
    "Cadastro de Setores",
    "Cadastro de Cargos",
]

st.session_state.setdefault("menu_atual", "Dashboard RH")
menu_options_usuario = ["Nova Solicitação", "Demandas Solicitadas"]

perfil_atual = st.session_state.get("perfil")
if perfil_atual == "admin":
    menu_options = menu_options_admin
elif perfil_atual == "gestor":
    menu_options = menu_options_gestor
else:
    menu_options = menu_options_usuario

selected_menu_qp = st.query_params.get("menu")
if selected_menu_qp in menu_options:
    st.session_state.menu_atual = selected_menu_qp

if st.session_state.get("menu_atual") not in menu_options:
    st.session_state.menu_atual = menu_options[0]

menu = st.session_state.menu_atual
atualizar_menu_sessao(st.session_state.get("token_sessao"), menu)
persistir_query_params()


if menu == "Usuários da Empresa" and perfil_atual == "admin":
    exigir_perfil("admin")
    st.header("Usuários da Empresa")

    empresa_id = get_empresa_id()

    with st.expander("Novo usuário", expanded=True):
        c1, c2 = st.columns(2)

        with c1:
            nome_usuario_novo = st.text_input("Nome completo", key="novo_usuario_nome")
            email_usuario_novo = st.text_input("E-mail", key="novo_usuario_email")
            usuario_usuario_novo = st.text_input("Usuário", key="novo_usuario_login")

        with c2:
            perfil_usuario_novo = st.selectbox(
                "Perfil",
                ["admin", "gestor", "usuario"],
                key="novo_usuario_perfil",
            )
            senha_usuario_novo = st.text_input(
                "Senha inicial",
                type="password",
                key="novo_usuario_senha",
            )

        if st.button("Cadastrar usuário", key="btn_cadastrar_usuario_empresa"):
            if not nome_usuario_novo.strip():
                st.error("Informe o nome do usuário.")
            elif not email_usuario_novo.strip():
                st.error("Informe o e-mail do usuário.")
            elif not usuario_usuario_novo.strip():
                st.error("Informe o login do usuário.")
            elif not senha_usuario_novo.strip() or len(senha_usuario_novo.strip()) < 6:
                st.error("A senha inicial deve ter pelo menos 6 caracteres.")
            else:
                try:
                    criar_usuario_empresa(
                        empresa_id=empresa_id,
                        nome=nome_usuario_novo,
                        email=email_usuario_novo,
                        usuario=usuario_usuario_novo,
                        senha=senha_usuario_novo,
                        perfil=perfil_usuario_novo,
                    )
                    st.success("Usuário cadastrado com sucesso.")
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))
                except Exception as exc:
                    st.error(f"Erro ao cadastrar usuário: {exc}")

    st.markdown("---")
    st.subheader("Usuários cadastrados")

    if "usuario_empresa_editando_id" not in st.session_state:
        st.session_state.usuario_empresa_editando_id = None

    usuarios_empresa = obter_usuarios_empresa(empresa_id)

    if not usuarios_empresa:
        st.info("Nenhum usuário cadastrado para esta empresa.")
    else:
        usuarios_empresa, _, _ = paginar_registros(
            usuarios_empresa,
            "pagina_usuarios_empresa",
            page_size=10,
        )

        for usuario_row in usuarios_empresa:
            usuario_id = usuario_row["id"]

            with st.container(border=True):
                col1, col2, col3 = st.columns([2.5, 2.2, 2.3])

                with col1:
                    st.write(f"**{usuario_row['nome']}**")
                    st.caption(usuario_row["usuario"])

                with col2:
                    st.write(usuario_row["email"] or "Sem e-mail")
                    st.caption(f"Perfil: {usuario_row['perfil']}")

                with col3:
                    b1, b2 = st.columns(2)

                    with b1:
                        status_label = (
                            "Ativo" if bool(usuario_row["ativo"]) else "Inativo"
                        )
                        st.write(status_label)

                    with b2:
                        if st.button(
                            "Alterar",
                            key=f"alterar_usuario_empresa_{usuario_id}",
                            use_container_width=True,
                        ):
                            st.session_state.usuario_empresa_editando_id = usuario_id
                            st.rerun()

                if st.session_state.usuario_empresa_editando_id == usuario_id:
                    ed1, ed2 = st.columns(2)

                    with ed1:
                        edit_nome = st.text_input(
                            "Nome",
                            value=usuario_row["nome"] or "",
                            key=f"edit_usuario_empresa_nome_{usuario_id}",
                        )
                        edit_email = st.text_input(
                            "E-mail",
                            value=usuario_row["email"] or "",
                            key=f"edit_usuario_empresa_email_{usuario_id}",
                        )
                        edit_usuario = st.text_input(
                            "Usuário",
                            value=usuario_row["usuario"] or "",
                            key=f"edit_usuario_empresa_login_{usuario_id}",
                        )

                    with ed2:
                        perfis = ["admin", "gestor", "usuario"]
                        idx_perfil = (
                            perfis.index(usuario_row["perfil"])
                            if usuario_row["perfil"] in perfis
                            else 2
                        )

                        edit_perfil = st.selectbox(
                            "Perfil",
                            perfis,
                            index=idx_perfil,
                            key=f"edit_usuario_empresa_perfil_{usuario_id}",
                        )

                        edit_ativo = st.checkbox(
                            "Ativo",
                            value=bool(usuario_row["ativo"]),
                            key=f"edit_usuario_empresa_ativo_{usuario_id}",
                        )

                        edit_senha = st.text_input(
                            "Nova senha (opcional)",
                            type="password",
                            key=f"edit_usuario_empresa_senha_{usuario_id}",
                        )

                    a1, a2 = st.columns(2)

                    with a1:
                        if st.button(
                            "Salvar alteração",
                            key=f"salvar_usuario_empresa_{usuario_id}",
                            use_container_width=True,
                        ):
                            try:
                                atualizar_usuario_empresa(
                                    usuario_id=usuario_id,
                                    empresa_id=empresa_id,
                                    nome=edit_nome,
                                    email=edit_email,
                                    usuario=edit_usuario,
                                    perfil=edit_perfil,
                                    ativo=edit_ativo,
                                    nova_senha=edit_senha,
                                )
                                st.session_state.usuario_empresa_editando_id = None
                                st.success("Usuário atualizado com sucesso.")
                                st.rerun()
                            except ValueError as exc:
                                st.error(str(exc))
                            except Exception as exc:
                                st.error(f"Erro ao atualizar usuário: {exc}")

                    with a2:
                        if st.button(
                            "Cancelar alteração",
                            key=f"cancelar_usuario_empresa_{usuario_id}",
                            use_container_width=True,
                        ):
                            st.session_state.usuario_empresa_editando_id = None
                            st.rerun()


with st.sidebar:
    render_sidebar_menu(menu_options=menu_options, current_menu=menu, logo_b64=logo_b64)
    st.markdown('<div style="flex:1;"></div>', unsafe_allow_html=True)
    st.markdown('<div class="bv-sidebar-divider"></div>', unsafe_allow_html=True)

    nome_usuario = (
        (st.session_state.get("nome_usuario") or st.session_state.usuario or "")
        .replace("_", " ")
        .strip()
    )
    partes_nome_usuario = [p for p in nome_usuario.split() if p]
    if len(partes_nome_usuario) >= 2:
        iniciais = (partes_nome_usuario[0][0] + partes_nome_usuario[1][0]).upper()
    elif len(partes_nome_usuario) == 1:
        iniciais = partes_nome_usuario[0][0].upper()
    else:
        iniciais = "US"

    st.markdown(
        f"""
        <div class="bv-user-card">
            <div class="bv-user-avatar">{iniciais}</div>
            <div class="bv-user-meta">
                <div class="bv-user-label">Usuário atual</div>
                <div class="bv-user-name">{html.escape(st.session_state.get('nome_usuario') or st.session_state.usuario)}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_swap_i, col_swap_b = st.columns([0.18, 0.82], vertical_alignment="center")
    with col_swap_i:
        st.markdown(
            f'<div style="display:flex;align-items:center;justify-content:center;height:38px;color:#DCE7F4;">{svg_menu_icon("swap")}</div>',
            unsafe_allow_html=True,
        )
    with col_swap_b:
        if st.button(
            "Trocar usuário", key="trocar_usuario_menu", use_container_width=True
        ):
            logout()


if menu == "Nova Solicitação":
    st.header("Nova Solicitação")

    if st.session_state.get("limpar_campos_nova_solicitacao", False):
        st.session_state["titulo"] = ""
        st.session_state["descricao"] = ""
        st.session_state.limpar_campos_nova_solicitacao = False

    if perfil_atual == "admin":
        clientes_ativos = obter_clientes_ativos()
        if clientes_ativos:
            lista_clientes = [
                f"{row['nome']} ({row['usuario']})" for row in clientes_ativos
            ]
            mapa_clientes = {
                f"{row['nome']} ({row['usuario']})": row["usuario"]
                for row in clientes_ativos
            }
            cliente_escolhido = st.selectbox("Cliente", lista_clientes)
            cliente_usuario = mapa_clientes[cliente_escolhido]
            cliente_info = obter_cliente_por_usuario(cliente_usuario)
        else:
            st.warning("Não há clientes ativos cadastrados.")
            st.stop()
    else:
        cliente_usuario = st.session_state.usuario
        cliente_info = obter_cliente_por_usuario(cliente_usuario)
        st.text_input(
            "Cliente", value=obter_nome_cliente(cliente_usuario), disabled=True
        )

    titulo = st.text_input("Título", key="titulo")
    descricao = st.text_area("Descrição", key="descricao")
    prioridade = st.selectbox("Prioridade", ["Alta", "Média", "Baixa"])

    complexidade = (
        st.selectbox("Complexidade", ["Leve", "Média", "Complexa"])
        if perfil_atual == "admin"
        else ""
    )

    st.subheader("Anexos de evidência")
    arquivos = st.file_uploader(
        "Envie pelo menos 1 imagem",
        type=["png", "jpg", "jpeg"],
        accept_multiple_files=True,
        key="anexos_upload",
    )

    observacoes_anexos = []
    if arquivos:
        for idx, arq in enumerate(arquivos, start=1):
            st.caption(f"Arquivo {idx}: {arq.name}")
            obs = st.text_input(f"Observação da imagem {idx}", key=f"obs_img_{idx}")
            observacoes_anexos.append(obs)

    col_a, col_b, col_c = st.columns(3)
    with col_a:
        enviar = st.button("Enviar", use_container_width=True)
    with col_b:
        limpar = st.button("LIMPAR", use_container_width=True)
    with col_c:
        nova = st.button("NOVA", use_container_width=True)

    if limpar:
        limpar_formulario()

    if nova:
        nova_solicitacao()

    if enviar:
        cliente_id = cliente_info["id"] if cliente_info else None
        empresa_id = cliente_info["empresa_id"] if cliente_info else None
        titulo_limpo = titulo.strip()
        descricao_limpa = descricao.strip()

        if not cliente_info or not cliente_id:
            st.error("Não foi possível identificar o cliente da solicitação.")
        elif empresa_id is None:
            st.error("O cliente selecionado não está vinculado a nenhuma empresa.")
        elif not titulo_limpo or not descricao_limpa:
            st.warning("Preencha título e descrição antes de enviar.")
        elif not arquivos or len(arquivos) == 0:
            st.error("É obrigatório enviar pelo menos uma imagem.")
        else:
            uploads_invalidos = []
            for arquivo in arquivos:
                ok, mensagem = validar_upload_imagem(arquivo)
                if not ok:
                    uploads_invalidos.append(mensagem)

            if uploads_invalidos:
                for mensagem in uploads_invalidos:
                    st.error(mensagem)
            else:
                duplicado = conn.execute(
                    """
                    SELECT id
                    FROM solicitacoes
                    WHERE cliente_id = %s
                      AND titulo = %s
                      AND descricao = %s
                      AND status IN ('Pendente', 'Iniciado', 'Pausado', 'Em análise', 'Em atendimento', 'Aguardando cliente')
                    LIMIT 1
                    """,
                    (cliente_id, titulo_limpo, descricao_limpa),
                ).fetchone()

                if duplicado is not None:
                    st.warning(
                        f"Esta solicitação já foi solicitada antes e ainda está em andamento. ID #{duplicado['id']}"
                    )
                else:
                    try:
                        with conn.cursor() as cur:
                            cur.execute(
                                """
                                INSERT INTO solicitacoes
                                (
                                    cliente,
                                    cliente_id,
                                    empresa_id,
                                    titulo,
                                    descricao,
                                    prioridade,
                                    status,
                                    complexidade,
                                    resposta,
                                    data_criacao
                                )
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                                RETURNING id
                                """,
                                (
                                    cliente_usuario,
                                    cliente_id,
                                    empresa_id,
                                    titulo_limpo,
                                    descricao_limpa,
                                    prioridade,
                                    "Em análise",
                                    complexidade,
                                    "",
                                    agora(),
                                ),
                            )
                            solicitacao_id = cur.fetchone()["id"]

                            for idx, arq in enumerate(arquivos):
                                cur.execute(
                                    """
                                    INSERT INTO anexos (solicitacao_id, nome_arquivo, observacao, imagem, data_criacao)
                                    VALUES (%s, %s, %s, %s, %s)
                                    """,
                                    (
                                        solicitacao_id,
                                        arq.name,
                                        (
                                            observacoes_anexos[idx]
                                            if idx < len(observacoes_anexos)
                                            else ""
                                        ),
                                        arq.getvalue(),
                                        agora(),
                                    ),
                                )

                        st.session_state.limpar_campos_nova_solicitacao = True
                        st.success("Solicitação enviada com sucesso.")
                        st.rerun()
                    except psycopg.Error as e:
                        st.error(f"Erro ao gravar solicitação: {e}")


elif menu == "Demandas Solicitadas":
    st.header("Demandas Solicitadas")

    col_legenda1, col_legenda2 = st.columns([8, 1])
    with col_legenda2:
        if st.button("📌 Legenda", use_container_width=True):
            st.session_state.mostrar_legenda = not st.session_state.get(
                "mostrar_legenda", False
            )

    if st.session_state.get("mostrar_legenda", False):
        st.info(
            "🔴 Em análise\n\n🟢 Em atendimento\n\n🟡 Aguardando cliente\n\n🔵 Concluído"
        )

    f1, f2, f3 = st.columns([1.2, 1.2, 2.2])
    with f1:
        status_filtro = st.selectbox(
            "Filtrar por status",
            [
                "Todos",
                "Em análise",
                "Em atendimento",
                "Aguardando cliente",
                "Concluído",
            ],
            index=0,
            key="filtro_status_demandas",
        )
    with f2:
        prioridade_filtro = st.selectbox(
            "Filtrar por prioridade",
            ["Todas", "Alta", "Média", "Baixa"],
            index=0,
            key="filtro_prioridade_demandas",
        )
    with f3:
        busca_filtro = st.text_input(
            "Buscar por ID ou título",
            placeholder="Ex.: 125 ou erro no relatório",
            key="busca_demandas",
        )

    st.caption(
        "Listagem otimizada para reduzir consultas repetidas e melhorar o tempo de resposta."
    )

    clientes_mapa = {}
    atendentes_ativos = obter_atendentes_ativos() if perfil_atual == "admin" else []

    if perfil_atual == "admin":
        clientes = conn.execute(
            """
            SELECT id, usuario, nome, empresa_id
            FROM clientes
            WHERE ativo = TRUE
            ORDER BY nome, usuario
            """
        ).fetchall()
        clientes_mapa = {(cli["id"], cli["usuario"]): cli for cli in clientes if cli}
        todas_solicitacoes = obter_solicitacoes_filtradas(
            status_filtro=status_filtro,
            prioridade_filtro=prioridade_filtro,
            busca=busca_filtro,
            limite=300,
        )
        grupos_solicitacoes = agrupar_solicitacoes_por_cliente(todas_solicitacoes)
        clientes_iteracao = [
            clientes_mapa[chave]
            for chave in clientes_mapa
            if chave in grupos_solicitacoes
        ]
    elif perfil_atual == "atendente":
        dados_cli = obter_solicitacoes_filtradas(
            status_filtro=status_filtro,
            prioridade_filtro=prioridade_filtro,
            busca=busca_filtro,
            limite=200,
            atendente_usuario=st.session_state.usuario,
        )
        clientes_iteracao = []
        grupos_solicitacoes = {"_atendente": dados_cli}
    else:
        cliente_logado = obter_cliente_por_usuario(st.session_state.usuario)
        clientes_iteracao = [cliente_logado] if cliente_logado else []
        grupos_solicitacoes = {}

    encontrou_resultado = False

    if perfil_atual == "admin":
        clientes_iteracao, _, _ = paginar_registros(
            clientes_iteracao, state_key="pagina_demandas_clientes", page_size=8
        )

    if perfil_atual == "atendente":
        df_cli = pd.DataFrame(grupos_solicitacoes.get("_atendente", []))
        if df_cli.empty:
            st.info("Nenhuma solicitação encontrada com os filtros aplicados.")
        else:
            encontrou_resultado = True
            for _, row in df_cli.iterrows():
                status_atual = normalizar_status(row["status"])
                solicitacao_id = int(row["id"])
                with st.container(border=True):
                    c1, c2, c3, c4 = st.columns([0.8, 3.2, 1.3, 1.7])
                    with c1:
                        st.write(f"**#{solicitacao_id}**")
                    with c2:
                        st.write(f"**{row['titulo']}**")
                        st.caption(row["descricao"])
                    with c3:
                        st.write(f"Prioridade: **{row['prioridade']}**")
                    with c4:
                        st.write(f"Status: **{formatar_status_texto(status_atual)}**")

                    with st.expander(f"Anexos da solicitação #{solicitacao_id}"):
                        render_anexos_como_arquivo(
                            solicitacao_id, prefixo=f"at_{solicitacao_id}"
                        )

                    obs_key = f"obs_at_{solicitacao_id}"
                    if obs_key not in st.session_state:
                        st.session_state[obs_key] = (
                            row["resposta"] if row["resposta"] else ""
                        )

                    st.text_area(
                        "Observações",
                        key=obs_key,
                        height=90,
                        placeholder="Digite aqui a observação para o cliente...",
                    )

                    ac1, ac2, ac3 = st.columns([1.2, 1.2, 4])
                    if status_atual == "Em análise":
                        with ac1:
                            if st.button(
                                "INICIAR",
                                key=f"iniciar_at_{solicitacao_id}",
                                use_container_width=True,
                            ):
                                atualizar_solicitacao(
                                    solicitacao_id,
                                    "Em atendimento",
                                    st.session_state[obs_key],
                                )
                                st.rerun()
                    elif status_atual == "Em atendimento":
                        with ac1:
                            if st.button(
                                "AGUARDAR CLIENTE",
                                key=f"aguardar_at_{solicitacao_id}",
                                use_container_width=True,
                            ):
                                atualizar_solicitacao(
                                    solicitacao_id,
                                    "Aguardando cliente",
                                    st.session_state[obs_key],
                                )
                                st.rerun()
                        with ac2:
                            if st.button(
                                "FINALIZAR",
                                key=f"finalizar_at_{solicitacao_id}",
                                use_container_width=True,
                            ):
                                atualizar_solicitacao(
                                    solicitacao_id,
                                    "Concluído",
                                    st.session_state[obs_key],
                                )
                                st.rerun()
                    elif status_atual == "Aguardando cliente":
                        with ac1:
                            if st.button(
                                "RETOMAR",
                                key=f"retomar_at_{solicitacao_id}",
                                use_container_width=True,
                            ):
                                atualizar_solicitacao(
                                    solicitacao_id,
                                    "Em atendimento",
                                    st.session_state[obs_key],
                                )
                                st.rerun()
                        with ac2:
                            if st.button(
                                "FINALIZAR",
                                key=f"finalizar_at2_{solicitacao_id}",
                                use_container_width=True,
                            ):
                                atualizar_solicitacao(
                                    solicitacao_id,
                                    "Concluído",
                                    st.session_state[obs_key],
                                )
                                st.rerun()
                    else:
                        st.success("Demanda concluída.")
    else:
        for cli in clientes_iteracao:
            if not cli:
                continue

            if perfil_atual == "admin":
                dados_cli = grupos_solicitacoes.get((cli["id"], cli["usuario"]), [])
            else:
                dados_cli = obter_solicitacoes_filtradas(
                    cliente_id=cli["id"],
                    cliente_usuario=cli["usuario"],
                    empresa_id=None,
                    status_filtro=status_filtro,
                    prioridade_filtro=prioridade_filtro,
                    busca=busca_filtro,
                    limite=50,
                )

            if not dados_cli:
                continue

            encontrou_resultado = True
            nome_exibicao = cli["nome"] or cli["usuario"]
            st.subheader(f"Cliente: {nome_exibicao} ({cli['usuario']})")

            df_cli = pd.DataFrame(dados_cli)

            if perfil_atual != "admin":
                df_exibicao = df_cli.copy()
                df_exibicao["status"] = df_exibicao["status"].apply(
                    formatar_status_texto
                )
                df_exibicao["observacoes"] = df_exibicao["resposta"].fillna("")
                df_exibicao = df_exibicao[
                    [
                        "id",
                        "titulo",
                        "prioridade",
                        "status",
                        "observacoes",
                        "data_criacao",
                    ]
                ]
                df_exibicao.columns = [
                    "ID",
                    "Título",
                    "Prioridade",
                    "Status",
                    "Observações",
                    "Data",
                ]
                st.dataframe(df_exibicao, use_container_width=True)

                for _, row in df_cli.iterrows():
                    anexo_id = int(row["id"])
                    with st.expander(f"Anexos da solicitação #{anexo_id}"):
                        render_anexos_como_arquivo(
                            anexo_id, prefixo=f"cliente_{anexo_id}"
                        )
            else:
                for _, row in df_cli.iterrows():
                    status_atual = normalizar_status(row["status"])
                    solicitacao_id = int(row["id"])

                    with st.container(border=True):
                        c1, c2, c3, c4, c5 = st.columns([0.7, 2.5, 1.2, 1.4, 1.5])
                        with c1:
                            st.write(f"**#{solicitacao_id}**")
                        with c2:
                            st.write(f"**{row['titulo']}**")
                            st.caption(row["descricao"])
                        with c3:
                            st.write(f"Prioridade: **{row['prioridade']}**")
                        with c4:
                            st.write(
                                f"Status: **{formatar_status_texto(status_atual)}**"
                            )
                        with c5:
                            if row["complexidade"]:
                                st.write(f"Complexidade: **{row['complexidade']}**")

                        with st.expander(f"Anexos da solicitação #{solicitacao_id}"):
                            render_anexos_como_arquivo(
                                solicitacao_id, prefixo=f"admin_{solicitacao_id}"
                            )

                        obs_key = f"obs_{solicitacao_id}"
                        if obs_key not in st.session_state:
                            st.session_state[obs_key] = (
                                row["resposta"] if row["resposta"] else ""
                            )

                        st.text_area(
                            "Observações",
                            key=obs_key,
                            height=90,
                            placeholder="Digite aqui a observação para o cliente...",
                        )

                        nome_atendente_atual = (
                            row.get("atendente_nome") or "Não atribuído"
                        )
                        st.caption(f"Atendente atual: {nome_atendente_atual}")

                        if atendentes_ativos:
                            opcoes_atendentes = {
                                atendente["nome"]: atendente["id"]
                                for atendente in atendentes_ativos
                            }
                            nomes_atendentes = list(opcoes_atendentes.keys())
                            indice_atendente = 0
                            if row.get("atendente_id"):
                                for idx_at, atendente in enumerate(atendentes_ativos):
                                    if atendente["id"] == row.get("atendente_id"):
                                        indice_atendente = idx_at
                                        break

                            ac_at1, ac_at2 = st.columns([2.4, 1])
                            with ac_at1:
                                atendente_sel = st.selectbox(
                                    "Atendente responsável",
                                    nomes_atendentes,
                                    index=indice_atendente,
                                    key=f"atendente_{solicitacao_id}",
                                )
                            with ac_at2:
                                st.write("")
                                st.write("")
                                if st.button(
                                    "Atribuir",
                                    key=f"atribuir_atendente_{solicitacao_id}",
                                    use_container_width=True,
                                ):
                                    conn.execute(
                                        """
                                        UPDATE solicitacoes
                                        SET atendente_id = %s,
                                            atribuido_em = %s
                                        WHERE id = %s
                                        """,
                                        (
                                            opcoes_atendentes[atendente_sel],
                                            agora(),
                                            solicitacao_id,
                                        ),
                                    )
                                    st.success("Atendente atribuído.")
                                    st.rerun()
                        else:
                            st.info("Nenhum atendente ativo cadastrado.")

                        ac1, ac2, ac3, ac4 = st.columns([1.2, 1.2, 1, 3.6])

                        if status_atual == "Em análise":
                            with ac1:
                                if st.button(
                                    "INICIAR",
                                    key=f"iniciar_{solicitacao_id}",
                                    use_container_width=True,
                                ):
                                    atualizar_solicitacao(
                                        solicitacao_id,
                                        "Em atendimento",
                                        st.session_state[obs_key],
                                    )
                                    st.rerun()
                        elif status_atual == "Em atendimento":
                            with ac1:
                                if st.button(
                                    "AGUARDAR CLIENTE",
                                    key=f"aguardar_{solicitacao_id}",
                                    use_container_width=True,
                                ):
                                    atualizar_solicitacao(
                                        solicitacao_id,
                                        "Aguardando cliente",
                                        st.session_state[obs_key],
                                    )
                                    st.rerun()
                            with ac2:
                                if st.button(
                                    "FINALIZAR",
                                    key=f"finalizar_{solicitacao_id}",
                                    use_container_width=True,
                                ):
                                    atualizar_solicitacao(
                                        solicitacao_id,
                                        "Concluído",
                                        st.session_state[obs_key],
                                    )
                                    st.rerun()
                        elif status_atual == "Aguardando cliente":
                            with ac1:
                                if st.button(
                                    "RETOMAR",
                                    key=f"retomar_{solicitacao_id}",
                                    use_container_width=True,
                                ):
                                    atualizar_solicitacao(
                                        solicitacao_id,
                                        "Em atendimento",
                                        st.session_state[obs_key],
                                    )
                                    st.rerun()
                            with ac2:
                                if st.button(
                                    "FINALIZAR",
                                    key=f"finalizar_aguardando_{solicitacao_id}",
                                    use_container_width=True,
                                ):
                                    atualizar_solicitacao(
                                        solicitacao_id,
                                        "Concluído",
                                        st.session_state[obs_key],
                                    )
                                    st.rerun()
                        else:
                            st.success("Demanda concluída.")

    if not encontrou_resultado and perfil_atual != "atendente":
        st.info("Nenhuma solicitação encontrada com os filtros aplicados.")


elif menu == "Dashboard RH" and perfil_atual in ("admin", "gestor"):
    exigir_perfil("admin", "gestor")
    st.header("Dashboard RH")

    empresa_id = get_empresa_id()

    empresa_info = conn.execute(
        """
        SELECT plano, limite_colaboradores, limite_usuarios
        FROM empresas
        WHERE id = %s
        LIMIT 1
        """,
        (empresa_id,),
    ).fetchone()

    total_usuarios_empresa = conn.execute(
        """
        SELECT COUNT(*) AS total
        FROM usuarios
        WHERE empresa_id = %s
        """,
        (empresa_id,),
    ).fetchone()

    total_colaboradores_ativos_empresa = conn.execute(
        """
        SELECT COUNT(*) AS total
        FROM colaboradores
        WHERE empresa_id = %s
          AND ativo = TRUE
        """,
        (empresa_id,),
    ).fetchone()

    plano_nome = (
        empresa_info["plano"]
        if empresa_info and empresa_info.get("plano")
        else "não definido"
    )
    limite_usuarios = empresa_info["limite_usuarios"] if empresa_info else None
    limite_colaboradores = (
        empresa_info["limite_colaboradores"] if empresa_info else None
    )
    usados_usuarios = total_usuarios_empresa["total"] if total_usuarios_empresa else 0
    usados_colaboradores = (
        total_colaboradores_ativos_empresa["total"]
        if total_colaboradores_ativos_empresa
        else 0
    )

    plano_col1, plano_col2, plano_col3 = st.columns(3)
    plano_col1.metric("Plano atual", str(plano_nome).title())
    plano_col2.metric(
        "Usuários",
        f"{usados_usuarios} / {limite_usuarios if limite_usuarios is not None else 'Ilimitado'}",
    )
    plano_col3.metric(
        "Colaboradores ativos",
        f"{usados_colaboradores} / {limite_colaboradores if limite_colaboradores is not None else 'Ilimitado'}",
    )

    dados = conn.execute(
        """
        SELECT
            c.id,
            c.nome,
            c.matricula,
            c.status,
            c.ativo,
            c.data_admissao,
            c.data_desligamento,
            c.data_nascimento,
            f.nome AS filial,
            s.nome AS setor,
            cg.nome AS cargo
        FROM colaboradores c
        LEFT JOIN filiais f
            ON f.id = c.filial_id
           AND f.empresa_id = c.empresa_id
        LEFT JOIN setores s
            ON s.id = c.setor_id
           AND s.empresa_id = c.empresa_id
        LEFT JOIN cargos cg
            ON cg.id = c.cargo_id
           AND cg.empresa_id = c.empresa_id
        WHERE c.empresa_id = %s
        ORDER BY c.nome
        """,
        (empresa_id,),
    ).fetchall()

    df = pd.DataFrame(dados) if dados else pd.DataFrame()

    total_filiais_empresa = conn.execute(
        """
        SELECT COUNT(*) AS total
        FROM filiais
        WHERE empresa_id = %s
        """,
        (empresa_id,),
    ).fetchone()

    total_setores_empresa = conn.execute(
        """
        SELECT COUNT(*) AS total
        FROM setores
        WHERE empresa_id = %s
        """,
        (empresa_id,),
    ).fetchone()

    total_cargos_empresa = conn.execute(
        """
        SELECT COUNT(*) AS total
        FROM cargos
        WHERE empresa_id = %s
        """,
        (empresa_id,),
    ).fetchone()

    estrutura1, estrutura2, estrutura3 = st.columns(3)
    estrutura1.metric(
        "Filiais", total_filiais_empresa["total"] if total_filiais_empresa else 0
    )
    estrutura2.metric(
        "Setores", total_setores_empresa["total"] if total_setores_empresa else 0
    )
    estrutura3.metric(
        "Cargos", total_cargos_empresa["total"] if total_cargos_empresa else 0
    )

    if df.empty:
        st.info(
            """🚀 Bem-vindo ao Gestão RH

Para começar:
1. Cadastre uma filial
2. Cadastre um setor
3. Cadastre um cargo
4. Cadastre seu primeiro colaborador"""
        )
    else:
        df["data_admissao"] = pd.to_datetime(df["data_admissao"], errors="coerce")
        df["data_desligamento"] = pd.to_datetime(
            df["data_desligamento"], errors="coerce"
        )
        df["data_nascimento"] = pd.to_datetime(df["data_nascimento"], errors="coerce")

        anos_admissao = df["data_admissao"].dt.year.dropna().astype(int).tolist()
        anos_desligamento = (
            df["data_desligamento"].dt.year.dropna().astype(int).tolist()
        )
        anos_disponiveis = sorted(
            list(set(anos_admissao + anos_desligamento)), reverse=True
        )
        if not anos_disponiveis:
            anos_disponiveis = [datetime.now().year]

        meses_map = {
            1: "Janeiro",
            2: "Fevereiro",
            3: "Março",
            4: "Abril",
            5: "Maio",
            6: "Junho",
            7: "Julho",
            8: "Agosto",
            9: "Setembro",
            10: "Outubro",
            11: "Novembro",
            12: "Dezembro",
        }

        f1, f2 = st.columns(2)
        with f1:
            ano_sel = st.selectbox(
                "Ano", anos_disponiveis, index=0, key="dashboard_rh_ano"
            )
        with f2:
            mes_atual = datetime.now().month
            mes_sel = st.selectbox(
                "Mês",
                list(meses_map.keys()),
                index=mes_atual - 1,
                format_func=lambda x: meses_map[x],
                key="dashboard_rh_mes",
            )

        total_colaboradores = len(df)
        registros_ativos = len(df[df["ativo"] == True])
        afastados_total = len(df[df["status"] == "Afastado"])

        admissoes_periodo = len(
            df[
                (df["data_admissao"].dt.year == ano_sel)
                & (df["data_admissao"].dt.month == mes_sel)
            ]
        )
        desligamentos_periodo = len(
            df[
                (df["data_desligamento"].dt.year == ano_sel)
                & (df["data_desligamento"].dt.month == mes_sel)
            ]
        )
        turnover = (
            (desligamentos_periodo / registros_ativos * 100)
            if registros_ativos > 0
            else 0
        )

        aniversariantes_mes = df[
            df["data_nascimento"].notna() & (df["data_nascimento"].dt.month == mes_sel)
        ].copy()
        if not aniversariantes_mes.empty:
            aniversariantes_mes["dia"] = aniversariantes_mes["data_nascimento"].dt.day
            aniversariantes_mes = aniversariantes_mes.sort_values(["dia", "nome"])

        empresa_info = conn.execute(
            """
            SELECT plano, limite_colaboradores, limite_usuarios, fantasia
            FROM empresas
            WHERE id = %s
            LIMIT 1
            """,
            (empresa_id,),
        ).fetchone()
        total_usuarios_empresa = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM usuarios
            WHERE empresa_id = %s
            """,
            (empresa_id,),
        ).fetchone()
        total_filiais = conn.execute(
            "SELECT COUNT(*) AS total FROM filiais WHERE empresa_id = %s",
            (empresa_id,),
        ).fetchone()
        total_setores = conn.execute(
            "SELECT COUNT(*) AS total FROM setores WHERE empresa_id = %s",
            (empresa_id,),
        ).fetchone()
        total_cargos = conn.execute(
            "SELECT COUNT(*) AS total FROM cargos WHERE empresa_id = %s",
            (empresa_id,),
        ).fetchone()

        st.caption(
            f"Empresa: {empresa_info['fantasia'] if empresa_info else st.session_state.get('empresa_nome','')} · Plano: {empresa_info['plano'] if empresa_info else st.session_state.get('plano','starter')}"
        )

        r1, r2, r3 = st.columns(3)
        r1.metric(
            "Plano atual",
            (
                empresa_info["plano"].title()
                if empresa_info and empresa_info.get("plano")
                else "Starter"
            ),
        )
        usuarios_total = (
            total_usuarios_empresa["total"] if total_usuarios_empresa else 0
        )
        limite_usuarios = empresa_info["limite_usuarios"] if empresa_info else None
        r2.metric(
            "Usuários",
            f"{usuarios_total} / {limite_usuarios if limite_usuarios is not None else '∞'}",
        )
        limite_colaboradores = (
            empresa_info["limite_colaboradores"] if empresa_info else None
        )
        r3.metric(
            "Colaboradores ativos",
            f"{registros_ativos} / {limite_colaboradores if limite_colaboradores is not None else '∞'}",
        )

        e1, e2, e3 = st.columns(3)
        e1.metric("Filiais", total_filiais["total"] if total_filiais else 0)
        e2.metric("Setores", total_setores["total"] if total_setores else 0)
        e3.metric("Cargos", total_cargos["total"] if total_cargos else 0)

        c1, c2, c3, c4, c5, c6 = st.columns(6)
        c1.metric("Total de colaboradores", total_colaboradores)
        c2.metric("Registros ativos", registros_ativos)
        c3.metric("Admissões no período", admissoes_periodo)
        c4.metric("Desligamentos no período", desligamentos_periodo)
        c5.metric("Turnover", f"{turnover:.2f}%")
        c6.metric("Afastados", afastados_total)

        if total_colaboradores == 0:
            st.info(
                """🚀 Bem-vindo ao Gestão RH

Para começar:

1. Cadastre uma filial
2. Cadastre um setor
3. Cadastre um cargo
4. Cadastre seu primeiro colaborador"""
            )

        st.markdown("---")

        st.subheader("Resumo do quadro")
        resumo = (
            df.groupby(["filial", "setor", "cargo", "status"], dropna=False)["id"]
            .count()
            .reset_index()
            .rename(
                columns={
                    "id": "Quantidade",
                    "filial": "Filial",
                    "setor": "Setor",
                    "cargo": "Cargo",
                    "status": "Status",
                }
            )
            .sort_values(["Filial", "Setor", "Cargo", "Status"])
        )
        resumo["Filial"] = resumo["Filial"].fillna("Sem filial")
        resumo["Setor"] = resumo["Setor"].fillna("Sem setor")
        resumo["Cargo"] = resumo["Cargo"].fillna("Sem cargo")
        resumo["Status"] = resumo["Status"].fillna("Sem status")
        st.dataframe(resumo, use_container_width=True, hide_index=True)

        st.markdown("---")

        st.subheader(f"Aniversariantes de {meses_map[mes_sel]}")
        if aniversariantes_mes.empty:
            st.info("Nenhum aniversariante neste mês.")
        else:
            tabela_aniversariantes = aniversariantes_mes[
                ["dia", "nome", "matricula", "filial", "setor", "cargo", "status"]
            ].copy()
            tabela_aniversariantes["filial"] = tabela_aniversariantes["filial"].fillna(
                "Sem filial"
            )
            tabela_aniversariantes["setor"] = tabela_aniversariantes["setor"].fillna(
                "Sem setor"
            )
            tabela_aniversariantes["cargo"] = tabela_aniversariantes["cargo"].fillna(
                "Sem cargo"
            )
            tabela_aniversariantes["status"] = tabela_aniversariantes["status"].fillna(
                "Sem status"
            )
            tabela_aniversariantes.columns = [
                "Dia",
                "Nome",
                "Matrícula",
                "Filial",
                "Setor",
                "Cargo",
                "Status",
            ]
            st.dataframe(
                tabela_aniversariantes, use_container_width=True, hide_index=True
            )

elif menu == "Cadastro de Filiais" and perfil_atual in ("admin", "gestor"):
    exigir_perfil("admin", "gestor")
    st.header("Cadastro de Filiais")
    empresa_id = get_empresa_id()

    with st.expander("Nova filial", expanded=True):
        c1, c2, c3 = st.columns(3)
        with c1:
            nome_filial = st.text_input("Nome da Filial", key="filial_nome")
            cidade_filial = st.text_input("Cidade", key="filial_cidade")
        with c2:
            uf_filial = st.text_input("UF", key="filial_uf", max_chars=2)
            licenca_filial = st.text_input("Código de Licença", key="filial_licenca")
        with c3:
            ativo_filial = st.checkbox("Ativa", value=True, key="filial_ativo")

        if st.button("Cadastrar Filial", key="btn_cadastrar_filial"):
            if not nome_filial.strip():
                st.error("Informe o nome da filial.")
            else:
                conn.execute(
                    """
                    INSERT INTO filiais (empresa_id, nome, cidade, uf, licenca, ativo)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        empresa_id,
                        nome_filial.strip(),
                        cidade_filial.strip(),
                        uf_filial.strip().upper(),
                        licenca_filial.strip(),
                        ativo_filial,
                    ),
                )
                st.success("Filial cadastrada com sucesso.")
                st.rerun()

    st.markdown("---")
    st.subheader("Filiais cadastradas")

    if "filial_editando_id" not in st.session_state:
        st.session_state.filial_editando_id = None

    filiais = conn.execute(
        """
        SELECT id, nome, cidade, uf, licenca, ativo
        FROM filiais
        WHERE empresa_id = %s
        ORDER BY id
        """,
        (empresa_id,),
    ).fetchall()

    if filiais:
        filiais, _, _ = paginar_registros(
            filiais, "pagina_filiais_cadastro", page_size=10
        )
        for filial in filiais:
            filial_id = filial["id"]
            with st.container(border=True):
                col1, col2, col3 = st.columns([3.4, 1.5, 3.1])
                with col1:
                    st.write(f"**ID {filial['id']} - {filial['nome']}**")
                    localizacao = " • ".join(
                        [x for x in [filial["cidade"] or "", filial["uf"] or ""] if x]
                    )
                    st.caption(localizacao)
                    st.caption(f"Licença: {filial['licenca'] or 'Não informada'}")
                with col2:
                    st.write("Ativa" if bool(filial["ativo"]) else "Inativa")
                with col3:
                    b1, b2, b3 = st.columns(3)
                    with b1:
                        if bool(filial["ativo"]):
                            if st.button(
                                "Inativar",
                                key=f"inativar_filial_{filial_id}",
                                use_container_width=True,
                            ):
                                conn.execute(
                                    "UPDATE filiais SET ativo = FALSE WHERE id = %s AND empresa_id = %s",
                                    (filial_id, empresa_id),
                                )
                                st.rerun()
                        else:
                            if st.button(
                                "Ativar",
                                key=f"ativar_filial_{filial_id}",
                                use_container_width=True,
                            ):
                                conn.execute(
                                    "UPDATE filiais SET ativo = TRUE WHERE id = %s AND empresa_id = %s",
                                    (filial_id, empresa_id),
                                )
                                st.rerun()
                    with b2:
                        if st.button(
                            "Excluir",
                            key=f"excluir_filial_{filial_id}",
                            use_container_width=True,
                        ):
                            possui_colaboradores = conn.execute(
                                "SELECT 1 FROM colaboradores WHERE filial_id = %s AND empresa_id = %s LIMIT 1",
                                (filial_id, empresa_id),
                            ).fetchone()
                            if possui_colaboradores:
                                st.warning(
                                    "Esta filial possui colaboradores vinculados. Inative ao invés de excluir."
                                )
                            else:
                                conn.execute(
                                    "DELETE FROM filiais WHERE id = %s AND empresa_id = %s",
                                    (filial_id, empresa_id),
                                )
                                st.success("Filial excluída.")
                                st.rerun()
                    with b3:
                        if st.button(
                            "Alterar",
                            key=f"alterar_filial_{filial_id}",
                            use_container_width=True,
                        ):
                            st.session_state.filial_editando_id = filial_id
                            st.rerun()
                if st.session_state.filial_editando_id == filial_id:
                    e1, e2, e3 = st.columns(3)
                    with e1:
                        novo_nome_filial = st.text_input(
                            "Nome da Filial",
                            value=filial["nome"] or "",
                            key=f"edit_filial_nome_{filial_id}",
                        )
                        nova_cidade_filial = st.text_input(
                            "Cidade",
                            value=filial["cidade"] or "",
                            key=f"edit_filial_cidade_{filial_id}",
                        )
                    with e2:
                        nova_uf_filial = st.text_input(
                            "UF",
                            value=filial["uf"] or "",
                            key=f"edit_filial_uf_{filial_id}",
                            max_chars=2,
                        )
                        nova_licenca_filial = st.text_input(
                            "Código de Licença",
                            value=filial["licenca"] or "",
                            key=f"edit_filial_licenca_{filial_id}",
                        )
                    a1, a2 = st.columns(2)
                    with a1:
                        if st.button(
                            "Salvar alteração",
                            key=f"salvar_filial_{filial_id}",
                            use_container_width=True,
                        ):
                            if not novo_nome_filial.strip():
                                st.error("Informe o nome da filial.")
                            else:
                                conn.execute(
                                    """
                                    UPDATE filiais
                                    SET nome = %s, cidade = %s, uf = %s, licenca = %s
                                    WHERE id = %s AND empresa_id = %s
                                    """,
                                    (
                                        novo_nome_filial.strip(),
                                        nova_cidade_filial.strip(),
                                        nova_uf_filial.strip().upper(),
                                        nova_licenca_filial.strip(),
                                        filial_id,
                                        empresa_id,
                                    ),
                                )
                                st.session_state.filial_editando_id = None
                                st.success("Filial atualizada com sucesso.")
                                st.rerun()
                    with a2:
                        if st.button(
                            "Cancelar alteração",
                            key=f"cancelar_filial_{filial_id}",
                            use_container_width=True,
                        ):
                            st.session_state.filial_editando_id = None
                            st.rerun()
    else:
        st.info("Nenhuma filial cadastrada ainda.")

elif menu == "Cadastro de Colaboradores" and perfil_atual in ("admin", "gestor"):
    exigir_perfil("admin", "gestor")
    st.header("Cadastro de Colaboradores")
    empresa_id = get_empresa_id()

    filiais = conn.execute(
        "SELECT id, nome FROM filiais WHERE empresa_id = %s AND ativo = TRUE ORDER BY nome",
        (empresa_id,),
    ).fetchall()

    setores = conn.execute(
        "SELECT id, nome FROM setores WHERE empresa_id = %s AND ativo = TRUE ORDER BY nome",
        (empresa_id,),
    ).fetchall()

    cargos = conn.execute(
        "SELECT id, nome FROM cargos WHERE empresa_id = %s AND ativo = TRUE ORDER BY nome",
        (empresa_id,),
    ).fetchall()

    with st.expander("Novo colaborador", expanded=True):
        c1, c2, c3 = st.columns(3)

        with c1:
            matricula = st.text_input("Matrícula", key="colab_matricula")
            nome = st.text_input("Nome completo", key="colab_nome")
            cpf = st.text_input("CPF", key="colab_cpf")
            data_nascimento = st.date_input(
                "Data de nascimento",
                key="colab_nascimento",
                min_value=datetime(1950, 1, 1).date(),
                max_value=datetime.now().date(),
                value=datetime(1990, 1, 1).date(),
            )

        with c2:
            data_admissao = st.date_input("Data de admissão", key="colab_admissao")
            email = st.text_input("E-mail", key="colab_email")
            telefone = st.text_input("Telefone", key="colab_telefone")

            if filiais:
                filial_labels = [row["nome"] for row in filiais]
                filial_sel = st.selectbox("Filial", filial_labels, key="colab_filial")
                filial_id = next(
                    row["id"] for row in filiais if row["nome"] == filial_sel
                )
            else:
                filial_id = None
                st.warning(
                    "Cadastre pelo menos uma filial antes de criar colaboradores."
                )

        with c3:
            if setores:
                setor_labels = [row["nome"] for row in setores]
                setor_sel = st.selectbox("Setor", setor_labels, key="colab_setor")
                setor_id = next(
                    row["id"] for row in setores if row["nome"] == setor_sel
                )
            else:
                setor_id = None
                st.info("Nenhum setor ativo cadastrado.")

            if cargos:
                cargo_labels = [row["nome"] for row in cargos]
                cargo_sel = st.selectbox("Cargo", cargo_labels, key="colab_cargo")
                cargo_id = next(row["id"] for row in cargos if row["nome"] == cargo_sel)
            else:
                cargo_id = None
                st.info("Nenhum cargo ativo cadastrado.")

            status = st.selectbox(
                "Status",
                ["Ativo", "Afastado", "Férias", "Desligado"],
                key="colab_status",
            )
            ativo = st.checkbox("Registro ativo", value=True, key="colab_ativo")

        if st.button("Cadastrar Colaborador", key="btn_cadastrar_colaborador"):
            if not nome.strip():
                st.error("Informe o nome do colaborador.")
            elif not filial_id:
                st.error("É necessário vincular o colaborador a uma filial.")
            elif not validar_limite_colaboradores(empresa_id):
                st.error("Seu plano atingiu o limite de colaboradores ativos.")
            else:
                conn.execute(
                    """
                    INSERT INTO colaboradores
                    (
                        empresa_id,
                        matricula,
                        nome,
                        cpf,
                        data_nascimento,
                        data_admissao,
                        data_desligamento,
                        email,
                        telefone,
                        filial_id,
                        setor_id,
                        cargo_id,
                        status,
                        ativo
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        empresa_id,
                        matricula.strip(),
                        nome.strip(),
                        formatar_cpf(cpf.strip()),
                        data_nascimento,
                        data_admissao,
                        None,
                        email.strip().lower(),
                        telefone.strip(),
                        filial_id,
                        setor_id,
                        cargo_id,
                        status,
                        ativo,
                    ),
                )
                st.success("Colaborador cadastrado com sucesso.")
                st.rerun()

    st.markdown("---")
    st.subheader("Colaboradores cadastrados")

    if "colaborador_editando_id" not in st.session_state:
        st.session_state.colaborador_editando_id = None

    colaboradores = conn.execute(
        """
        SELECT
            c.id,
            c.matricula,
            c.nome,
            c.cpf,
            c.data_nascimento,
            c.data_admissao,
            c.data_desligamento,
            c.email,
            c.telefone,
            c.filial_id,
            c.setor_id,
            c.cargo_id,
            c.status,
            c.ativo,
            f.nome AS filial_nome,
            s.nome AS setor_nome,
            cg.nome AS cargo_nome
        FROM colaboradores c
        LEFT JOIN filiais f ON f.id = c.filial_id AND f.empresa_id = c.empresa_id
        LEFT JOIN setores s ON s.id = c.setor_id AND s.empresa_id = c.empresa_id
        LEFT JOIN cargos cg ON cg.id = c.cargo_id AND cg.empresa_id = c.empresa_id
        WHERE c.empresa_id = %s
        ORDER BY c.nome
        """,
        (empresa_id,),
    ).fetchall()

    mapa_filiais = {row["id"]: row["nome"] for row in filiais}
    mapa_setores = {row["id"]: row["nome"] for row in setores}
    mapa_cargos = {row["id"]: row["nome"] for row in cargos}

    if colaboradores:
        colaboradores, _, _ = paginar_registros(
            colaboradores, "pagina_colaboradores_cadastro", page_size=10
        )

        for colab in colaboradores:
            colaborador_id = colab["id"]

            with st.container(border=True):
                col1, col2, col3, col4 = st.columns([2.2, 2.1, 1.2, 3.2])

                with col1:
                    st.write(f"**{colab['nome']}**")
                    subtitulo = " • ".join(
                        [x for x in [colab["matricula"] or "", colab["cpf"] or ""] if x]
                    )
                    st.caption(subtitulo)

                with col2:
                    st.write(colab["filial_nome"] or "Sem filial")
                    st.caption(colab["setor_nome"] or "Sem setor")
                    st.caption(colab["cargo_nome"] or "Sem cargo")

                with col3:
                    st.write(colab["status"] or "Sem status")
                    st.caption("Ativo" if bool(colab["ativo"]) else "Inativo")

                with col4:
                    b1, b2, b3 = st.columns(3)

                    with b1:
                        if bool(colab["ativo"]):
                            if st.button(
                                "Inativar",
                                key=f"abrir_inativacao_colab_{colaborador_id}",
                                use_container_width=True,
                            ):
                                st.session_state[
                                    f"inativando_colab_{colaborador_id}"
                                ] = True
                                st.rerun()
                        else:
                            if st.button(
                                "Ativar",
                                key=f"ativar_colab_{colaborador_id}",
                                use_container_width=True,
                            ):
                                conn.execute(
                                    """
                                    UPDATE colaboradores
                                    SET ativo = TRUE,
                                        status = 'Ativo',
                                        data_desligamento = NULL
                                    WHERE id = %s
                                    """,
                                    (colaborador_id,),
                                )
                                st.success("Colaborador reativado com sucesso.")
                                st.rerun()

                    with b2:
                        if st.button(
                            "Excluir",
                            key=f"excluir_colab_{colaborador_id}",
                            use_container_width=True,
                        ):
                            conn.execute(
                                "DELETE FROM colaboradores WHERE id = %s",
                                (colaborador_id,),
                            )
                            st.success("Colaborador excluído.")
                            st.rerun()

                    with b3:
                        if st.button(
                            "Alterar",
                            key=f"alterar_colab_{colaborador_id}",
                            use_container_width=True,
                        ):
                            st.session_state.colaborador_editando_id = colaborador_id
                            st.rerun()

                if st.session_state.get(f"inativando_colab_{colaborador_id}", False):
                    st.markdown("**Motivo da inativação**")

                    motivo_inativacao = st.selectbox(
                        "Motivo",
                        ["Afastamento", "Demissão"],
                        key=f"motivo_inativacao_{colaborador_id}",
                    )

                    data_inativacao = st.date_input(
                        "Data",
                        key=f"data_inativacao_{colaborador_id}",
                        min_value=datetime(1950, 1, 1).date(),
                        max_value=datetime.now().date(),
                        value=datetime.now().date(),
                    )

                    x1, x2 = st.columns(2)

                    with x1:
                        if st.button(
                            "Confirmar inativação",
                            key=f"confirmar_inativacao_{colaborador_id}",
                            use_container_width=True,
                        ):
                            novo_status = (
                                "Afastado"
                                if motivo_inativacao == "Afastamento"
                                else "Desligado"
                            )
                            nova_data_desligamento = (
                                data_inativacao
                                if motivo_inativacao == "Demissão"
                                else None
                            )

                            conn.execute(
                                """
                                UPDATE colaboradores
                                SET ativo = FALSE,
                                    status = %s,
                                    data_desligamento = %s
                                WHERE id = %s
                                """,
                                (novo_status, nova_data_desligamento, colaborador_id),
                            )

                            st.session_state[f"inativando_colab_{colaborador_id}"] = (
                                False
                            )
                            st.success("Colaborador inativado com sucesso.")
                            st.rerun()

                    with x2:
                        if st.button(
                            "Cancelar inativação",
                            key=f"cancelar_inativacao_{colaborador_id}",
                            use_container_width=True,
                        ):
                            st.session_state[f"inativando_colab_{colaborador_id}"] = (
                                False
                            )
                            st.rerun()

                if st.session_state.colaborador_editando_id == colaborador_id:
                    st.markdown("**Alteração de colaborador**")

                    e1, e2, e3 = st.columns(3)

                    with e1:
                        nova_matricula = st.text_input(
                            "Matrícula",
                            value=colab["matricula"] or "",
                            key=f"edit_colab_matricula_{colaborador_id}",
                        )
                        novo_nome = st.text_input(
                            "Nome completo",
                            value=colab["nome"] or "",
                            key=f"edit_colab_nome_{colaborador_id}",
                        )
                        novo_cpf = st.text_input(
                            "CPF",
                            value=colab["cpf"] or "",
                            key=f"edit_colab_cpf_{colaborador_id}",
                        )

                    with e2:
                        novo_email = st.text_input(
                            "E-mail",
                            value=colab["email"] or "",
                            key=f"edit_colab_email_{colaborador_id}",
                        )
                        novo_telefone = st.text_input(
                            "Telefone",
                            value=colab["telefone"] or "",
                            key=f"edit_colab_telefone_{colaborador_id}",
                        )

                        filial_labels = (
                            [row["nome"] for row in filiais] if filiais else []
                        )
                        filial_atual = mapa_filiais.get(colab["filial_id"])
                        if filial_labels:
                            idx_filial = (
                                filial_labels.index(filial_atual)
                                if filial_atual in filial_labels
                                else 0
                            )
                            filial_edit_nome = st.selectbox(
                                "Filial",
                                filial_labels,
                                index=idx_filial,
                                key=f"edit_colab_filial_{colaborador_id}",
                            )
                            nova_filial_id = next(
                                row["id"]
                                for row in filiais
                                if row["nome"] == filial_edit_nome
                            )
                        else:
                            nova_filial_id = colab["filial_id"]

                    with e3:
                        setor_labels = (
                            [row["nome"] for row in setores] if setores else []
                        )
                        setor_atual = mapa_setores.get(colab["setor_id"])
                        if setor_labels:
                            idx_setor = (
                                setor_labels.index(setor_atual)
                                if setor_atual in setor_labels
                                else 0
                            )
                            setor_edit_nome = st.selectbox(
                                "Setor",
                                setor_labels,
                                index=idx_setor,
                                key=f"edit_colab_setor_{colaborador_id}",
                            )
                            novo_setor_id = next(
                                row["id"]
                                for row in setores
                                if row["nome"] == setor_edit_nome
                            )
                        else:
                            novo_setor_id = colab["setor_id"]

                        cargo_labels = [row["nome"] for row in cargos] if cargos else []
                        cargo_atual = mapa_cargos.get(colab["cargo_id"])
                        if cargo_labels:
                            idx_cargo = (
                                cargo_labels.index(cargo_atual)
                                if cargo_atual in cargo_labels
                                else 0
                            )
                            cargo_edit_nome = st.selectbox(
                                "Cargo",
                                cargo_labels,
                                index=idx_cargo,
                                key=f"edit_colab_cargo_{colaborador_id}",
                            )
                            novo_cargo_id = next(
                                row["id"]
                                for row in cargos
                                if row["nome"] == cargo_edit_nome
                            )
                        else:
                            novo_cargo_id = colab["cargo_id"]

                        novo_status = st.selectbox(
                            "Status",
                            ["Ativo", "Afastado", "Férias", "Desligado"],
                            index=(
                                ["Ativo", "Afastado", "Férias", "Desligado"].index(
                                    colab["status"]
                                )
                                if colab["status"]
                                in ["Ativo", "Afastado", "Férias", "Desligado"]
                                else 0
                            ),
                            key=f"edit_colab_status_{colaborador_id}",
                        )

                    a1, a2 = st.columns(2)

                    with a1:
                        if st.button(
                            "Salvar alteração",
                            key=f"salvar_colab_{colaborador_id}",
                            use_container_width=True,
                        ):
                            if not novo_nome.strip():
                                st.error("Informe o nome do colaborador.")
                            else:
                                conn.execute(
                                    """
                                    UPDATE colaboradores
                                    SET matricula = %s,
                                        nome = %s,
                                        cpf = %s,
                                        email = %s,
                                        telefone = %s,
                                        filial_id = %s,
                                        setor_id = %s,
                                        cargo_id = %s,
                                        status = %s
                                    WHERE id = %s
                                    """,
                                    (
                                        nova_matricula.strip(),
                                        novo_nome.strip(),
                                        formatar_cpf(novo_cpf.strip()),
                                        novo_email.strip().lower(),
                                        novo_telefone.strip(),
                                        nova_filial_id,
                                        novo_setor_id,
                                        novo_cargo_id,
                                        novo_status,
                                        colaborador_id,
                                    ),
                                )
                                st.session_state.colaborador_editando_id = None
                                st.success("Colaborador atualizado com sucesso.")
                                st.rerun()

                    with a2:
                        if st.button(
                            "Cancelar alteração",
                            key=f"cancelar_colab_{colaborador_id}",
                            use_container_width=True,
                        ):
                            st.session_state.colaborador_editando_id = None
                            st.rerun()
    else:
        st.info("Nenhum colaborador cadastrado ainda.")

elif menu == "Cadastro de Setores" and perfil_atual in ("admin", "gestor"):
    exigir_perfil("admin", "gestor")
    st.header("Cadastro de Setores")
    empresa_id = get_empresa_id()

    with st.expander("Novo setor", expanded=True):
        nome_setor = st.text_input("Nome do Setor", key="setor_nome")
        ativo_setor = st.checkbox("Ativo", value=True, key="setor_ativo")
        if st.button("Cadastrar Setor", key="btn_cadastrar_setor"):
            if not nome_setor.strip():
                st.error("Informe o nome do setor.")
            else:
                conn.execute(
                    "INSERT INTO setores (empresa_id, nome, ativo) VALUES (%s, %s, %s)",
                    (empresa_id, nome_setor.strip(), ativo_setor),
                )
                st.success("Setor cadastrado com sucesso.")
                st.rerun()

    st.markdown("---")
    st.subheader("Setores cadastrados")
    if "setor_editando_id" not in st.session_state:
        st.session_state.setor_editando_id = None

    setores = conn.execute(
        "SELECT id, nome, ativo FROM setores WHERE empresa_id = %s ORDER BY id",
        (empresa_id,),
    ).fetchall()
    if setores:
        setores, _, _ = paginar_registros(
            setores, "pagina_setores_cadastro", page_size=10
        )
        for setor in setores:
            setor_id = setor["id"]
            with st.container(border=True):
                col1, col2, col3 = st.columns([2.2, 1.2, 3.2])
                with col1:
                    st.write(f"**ID {setor['id']} - {setor['nome']}**")
                with col2:
                    st.write("Ativo" if bool(setor["ativo"]) else "Inativo")
                with col3:
                    b1, b2, b3 = st.columns(3)
                    with b1:
                        if bool(setor["ativo"]):
                            if st.button(
                                "Inativar",
                                key=f"inativar_setor_{setor_id}",
                                use_container_width=True,
                            ):
                                conn.execute(
                                    "UPDATE setores SET ativo = FALSE WHERE id = %s AND empresa_id = %s",
                                    (setor_id, empresa_id),
                                )
                                st.rerun()
                        else:
                            if st.button(
                                "Ativar",
                                key=f"ativar_setor_{setor_id}",
                                use_container_width=True,
                            ):
                                conn.execute(
                                    "UPDATE setores SET ativo = TRUE WHERE id = %s AND empresa_id = %s",
                                    (setor_id, empresa_id),
                                )
                                st.rerun()
                    with b2:
                        if st.button(
                            "Excluir",
                            key=f"excluir_setor_{setor_id}",
                            use_container_width=True,
                        ):
                            possui = conn.execute(
                                "SELECT 1 FROM colaboradores WHERE setor_id = %s AND empresa_id = %s LIMIT 1",
                                (setor_id, empresa_id),
                            ).fetchone()
                            if possui:
                                st.warning(
                                    "Este setor possui colaboradores vinculados. Inative ao invés de excluir."
                                )
                            else:
                                conn.execute(
                                    "DELETE FROM setores WHERE id = %s AND empresa_id = %s",
                                    (setor_id, empresa_id),
                                )
                                st.success("Setor excluído.")
                                st.rerun()
                    with b3:
                        if st.button(
                            "Alterar",
                            key=f"alterar_setor_{setor_id}",
                            use_container_width=True,
                        ):
                            st.session_state.setor_editando_id = setor_id
                            st.rerun()
                if st.session_state.setor_editando_id == setor_id:
                    novo_nome_setor = st.text_input(
                        "Nome do Setor",
                        value=setor["nome"] or "",
                        key=f"edit_setor_nome_{setor_id}",
                    )
                    a1, a2 = st.columns(2)
                    with a1:
                        if st.button(
                            "Salvar alteração",
                            key=f"salvar_setor_{setor_id}",
                            use_container_width=True,
                        ):
                            if not novo_nome_setor.strip():
                                st.error("Informe o nome do setor.")
                            else:
                                conn.execute(
                                    "UPDATE setores SET nome = %s WHERE id = %s AND empresa_id = %s",
                                    (novo_nome_setor.strip(), setor_id, empresa_id),
                                )
                                st.session_state.setor_editando_id = None
                                st.success("Setor atualizado com sucesso.")
                                st.rerun()
                    with a2:
                        if st.button(
                            "Cancelar alteração",
                            key=f"cancelar_setor_{setor_id}",
                            use_container_width=True,
                        ):
                            st.session_state.setor_editando_id = None
                            st.rerun()
    else:
        st.info("Nenhum setor cadastrado ainda.")

elif menu == "Cadastro de Cargos" and perfil_atual in ("admin", "gestor"):
    exigir_perfil("admin", "gestor")
    st.header("Cadastro de Cargos")
    empresa_id = get_empresa_id()

    with st.expander("Novo cargo", expanded=True):
        nome_cargo = st.text_input("Nome do Cargo", key="cargo_nome")
        ativo_cargo = st.checkbox("Ativo", value=True, key="cargo_ativo")
        if st.button("Cadastrar Cargo", key="btn_cadastrar_cargo"):
            if not nome_cargo.strip():
                st.error("Informe o nome do cargo.")
            else:
                conn.execute(
                    "INSERT INTO cargos (empresa_id, nome, ativo) VALUES (%s, %s, %s)",
                    (empresa_id, nome_cargo.strip(), ativo_cargo),
                )
                st.success("Cargo cadastrado com sucesso.")
                st.rerun()

    st.markdown("---")
    st.subheader("Cargos cadastrados")
    if "cargo_editando_id" not in st.session_state:
        st.session_state.cargo_editando_id = None
    cargos_lista = conn.execute(
        "SELECT id, nome, ativo FROM cargos WHERE empresa_id = %s ORDER BY id",
        (empresa_id,),
    ).fetchall()
    if cargos_lista:
        cargos_lista, _, _ = paginar_registros(
            cargos_lista, "pagina_cargos_cadastro", page_size=10
        )
        for cargo in cargos_lista:
            cargo_id = cargo["id"]
            with st.container(border=True):
                c1, c2, c3 = st.columns([3, 1.5, 3])
                with c1:
                    st.write(f"**ID {cargo['id']} - {cargo['nome']}**")
                with c2:
                    st.write("Ativo" if bool(cargo["ativo"]) else "Inativo")
                with c3:
                    b1, b2, b3 = st.columns(3)
                    with b1:
                        if bool(cargo["ativo"]):
                            if st.button(
                                "Inativar",
                                key=f"inativar_cargo_{cargo_id}",
                                use_container_width=True,
                            ):
                                conn.execute(
                                    "UPDATE cargos SET ativo = FALSE WHERE id = %s AND empresa_id = %s",
                                    (cargo_id, empresa_id),
                                )
                                st.rerun()
                        else:
                            if st.button(
                                "Ativar",
                                key=f"ativar_cargo_{cargo_id}",
                                use_container_width=True,
                            ):
                                conn.execute(
                                    "UPDATE cargos SET ativo = TRUE WHERE id = %s AND empresa_id = %s",
                                    (cargo_id, empresa_id),
                                )
                                st.rerun()
                    with b2:
                        if st.button(
                            "Excluir",
                            key=f"excluir_cargo_{cargo_id}",
                            use_container_width=True,
                        ):
                            possui = conn.execute(
                                "SELECT 1 FROM colaboradores WHERE cargo_id = %s AND empresa_id = %s LIMIT 1",
                                (cargo_id, empresa_id),
                            ).fetchone()
                            if possui:
                                st.warning(
                                    "Este cargo possui colaboradores vinculados. Inative ao invés de excluir."
                                )
                            else:
                                conn.execute(
                                    "DELETE FROM cargos WHERE id = %s AND empresa_id = %s",
                                    (cargo_id, empresa_id),
                                )
                                st.success("Cargo excluído.")
                                st.rerun()
                    with b3:
                        if st.button(
                            "Alterar",
                            key=f"alterar_cargo_{cargo_id}",
                            use_container_width=True,
                        ):
                            st.session_state.cargo_editando_id = cargo_id
                            st.rerun()
                if st.session_state.cargo_editando_id == cargo_id:
                    novo_nome_cargo = st.text_input(
                        "Nome do Cargo",
                        value=cargo["nome"] or "",
                        key=f"edit_cargo_nome_{cargo_id}",
                    )
                    a1, a2 = st.columns(2)
                    with a1:
                        if st.button(
                            "Salvar alteração",
                            key=f"salvar_cargo_{cargo_id}",
                            use_container_width=True,
                        ):
                            if not novo_nome_cargo.strip():
                                st.error("Informe o nome do cargo.")
                            else:
                                conn.execute(
                                    "UPDATE cargos SET nome = %s WHERE id = %s AND empresa_id = %s",
                                    (novo_nome_cargo.strip(), cargo_id, empresa_id),
                                )
                                st.session_state.cargo_editando_id = None
                                st.success("Cargo atualizado com sucesso.")
                                st.rerun()
                    with a2:
                        if st.button(
                            "Cancelar alteração",
                            key=f"cancelar_cargo_{cargo_id}",
                            use_container_width=True,
                        ):
                            st.session_state.cargo_editando_id = None
                            st.rerun()
    else:
        st.info("Nenhum cargo cadastrado ainda.")

elif menu == "Quadro de Funcionários" and perfil_atual in ("admin", "gestor"):
    exigir_perfil("admin", "gestor")
    st.header("Quadro de Funcionários")
    empresa_id = get_empresa_id()

    dados = conn.execute(
        """
        SELECT
            c.id, c.nome, c.matricula, c.status, c.ativo,
            f.nome AS filial, s.nome AS setor, cg.nome AS cargo, c.data_admissao
        FROM colaboradores c
        LEFT JOIN filiais f ON f.id = c.filial_id AND f.empresa_id = c.empresa_id
        LEFT JOIN setores s ON s.id = c.setor_id AND s.empresa_id = c.empresa_id
        LEFT JOIN cargos cg ON cg.id = c.cargo_id AND cg.empresa_id = c.empresa_id
        WHERE c.empresa_id = %s
        ORDER BY c.nome
        """,
        (empresa_id,),
    ).fetchall()

    df = pd.DataFrame(dados) if dados else pd.DataFrame()
    if df.empty:
        st.info("Nenhum colaborador cadastrado.")
    else:
        st.subheader("Filtros")
        col1, col2, col3 = st.columns(3)
        with col1:
            filiais_filtro = ["Todos"] + sorted(df["filial"].dropna().unique().tolist())
            filtro_filial = st.selectbox("Filial", filiais_filtro)
        with col2:
            setores_filtro = ["Todos"] + sorted(df["setor"].dropna().unique().tolist())
            filtro_setor = st.selectbox("Setor", setores_filtro)
        with col3:
            status_filtro = ["Todos"] + sorted(df["status"].dropna().unique().tolist())
            filtro_status = st.selectbox("Status", status_filtro)

        df_filtrado = df.copy()
        if filtro_filial != "Todos":
            df_filtrado = df_filtrado[df_filtrado["filial"] == filtro_filial]
        if filtro_setor != "Todos":
            df_filtrado = df_filtrado[df_filtrado["setor"] == filtro_setor]
        if filtro_status != "Todos":
            df_filtrado = df_filtrado[df_filtrado["status"] == filtro_status]

        st.markdown("---")
        colA, colB, colC = st.columns(3)
        colA.metric("Total", len(df_filtrado))
        colB.metric("Ativos", len(df_filtrado[df_filtrado["ativo"] == True]))
        colC.metric(
            "Desligados", len(df_filtrado[df_filtrado["status"] == "Desligado"])
        )

        st.markdown("---")
        st.subheader("Lista de Colaboradores")
        st.dataframe(
            df_filtrado[
                [
                    "nome",
                    "matricula",
                    "filial",
                    "setor",
                    "cargo",
                    "status",
                    "ativo",
                    "data_admissao",
                ]
            ],
            use_container_width=True,
        )

elif menu == "Cadastro de Atendentes" and perfil_atual == "admin":
    st.header("Cadastro de Atendentes")

    with st.expander("Novo atendente", expanded=True):
        nome_atendente = st.text_input("Nome do atendente")
        usuario_atendente = st.text_input(
            "Usuário do atendente",
            value=gerar_usuario(nome_atendente) if nome_atendente.strip() else "",
            key="novo_atendente_usuario",
        )
        email_atendente = st.text_input("E-mail", key="novo_atendente_email")
        senha_atendente = st.text_input(
            "Senha", type="password", key="novo_atendente_senha"
        )
        ativo_atendente = st.checkbox("Ativo", value=True, key="novo_atendente_ativo")

        if st.button("Cadastrar Atendente"):
            if (
                not nome_atendente.strip()
                or not usuario_atendente.strip()
                or not senha_atendente.strip()
            ):
                st.error("Preencha nome, usuário e senha.")
            else:
                existe = conn.execute(
                    "SELECT 1 FROM atendentes WHERE usuario = %s",
                    (usuario_atendente.strip(),),
                ).fetchone()
                if existe:
                    st.error("Já existe um atendente com esse usuário.")
                else:
                    conn.execute(
                        """
                        INSERT INTO atendentes (nome, usuario, senha, email, ativo)
                        VALUES (%s, %s, %s, %s, %s)
                        """,
                        (
                            nome_atendente.strip(),
                            usuario_atendente.strip(),
                            gerar_hash_senha(senha_atendente.strip()),
                            email_atendente.strip().lower(),
                            ativo_atendente,
                        ),
                    )
                    st.success("Atendente cadastrado com sucesso.")
                    st.rerun()

    st.markdown("---")
    st.subheader("Atendentes cadastrados")

    if "atendente_editando_id" not in st.session_state:
        st.session_state.atendente_editando_id = None

    atendentes = obter_todos_atendentes()

    if atendentes:
        atendentes, _, _ = paginar_registros(
            atendentes, "pagina_atendentes_cadastro", page_size=10
        )
        for atendente in atendentes:
            atendente_id = atendente["id"]
            with st.container(border=True):
                col1, col2, col3 = st.columns([2.2, 2.4, 3.4])

                with col1:
                    st.write(f"**{atendente['usuario']}**")
                    st.caption(atendente["nome"] or "")

                with col2:
                    st.write(atendente["email"] or "Sem e-mail")
                    st.write("Ativo" if bool(atendente["ativo"]) else "Inativo")

                with col3:
                    b1, b2, b3 = st.columns(3)
                    with b1:
                        if bool(atendente["ativo"]):
                            if st.button(
                                "Inativar",
                                key=f"inativar_atendente_{atendente_id}",
                                use_container_width=True,
                            ):
                                conn.execute(
                                    "UPDATE atendentes SET ativo = FALSE WHERE id = %s",
                                    (atendente_id,),
                                )
                                st.rerun()
                        else:
                            if st.button(
                                "Ativar",
                                key=f"ativar_atendente_{atendente_id}",
                                use_container_width=True,
                            ):
                                conn.execute(
                                    "UPDATE atendentes SET ativo = TRUE WHERE id = %s",
                                    (atendente_id,),
                                )
                                st.rerun()

                    with b2:
                        if st.button(
                            "Excluir",
                            key=f"excluir_atendente_{atendente_id}",
                            use_container_width=True,
                        ):
                            possui_vinculo = conn.execute(
                                "SELECT 1 FROM solicitacoes WHERE atendente_id = %s LIMIT 1",
                                (atendente_id,),
                            ).fetchone()

                            if possui_vinculo:
                                st.warning(
                                    "Este atendente já está vinculado a solicitações. Inative ao invés de excluir."
                                )
                            else:
                                conn.execute(
                                    "DELETE FROM atendentes WHERE id = %s",
                                    (atendente_id,),
                                )
                                st.success("Atendente excluído.")
                                st.rerun()

                    with b3:
                        if st.button(
                            "Alterar",
                            key=f"alterar_atendente_{atendente_id}",
                            use_container_width=True,
                        ):
                            st.session_state.atendente_editando_id = atendente_id
                            st.rerun()

                if st.session_state.atendente_editando_id == atendente_id:
                    ed1, ed2 = st.columns(2)

                    with ed1:
                        novo_nome_at = st.text_input(
                            "Nome",
                            value=atendente["nome"] or "",
                            key=f"edit_at_nome_{atendente_id}",
                        )
                        novo_usuario_at = st.text_input(
                            "Usuário",
                            value=atendente["usuario"] or "",
                            key=f"edit_at_usuario_{atendente_id}",
                        )

                    with ed2:
                        novo_email_at = st.text_input(
                            "E-mail",
                            value=atendente["email"] or "",
                            key=f"edit_at_email_{atendente_id}",
                        )
                        nova_senha_at = st.text_input(
                            "Nova senha (opcional)",
                            type="password",
                            key=f"edit_at_senha_{atendente_id}",
                        )

                    a1, a2 = st.columns(2)
                    with a1:
                        if st.button(
                            "Salvar alteração",
                            key=f"salvar_atendente_{atendente_id}",
                            use_container_width=True,
                        ):
                            if not novo_nome_at.strip() or not novo_usuario_at.strip():
                                st.error("Preencha nome e usuário.")
                            else:
                                usuario_existente = conn.execute(
                                    "SELECT 1 FROM atendentes WHERE usuario = %s AND id <> %s",
                                    (novo_usuario_at.strip(), atendente_id),
                                ).fetchone()

                                if usuario_existente:
                                    st.error(
                                        "Já existe outro atendente com esse usuário."
                                    )
                                else:
                                    if nova_senha_at.strip():
                                        conn.execute(
                                            """
                                            UPDATE atendentes
                                            SET nome = %s, usuario = %s, email = %s, senha = %s
                                            WHERE id = %s
                                            """,
                                            (
                                                novo_nome_at.strip(),
                                                novo_usuario_at.strip(),
                                                novo_email_at.strip().lower(),
                                                gerar_hash_senha(nova_senha_at.strip()),
                                                atendente_id,
                                            ),
                                        )
                                    else:
                                        conn.execute(
                                            """
                                            UPDATE atendentes
                                            SET nome = %s, usuario = %s, email = %s
                                            WHERE id = %s
                                            """,
                                            (
                                                novo_nome_at.strip(),
                                                novo_usuario_at.strip(),
                                                novo_email_at.strip().lower(),
                                                atendente_id,
                                            ),
                                        )

                                    st.session_state.atendente_editando_id = None
                                    st.success("Atendente atualizado com sucesso.")
                                    st.rerun()
                    with a2:
                        if st.button(
                            "Cancelar alteração",
                            key=f"cancelar_atendente_{atendente_id}",
                            use_container_width=True,
                        ):
                            st.session_state.atendente_editando_id = None
                            st.rerun()
    else:
        st.info("Nenhum atendente cadastrado ainda.")


elif menu == "Painel de Cadastros" and perfil_atual == "admin":
    st.header("Painel de Cadastros")
    st.caption(
        "Pré-cadastro por convite com geração de link para conclusão pelo cliente ou atendente."
    )

    tab1, tab2, tab3 = st.tabs(["Novo convite", "Pendentes / enviados", "Concluídos"])

    with tab1:
        empresas = conn.execute(
            "SELECT id, fantasia FROM empresas WHERE ativo = TRUE ORDER BY fantasia"
        ).fetchall()
        nome_convite = st.text_input("Nome", key="convite_nome")
        email_convite = st.text_input("E-mail", key="convite_email")
        tipo_convite = st.selectbox(
            "Tipo de usuário", ["cliente", "atendente"], key="convite_tipo"
        )
        obs_convite = st.text_area("Observação", key="convite_obs")
        empresa_id_convite = None

        if empresas:
            opcoes = ["Selecione"] + [row["fantasia"] for row in empresas]
            empresa_nome = st.selectbox("Empresa", opcoes, key="convite_empresa")
            if empresa_nome != "Selecione":
                empresa_id_convite = next(
                    row["id"] for row in empresas if row["fantasia"] == empresa_nome
                )
        else:
            st.warning(
                "Cadastre ao menos uma empresa ativa para usar o painel de convites."
            )

        if st.button("Gerar convite e link", key="criar_convite_btn"):
            if not nome_convite.strip() or not email_convite.strip():
                st.error("Preencha nome e e-mail.")
            elif tipo_convite == "cliente" and not empresa_id_convite:
                st.error("Selecione a empresa do cliente.")
            else:
                resultado_convite = criar_convite(
                    nome=nome_convite,
                    email=email_convite,
                    empresa_id=empresa_id_convite,
                    tipo_usuario=tipo_convite,
                    observacao=obs_convite,
                )
                link = resultado_convite["link"]
                if resultado_convite["email_enviado"]:
                    st.success("Convite criado e enviado por e-mail com sucesso.")
                else:
                    st.warning(
                        f"Convite criado, mas o e-mail não foi enviado. Motivo: {resultado_convite['email_msg']}"
                    )
                st.code(link, language="text")
                st.session_state["ultimo_link_convite"] = link

        ultimo_link = st.session_state.get("ultimo_link_convite")
        if ultimo_link:
            st.caption("Último link gerado")
            st.code(ultimo_link, language="text")

    with tab2:
        convites = conn.execute(
            """
            SELECT c.*, e.fantasia AS empresa_nome
            FROM convites_cadastro c
            LEFT JOIN empresas e ON e.id = c.empresa_id
            WHERE c.status IN ('pendente', 'enviado', 'expirado')
            ORDER BY c.created_at DESC
            """
        ).fetchall()

        if not convites:
            st.info("Nenhum convite pendente/enviado.")
        else:
            for convite in convites:
                link = montar_url_convite(convite["token"])
                with st.container(border=True):
                    c1, c2, c3, c4 = st.columns([2.4, 1.6, 1.4, 3.2])
                    with c1:
                        st.write(f"**{convite['nome']}**")
                        st.caption(convite["email"])
                    with c2:
                        st.write(convite["tipo_usuario"].capitalize())
                        st.caption(convite.get("empresa_nome") or "Sem empresa")
                    with c3:
                        st.write(convite["status"].capitalize())
                        exp = (
                            convite["expiracao_em"].strftime("%d/%m/%Y %H:%M")
                            if convite["expiracao_em"]
                            else "-"
                        )
                        st.caption(f"Expira em {exp}")
                    with c4:
                        a1, a2, a3 = st.columns(3)
                        with a1:
                            if st.button(
                                "Reenviar",
                                key=f"reenviar_convite_{convite['id']}",
                                use_container_width=True,
                            ):
                                resultado_reenvio = reenviar_convite(convite["id"])
                                st.session_state[f"link_convite_{convite['id']}"] = (
                                    resultado_reenvio["link"]
                                )
                                if resultado_reenvio["email_enviado"]:
                                    st.success(
                                        "Convite reenviado por e-mail com novo link."
                                    )
                                else:
                                    st.warning(
                                        f"Convite renovado com novo link, mas o e-mail não foi enviado. Motivo: {resultado_reenvio['email_msg']}"
                                    )
                                st.rerun()
                        with a2:
                            if st.button(
                                "Cancelar",
                                key=f"cancelar_convite_{convite['id']}",
                                use_container_width=True,
                            ):
                                conn.execute(
                                    "UPDATE convites_cadastro SET status = 'cancelado' WHERE id = %s",
                                    (convite["id"],),
                                )
                                st.success("Convite cancelado.")
                                st.rerun()
                        with a3:
                            st.code(
                                st.session_state.get(
                                    f"link_convite_{convite['id']}", link
                                ),
                                language="text",
                            )

    with tab3:
        concluidos = conn.execute(
            """
            SELECT c.*, e.fantasia AS empresa_nome
            FROM convites_cadastro c
            LEFT JOIN empresas e ON e.id = c.empresa_id
            WHERE c.status = 'concluido'
            ORDER BY c.utilizado_em DESC NULLS LAST, c.created_at DESC
            """
        ).fetchall()
        if not concluidos:
            st.info("Nenhum cadastro concluído ainda.")
        else:
            for convite in concluidos:
                with st.container(border=True):
                    st.write(f"**{convite['nome']}** • {convite['email']}")
                    st.caption(
                        f"Tipo: {convite['tipo_usuario'].capitalize()} • "
                        f"Empresa: {convite.get('empresa_nome') or 'Sem empresa'} • "
                        f"Concluído em: {convite['utilizado_em'].strftime('%d/%m/%Y %H:%M') if convite['utilizado_em'] else '-'}"
                    )
                    print(
                        f"Convite ID {convite['id']} - Status: {convite['status']} - Criado em: {convite['created_at']}"
                    )
