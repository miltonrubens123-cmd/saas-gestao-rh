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
import time


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


def obter_arquivo_documento(doc_id, empresa_id):
    return conn.execute(
        """
        SELECT arquivo, arquivo_nome
        FROM documentos_sst
        WHERE id = %s AND empresa_id = %s
        """,
        (doc_id, empresa_id),
    ).fetchone()


def listar_documentos_sst(empresa_id, limite=20, offset=0):
    return conn.execute(
        """
        SELECT
            d.id,
            d.titulo,
            d.data_emissao,
            d.data_vencimento,
            d.status,
            d.arquivo_nome,
            td.nome AS tipo_documento,
            td.escopo,
            c.nome AS colaborador_nome,
            c.matricula,
            f.nome AS filial_nome
        FROM documentos_sst d
        JOIN tipos_documento_sst td ON td.id = d.tipo_documento_id
        LEFT JOIN colaboradores c ON c.id = d.colaborador_id
        LEFT JOIN filiais f ON f.id = d.filial_id
        WHERE d.empresa_id = %s
        ORDER BY d.id DESC
        LIMIT %s OFFSET %s
        """,
        (empresa_id, limite, offset),
    ).fetchall()


@st.cache_data(ttl=30)
def listar_documentos_sst_resumo(empresa_id):
    return conn.execute(
        """
        SELECT
            d.id,
            d.titulo,
            d.data_emissao,
            d.data_vencimento,
            d.status,
            d.arquivo_nome,
            td.nome AS tipo_documento,
            td.escopo,
            c.nome AS colaborador_nome,
            c.matricula,
            f.nome AS filial_nome
        FROM documentos_sst d
        JOIN tipos_documento_sst td ON td.id = d.tipo_documento_id
        LEFT JOIN colaboradores c ON c.id = d.colaborador_id
        LEFT JOIN filiais f ON f.id = d.filial_id
        WHERE d.empresa_id = %s
        ORDER BY d.id DESC
        """,
        (empresa_id,),
    ).fetchall()


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


def get_empresa_contexto():
    empresa_id = st.session_state.get("empresa_id")
    if not empresa_id:
        st.error("Sessão inválida ou expirada. Faça login novamente.")
        st.stop()
    return empresa_id


def get_user_id():
    user_id = st.session_state.get("user_id")
    if not user_id:
        st.error("Sessão inválida ou expirada. Faça login novamente.")
        st.stop()
    return user_id


def get_perfil():
    perfil = st.session_state.get("perfil")
    if not perfil:
        st.error("Sessão inválida ou expirada. Faça login novamente.")
        st.stop()
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


def get_empresa_contexto():
    empresa_id = st.session_state.get("empresa_id_contexto")
    if not empresa_id:
        st.error("Nenhuma empresa selecionada ou vinculada ao usuário.")
        st.stop()
    return empresa_id


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

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tipos_documento_sst (
            id BIGSERIAL PRIMARY KEY,
            codigo TEXT NOT NULL UNIQUE,
            nome TEXT NOT NULL,
            escopo TEXT NOT NULL,
            periodicidade_meses INTEGER,
            exige_revisao_por_evento BOOLEAN DEFAULT FALSE,
            ativo BOOLEAN DEFAULT TRUE
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS documentos_sst (
            id BIGSERIAL PRIMARY KEY,
            empresa_id BIGINT NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
            filial_id BIGINT REFERENCES filiais(id) ON DELETE SET NULL,
            colaborador_id BIGINT REFERENCES colaboradores(id) ON DELETE SET NULL,
            tipo_documento_id BIGINT NOT NULL REFERENCES tipos_documento_sst(id),
            titulo TEXT NOT NULL,
            data_emissao DATE,
            data_vencimento DATE,
            status TEXT DEFAULT 'Vigente',
            observacao TEXT,
            arquivo_nome TEXT,
            arquivo BYTEA,
            revisao_necessaria BOOLEAN DEFAULT FALSE,
            criado_por BIGINT REFERENCES usuarios(id),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS eventos_revisao_sst (
            id BIGSERIAL PRIMARY KEY,
            empresa_id BIGINT NOT NULL REFERENCES empresas(id) ON DELETE CASCADE,
            filial_id BIGINT REFERENCES filiais(id) ON DELETE SET NULL,
            tipo_evento TEXT NOT NULL,
            descricao TEXT,
            data_evento DATE NOT NULL,
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

    if not coluna_existe("documentos_sst", "revisao_necessaria"):
        conn.execute(
            "ALTER TABLE documentos_sst ADD COLUMN revisao_necessaria BOOLEAN DEFAULT FALSE"
        )
    if not coluna_existe("documentos_sst", "criado_por"):
        conn.execute(
            "ALTER TABLE documentos_sst ADD COLUMN criado_por BIGINT REFERENCES usuarios(id)"
        )
    if not coluna_existe("documentos_sst", "updated_at"):
        conn.execute(
            "ALTER TABLE documentos_sst ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        )

    tipos_sst_padrao = [
        ("PGR", "Programa de Gerenciamento de Riscos", "empresa", 24, True),
        ("PCMSO_RA", "PCMSO - Relatório Analítico", "empresa", 12, False),
        ("LTCAT", "LTCAT", "empresa", 24, False),
        ("PERICULOSIDADE", "Laudo de Periculosidade", "empresa", 24, False),
        ("INSALUBRIDADE", "Laudo de Insalubridade", "empresa", 24, False),
        ("AET", "Análise Ergonômica do Trabalho", "empresa", 24, True),
        ("PAE", "Plano de Atendimento à Emergência", "empresa", 12, False),
        ("ASO_PERIODICO", "ASO Periódico", "colaborador", 12, False),
    ]

    for codigo, nome, escopo, periodicidade_meses, exige_revisao in tipos_sst_padrao:
        conn.execute(
            """
            INSERT INTO tipos_documento_sst
            (codigo, nome, escopo, periodicidade_meses, exige_revisao_por_evento, ativo)
            VALUES (%s, %s, %s, %s, %s, TRUE)
            ON CONFLICT (codigo) DO UPDATE
            SET nome = EXCLUDED.nome,
                escopo = EXCLUDED.escopo,
                periodicidade_meses = EXCLUDED.periodicidade_meses,
                exige_revisao_por_evento = EXCLUDED.exige_revisao_por_evento,
                ativo = TRUE
            """,
            (codigo, nome, escopo, periodicidade_meses, exige_revisao),
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


RUN_DB_BOOTSTRAP = os.getenv("RUN_DB_BOOTSTRAP", "true").lower() == "true"
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


def classificar_status_vencimento(data_vencimento):
    if not data_vencimento:
        return "Vigente"

    hoje = agora().date()
    if hasattr(data_vencimento, "date"):
        data_vencimento = data_vencimento.date()

    dias = (data_vencimento - hoje).days

    if dias < 0:
        return "Vencido"
    elif dias <= 30:
        return "A vencer"
    return "Vigente"


def atualizar_status_documentos_sst_empresa(empresa_id):
    conn.execute(
        """
        UPDATE documentos_sst
        SET
            status = CASE
                WHEN revisao_necessaria = TRUE THEN 'Revisão necessária'
                WHEN data_vencimento IS NULL THEN 'Vigente'
                WHEN data_vencimento < CURRENT_DATE THEN 'Vencido'
                WHEN data_vencimento <= CURRENT_DATE + INTERVAL '30 days' THEN 'A vencer'
                ELSE 'Vigente'
            END,
            updated_at = CURRENT_TIMESTAMP
        WHERE empresa_id = %s
        """,
        (empresa_id,),
    )


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


def logout():
    token = st.session_state.get("token_sessao")
    excluir_sessao(token)
    st.session_state.clear()
    st.query_params.clear()
    st.rerun()


def limpar_formulario():
    st.session_state.limpar_campos_nova_solicitacao = True
    st.rerun()


def nova_solicitacao():
    st.session_state.titulo = ""
    st.session_state.descricao = ""
    st.session_state.limpar_campos_nova_solicitacao = False
    st.rerun()


def paginar_registros(registros, state_key, page_size=12):
    total = len(registros or [])
    if total <= page_size:
        return registros, 1, 1

    total_paginas = (total + page_size - 1) // page_size
    pagina_atual = int(st.session_state.get(state_key, 1) or 1)
    pagina_atual = max(1, min(pagina_atual, total_paginas))
    st.session_state[state_key] = pagina_atual

    inicio = (pagina_atual - 1) * page_size
    fim = inicio + page_size

    nav1, nav2, nav3 = st.columns([1, 1.3, 1])
    with nav1:
        if st.button(
            "← Anterior",
            key=f"{state_key}_prev",
            use_container_width=True,
            disabled=pagina_atual == 1,
        ):
            st.session_state[state_key] = pagina_atual - 1
            st.rerun()
    with nav2:
        st.caption(f"Página {pagina_atual} de {total_paginas} • {total} registros")
    with nav3:
        if st.button(
            "Próxima →",
            key=f"{state_key}_next",
            use_container_width=True,
            disabled=pagina_atual >= total_paginas,
        ):
            st.session_state[state_key] = pagina_atual + 1
            st.rerun()

    return registros[inicio:fim], pagina_atual, total_paginas


def normalizar_status(status):
    mapa = {
        "Pendente": "Em análise",
        "Iniciado": "Em atendimento",
        "Pausado": "Aguardando cliente",
        "Resolvido": "Concluído",
        "Em análise": "Em análise",
        "Em atendimento": "Em atendimento",
        "Aguardando cliente": "Aguardando cliente",
        "Concluído": "Concluído",
    }
    return mapa.get(status, status)


def formatar_status_texto(status):
    status = normalizar_status(status)
    status_map = {
        "Em análise": "🔴 Em análise",
        "Em atendimento": "🟢 Em atendimento",
        "Aguardando cliente": "🟡 Aguardando cliente",
        "Concluído": "🔵 Concluído",
    }
    return status_map.get(status, status)


def obter_atendentes_ativos():
    return conn.execute(
        """
        SELECT id, nome, usuario, email, ativo, created_at
        FROM atendentes
        WHERE ativo = TRUE
        ORDER BY nome, usuario
        """
    ).fetchall()


def obter_todos_atendentes():
    return conn.execute(
        """
        SELECT id, nome, usuario, email, ativo, created_at
        FROM atendentes
        ORDER BY nome, usuario
        """
    ).fetchall()


def obter_clientes_ativos():
    return conn.execute(
        """
        SELECT usuario, nome
        FROM clientes
        WHERE ativo = TRUE
        ORDER BY nome, usuario
        """
    ).fetchall()


@st.cache_data(ttl=60)
def listar_tipos_documento_sst():
    return conn.execute(
        """
        SELECT id, codigo, nome, escopo, periodicidade_meses, exige_revisao_por_evento
        FROM tipos_documento_sst
        WHERE ativo = TRUE
        ORDER BY nome
        """
    ).fetchall()


@st.cache_data(ttl=60)
def listar_filiais_ativas(empresa_id):
    return conn.execute(
        """
        SELECT id, nome
        FROM filiais
        WHERE empresa_id = %s AND ativo = TRUE
        ORDER BY nome
        """,
        (empresa_id,),
    ).fetchall()


@st.cache_data(ttl=60)
def listar_colaboradores_ativos(empresa_id):
    return conn.execute(
        """
        SELECT id, nome
        FROM colaboradores
        WHERE empresa_id = %s AND ativo = TRUE
        ORDER BY nome
        """,
        (empresa_id,),
    ).fetchall()


def obter_nome_cliente(usuario):
    row = conn.execute(
        "SELECT nome FROM clientes WHERE usuario = %s",
        (usuario,),
    ).fetchone()
    return row["nome"] if row and row["nome"] else usuario


def atualizar_solicitacao(solicitacao_id, novo_status, observacao):
    novo_status = normalizar_status(novo_status)

    atual = conn.execute(
        """
        SELECT inicio_atendimento, fim_atendimento
        FROM solicitacoes
        WHERE id = %s
        """,
        (solicitacao_id,),
    ).fetchone()

    inicio_atendimento = atual["inicio_atendimento"] if atual else None
    fim_atendimento = atual["fim_atendimento"] if atual else None
    agora_atendimento = agora()

    if novo_status == "Em atendimento" and not inicio_atendimento:
        inicio_atendimento = agora_atendimento

    if novo_status == "Concluído":
        fim_atendimento = agora_atendimento

    conn.execute(
        """
        UPDATE solicitacoes
        SET status = %s,
            resposta = %s,
            inicio_atendimento = %s,
            fim_atendimento = %s
        WHERE id = %s
        """,
        (
            novo_status,
            (observacao or "").strip(),
            inicio_atendimento,
            fim_atendimento,
            solicitacao_id,
        ),
    )


def render_anexos_como_arquivo(solicitacao_id, prefixo="anexo"):
    anexos = conn.execute(
        """
        SELECT id, nome_arquivo, observacao, imagem
        FROM anexos
        WHERE solicitacao_id = %s
        ORDER BY id
        """,
        (solicitacao_id,),
    ).fetchall()

    if not anexos:
        return

    st.markdown("**Anexos do cliente:**")
    for anexo in anexos:
        nome_arquivo = anexo["nome_arquivo"] or "arquivo"
        observacao = anexo["observacao"] or "Sem observação"
        ext = Path(nome_arquivo).suffix.lower()
        mime = "image/png"
        if ext in [".jpg", ".jpeg"]:
            mime = "image/jpeg"
        elif ext == ".webp":
            mime = "image/webp"

        with st.expander(f"📎 {nome_arquivo}"):
            st.caption(observacao)
            st.image(anexo["imagem"], use_container_width=True)
            st.download_button(
                label="Baixar arquivo",
                data=anexo["imagem"],
                file_name=nome_arquivo,
                mime=mime,
                key=f"{prefixo}_download_{anexo['id']}",
                use_container_width=False,
            )


def calcular_data_vencimento_documento(data_emissao, periodicidade_meses):
    if not data_emissao or not periodicidade_meses:
        return None
    return (
        pd.Timestamp(data_emissao) + pd.DateOffset(months=int(periodicidade_meses))
    ).date()


def obter_solicitacoes_filtradas(
    cliente_id=None,
    cliente_usuario=None,
    empresa_id=None,
    status_filtro="Todos",
    prioridade_filtro="Todas",
    busca="",
    limite=50,
    atendente_usuario=None,
):
    filtros = []
    params = []

    if atendente_usuario:
        atendente = obter_atendente_por_usuario(atendente_usuario)
        if atendente:
            filtros.append("s.atendente_id = %s")
            params.append(atendente["id"])
        else:
            return []

    if cliente_id is not None:
        filtros.append("s.cliente_id = %s")
        params.append(cliente_id)
    elif empresa_id is not None:

        filtros.append("s.empresa_id = %s")
        params.append(empresa_id)
    elif cliente_usuario:
        cliente_ref = obter_cliente_por_usuario(cliente_usuario)
        if not cliente_ref:
            return []
        filtros.append("s.cliente_id = %s")
        params.append(cliente_ref["id"])

    if status_filtro != "Todos":
        filtros.append(
            """
            CASE
                WHEN s.status = 'Pendente' THEN 'Em análise'
                WHEN s.status = 'Iniciado' THEN 'Em atendimento'
                WHEN s.status = 'Pausado' THEN 'Aguardando cliente'
                WHEN s.status = 'Resolvido' THEN 'Concluído'
                ELSE s.status
            END = %s
            """
        )
        params.append(status_filtro)

    if prioridade_filtro != "Todas":
        filtros.append("COALESCE(s.prioridade, '') = %s")
        params.append(prioridade_filtro)

    busca = (busca or "").strip()
    if busca:
        if busca.isdigit():
            filtros.append("(CAST(s.id AS TEXT) = %s OR s.titulo ILIKE %s)")
            params.append(busca)
            params.append(f"%{busca}%")
        else:
            filtros.append("s.titulo ILIKE %s")
            params.append(f"%{busca}%")

    where_clause = " AND ".join(filtros) if filtros else "TRUE"

    sql = f"""
        SELECT
            s.id,
            s.cliente,
            s.cliente_id,
            s.empresa_id,
            s.atendente_id,
            a.nome AS atendente_nome,
            s.atribuido_em,
            s.titulo,
            s.descricao,
            s.prioridade,
            s.status,
            s.complexidade,
            s.resposta,
            s.data_criacao,
            s.inicio_atendimento,
            s.fim_atendimento
        FROM solicitacoes s
        LEFT JOIN atendentes a ON a.id = s.atendente_id
        WHERE {where_clause}
        ORDER BY s.id DESC
        LIMIT %s
    """
    params.append(limite)

    rows = conn.execute(sql, params).fetchall()
    dados = []
    for row in rows:
        item = dict(row)
        item["status"] = normalizar_status(item.get("status"))
        dados.append(item)
    return dados


def agrupar_solicitacoes_por_cliente(solicitacoes):
    grupos = defaultdict(list)
    for item in solicitacoes:
        chave = (item.get("cliente_id"), item.get("cliente"))
        grupos[chave].append(item)
    return grupos


def montar_url_convite(token_convite):
    base_url = (
        st.secrets.get("APP_BASE_URL") or os.getenv("APP_BASE_URL", "") or ""
    ).strip()

    if not base_url:
        return f"?invite={quote_plus(token_convite)}"

    base_url = base_url.rstrip("/")
    return f"{base_url}/?invite={quote_plus(token_convite)}"


def gerar_token_convite():
    return secrets.token_urlsafe(24)


def convite_expirado(convite):
    expiracao = convite.get("expiracao_em")
    if not expiracao:
        return False
    if expiracao.tzinfo is None:
        return expiracao < agora().replace(tzinfo=None)
    return expiracao < agora()


def obter_convite_por_token(token):
    convite = conn.execute(
        """
        SELECT c.*, e.fantasia AS empresa_nome
        FROM convites_cadastro c
        LEFT JOIN empresas e ON e.id = c.empresa_id
        WHERE c.token = %s
        LIMIT 1
        """,
        (token,),
    ).fetchone()

    if (
        convite
        and convite["status"] in ("pendente", "enviado")
        and convite_expirado(convite)
    ):
        conn.execute(
            "UPDATE convites_cadastro SET status = 'expirado' WHERE id = %s",
            (convite["id"],),
        )
        convite = conn.execute(
            """
            SELECT c.*, e.fantasia AS empresa_nome
            FROM convites_cadastro c
            LEFT JOIN empresas e ON e.id = c.empresa_id
            WHERE c.token = %s
            LIMIT 1
            """,
            (token,),
        ).fetchone()
    return convite


def criar_convite(nome, email, empresa_id, tipo_usuario, observacao=""):
    token = gerar_token_convite()
    usuario_sugerido = gerar_usuario(nome)
    enviado_em = agora()
    expiracao_em = agora() + timedelta(hours=CONVITE_EXPIRACAO_HORAS)

    convite = conn.execute(
        """
        INSERT INTO convites_cadastro
        (nome, email, empresa_id, tipo_usuario, token, status, observacao, usuario_sugerido, enviado_em, expiracao_em)
        VALUES (%s, %s, %s, %s, %s, 'enviado', %s, %s, %s, %s)
        RETURNING id
        """,
        (
            nome.strip(),
            email.strip().lower(),
            empresa_id,
            tipo_usuario,
            token,
            observacao.strip(),
            usuario_sugerido,
            enviado_em,
            expiracao_em,
        ),
    ).fetchone()

    link_convite = montar_url_convite(token)
    email_enviado = False
    email_msg = "Configuração de e-mail não encontrada. O convite foi criado apenas com link manual."

    if email_configurada():
        email_enviado, email_msg = enviar_email_convite(
            destinatario=email.strip().lower(),
            nome=nome.strip(),
            link=link_convite,
        )

    return {
        "id": convite["id"],
        "token": token,
        "link": link_convite,
        "email_enviado": email_enviado,
        "email_msg": email_msg,
    }


def calcular_vencimento_documento(data_emissao, periodicidade_meses):
    if not data_emissao or not periodicidade_meses:
        return None
    return (
        pd.Timestamp(data_emissao) + pd.DateOffset(months=int(periodicidade_meses))
    ).date()


def classificar_status_vencimento(data_vencimento, revisao_necessaria=False):
    if revisao_necessaria:
        return "Revisão necessária"

    if not data_vencimento:
        return "Vigente"

    hoje = agora().date()
    if hasattr(data_vencimento, "date"):
        data_vencimento = data_vencimento.date()

    dias = (data_vencimento - hoje).days

    if dias < 0:
        return "Vencido"
    elif dias <= 30:
        return "A vencer"
    return "Vigente"


def validar_upload_documento_sst(arquivo):
    nome = (arquivo.name or "").lower()
    ext = Path(nome).suffix.lower()
    permitidos = {".pdf", ".png", ".jpg", ".jpeg"}

    if ext not in permitidos:
        return False, "Tipo de arquivo inválido. Envie PDF, PNG, JPG ou JPEG."

    tamanho = len(arquivo.getvalue())
    limite = MAX_UPLOAD_MB * 1024 * 1024

    if tamanho > limite:
        return False, f"O arquivo excede o limite de {MAX_UPLOAD_MB} MB."

    return True, ""


def registrar_evento_revisao_sst(
    empresa_id, filial_id, tipo_evento, descricao, data_evento
):
    conn.execute(
        """
        INSERT INTO eventos_revisao_sst (
            empresa_id, filial_id, tipo_evento, descricao, data_evento, created_at
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            empresa_id,
            filial_id,
            tipo_evento,
            descricao.strip(),
            data_evento,
            agora(),
        ),
    )


def reenviar_convite(convite_id):
    convite = conn.execute(
        """
        SELECT id, nome, email
        FROM convites_cadastro
        WHERE id = %s
        LIMIT 1
        """,
        (convite_id,),
    ).fetchone()

    if not convite:
        raise ValueError("Convite não encontrado.")

    token = gerar_token_convite()
    enviado_em = agora()
    expiracao_em = agora() + timedelta(hours=CONVITE_EXPIRACAO_HORAS)

    conn.execute(
        """
        UPDATE convites_cadastro
        SET token = %s,
            status = 'enviado',
            enviado_em = %s,
            expiracao_em = %s
        WHERE id = %s
        """,
        (token, enviado_em, expiracao_em, convite_id),
    )

    link_convite = montar_url_convite(token)
    email_enviado = False
    email_msg = "Configuração de e-mail não encontrada. O convite foi renovado apenas com link manual."

    if email_configurada():
        email_enviado, email_msg = enviar_email_convite(
            destinatario=convite["email"],
            nome=convite["nome"],
            link=link_convite,
        )

    return {
        "token": token,
        "link": link_convite,
        "email_enviado": email_enviado,
        "email_msg": email_msg,
    }


def concluir_convite(
    convite, nome, usuario, senha, cpf="", funcao="", email="", nome_atendente=""
):
    tipo = convite["tipo_usuario"]

    if tipo == "cliente":
        existe = conn.execute(
            "SELECT 1 FROM clientes WHERE usuario = %s",
            (usuario,),
        ).fetchone()
        if existe:
            raise ValueError("Já existe um cliente com esse usuário.")

        conn.execute(
            """
            INSERT INTO clientes (usuario, senha, nome, ativo, cpf, empresa_id, funcao, email)
            VALUES (%s, %s, %s, TRUE, %s, %s, %s, %s)
            """,
            (
                usuario,
                gerar_hash_senha(senha),
                nome,
                cpf,
                convite["empresa_id"],
                funcao,
                email.strip().lower(),
            ),
        )
    else:
        existe = conn.execute(
            "SELECT 1 FROM atendentes WHERE usuario = %s",
            (usuario,),
        ).fetchone()
        if existe:
            raise ValueError("Já existe um atendente com esse usuário.")

        conn.execute(
            """
            INSERT INTO atendentes (nome, usuario, senha, email, ativo)
            VALUES (%s, %s, %s, %s, TRUE)
            """,
            (
                nome_atendente or nome,
                usuario,
                gerar_hash_senha(senha),
                email.strip().lower(),
            ),
        )

    conn.execute(
        """
        UPDATE convites_cadastro
        SET status = 'concluido',
            utilizado_em = %s
        WHERE id = %s
        """,
        (agora(), convite["id"]),
    )


def aplicar_estilo_login():
    st.markdown(
        """
        <style>
        html, body, [data-testid="stAppViewContainer"] {
            height: 100%;
        }

        .stApp {
            background: linear-gradient(135deg, #04182D 0%, #0B3A63 100%);
        }

        section[data-testid="stSidebar"] {
            display: none;
        }

        [data-testid="stHeader"] {
            background: transparent;
        }

        .block-container {
            max-width: 1380px;
            min-height: 100vh;
            display: flex;
            align-items: center;
            padding-top: 1.5rem !important;
            padding-bottom: 1.5rem !important;
        }

        .block-container > div {
            width: 100%;
        }

        .login-brand {
            min-height: 720px;
            border-radius: 32px;
            padding: 42px 42px;
            background: linear-gradient(180deg, rgba(7, 33, 66, 0.96) 0%, rgba(4, 35, 74, 0.98) 100%);
            border: 1px solid rgba(88, 140, 220, 0.28);
            box-shadow: 0 24px 60px rgba(0, 0, 0, 0.28);
            display: flex;
            align-items: center;
        }

        .login-brand-inner {
            width: 100%;
            max-width: 560px;
        }

        .login-brand-logo {
            margin-bottom: 22px;
        }

        .login-brand-logo img {
            max-width: 126px;
            width: 100%;
            height: auto;
            display: block;
        }

        .brand-kicker {
            color: #71B6FF;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 16px;
        }

        .brand-title-main {
            color: #FFFFFF;
            font-size: 66px;
            line-height: 1.02;
            font-weight: 800;
            margin: 0;
        }

        .brand-title-sub {
            color: #6FAEFF;
            font-size: 40px;
            line-height: 1.08;
            font-weight: 700;
            margin: 10px 0 26px 0;
        }

        .brand-description {
            color: #E4EEFA;
            font-size: 18px;
            line-height: 1.65;
            margin: 0 0 26px 0;
            max-width: 520px;
        }

        .brand-benefits {
            list-style: none;
            padding: 0;
            margin: 0 0 28px 0;
        }

        .brand-benefits li {
            color: #F3F8FF;
            font-size: 17px;
            line-height: 1.55;
            margin-bottom: 14px;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .brand-check {
            width: 18px;
            height: 18px;
            min-width: 18px;
            border-radius: 999px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: rgba(60, 126, 255, 0.18);
            border: 1px solid rgba(111, 174, 255, 0.35);
            color: #A8CCFF;
            font-size: 12px;
            font-weight: 700;
        }

        .brand-divider {
            height: 1px;
            width: 100%;
            max-width: 520px;
            background: rgba(133, 163, 204, 0.22);
            margin: 18px 0 22px 0;
        }

        .brand-footer {
            color: #B9CAE0;
            font-size: 16px;
            line-height: 1.6;
            max-width: 520px;
        }

        .login-panel-wrap {
            min-height: 720px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .login-panel {
            width: 100%;
            max-width: 520px;
            margin: auto;
            padding: 38px 34px 30px 34px;
            background: rgba(2, 21, 46, 0.84);
            border: 1px solid rgba(88, 140, 220, 0.22);
            border-radius: 30px;
            box-shadow: 0 24px 60px rgba(0, 0, 0, 0.24);
        }

        .login-panel-top-icon {
            width: 72px;
            height: 72px;
            margin: 0 auto 18px auto;
            border-radius: 999px;
            border: 1px solid rgba(111, 174, 255, 0.20);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #2E7DFF;
            font-size: 30px;
        }

        .login-panel h2 {
            margin: 0 0 12px 0;
            text-align: center;
            color: #FFFFFF;
            font-size: 28px;
            line-height: 1.15;
            font-weight: 800;
        }

        .login-panel .sub {
            text-align: center;
            color: #CBD8EA;
            font-size: 15px;
            line-height: 1.5;
            margin-bottom: 24px;
        }

        .stTextInput label {
            color: #E8F0FB !important;
            font-weight: 600 !important;
        }

        .stTextInput > div > div > input {
            background: rgba(255,255,255,0.05) !important;
            color: #FFFFFF !important;
            border: 1px solid rgba(150, 184, 227, 0.22) !important;
            border-radius: 12px !important;
            min-height: 48px !important;
        }

        .stTextInput > div > div > input::placeholder {
            color: #8EA7C6 !important;
        }

        .stButton > button {
            width: 100%;
            min-height: 50px;
            border-radius: 14px;
            font-weight: 700;
            font-size: 16px;
            border: 1px solid rgba(70, 122, 214, 0.55);
            background: linear-gradient(180deg, #1E56BA 0%, #1A4EAB 100%);
            color: #FFFFFF;
            box-shadow: 0 8px 22px rgba(20, 64, 146, 0.20);
        }

        .login-panel-divider {
            height: 1px;
            background: rgba(133, 163, 204, 0.18);
            margin: 22px 0 18px 0;
        }

        .login-panel-footer {
            text-align: center;
            color: #AABDD6;
            font-size: 14px;
            line-height: 1.5;
        }

        @media (max-width: 1100px) {
            .block-container {
                max-width: 100%;
                min-height: auto;
                display: block;
                padding-top: 1rem !important;
                padding-bottom: 1rem !important;
            }

            .login-brand,
            .login-panel-wrap {
                min-height: auto;
            }

            .login-panel {
                margin-top: 20px;
            }

            .brand-title-main {
                font-size: 52px;
            }

            .brand-title-sub {
                font-size: 32px;
            }
        }

        @media (max-width: 640px) {
            .login-brand {
                padding: 28px 22px;
                border-radius: 24px;
            }

            .login-panel {
                padding: 24px 18px 22px 18px;
                border-radius: 24px;
            }

            .brand-title-main {
                font-size: 42px;
            }

            .brand-title-sub {
                font-size: 26px;
            }

            .brand-description,
            .brand-benefits li,
            .brand-footer {
                font-size: 15px;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


@st.cache_data(ttl=60)
def listar_tipos_documento_sst():
    return conn.execute(
        """
        SELECT id, codigo, nome, escopo, periodicidade_meses, exige_revisao_por_evento
        FROM tipos_documento_sst
        WHERE ativo = TRUE
        ORDER BY nome
    """
    ).fetchall()


@st.cache_data(ttl=60)
def listar_filiais_ativas(empresa_id):
    return conn.execute(
        """
        SELECT id, nome
        FROM filiais
        WHERE empresa_id = %s AND ativo = TRUE
        ORDER BY nome
    """,
        (empresa_id,),
    ).fetchall()


@st.cache_data(ttl=60)
def listar_colaboradores_ativos(empresa_id):
    return conn.execute(
        """
        SELECT id, nome, matricula
        FROM colaboradores
        WHERE empresa_id = %s
        ORDER BY nome
    """,
        (empresa_id,),
    ).fetchall()


def render_tela_convite(token_convite):
    aplicar_estilo_login()

    convite = obter_convite_por_token(token_convite)

    col_left, col_center, col_right = st.columns([0.18, 0.64, 0.18])

    with col_center:
        st.markdown('<div class="convite-card">', unsafe_allow_html=True)

        if logo_b64:
            st.markdown(
                f"""
                <div class="convite-logo">
                    <img src="data:image/png;base64,{logo_b64}">
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown(
            """
            <div class="convite-titulo">Concluir cadastro</div>
            <div class="convite-subtitulo">
                Finalize seu acesso ao ambiente Gestão RH.
            </div>
            """,
            unsafe_allow_html=True,
        )

        if not convite:
            st.error("Convite inválido.")
            st.markdown("</div>", unsafe_allow_html=True)
            st.stop()

        if convite["status"] == "concluido":
            st.success("Este convite já foi utilizado.")
            portal_url = (
                st.secrets.get("APP_BASE_URL") or os.getenv("APP_BASE_URL", "") or ""
            ).rstrip("/")
            if portal_url:
                st.link_button("Acessar portal", portal_url, use_container_width=True)
                st.caption(f"Portal: {portal_url}")
            st.markdown("</div>", unsafe_allow_html=True)
            st.stop()

        if convite["status"] in ("cancelado", "expirado") or convite_expirado(convite):
            st.error("Este convite expirou ou foi cancelado.")
            st.markdown("</div>", unsafe_allow_html=True)
            st.stop()

        st.info(
            f"Convite para {convite['nome']} • Perfil: {convite['tipo_usuario'].capitalize()}"
            + (
                f" • Empresa: {convite['empresa_nome']}"
                if convite.get("empresa_nome")
                else ""
            )
        )

        email = st.text_input("E-mail", value=convite["email"], disabled=True)
        nome = st.text_input("Nome completo", value=convite["nome"])
        usuario = st.text_input(
            "Usuário",
            value=convite.get("usuario_sugerido") or gerar_usuario(convite["nome"]),
        )
        senha = st.text_input("Senha", type="password")
        confirmar_senha = st.text_input("Confirmar senha", type="password")

        cpf = ""
        funcao = ""
        if convite["tipo_usuario"] == "cliente":
            cpf = st.text_input("CPF")
            funcao = st.text_input("Função")
        else:
            funcao = st.text_input("Função / Cargo")

        if st.button("Concluir cadastro", use_container_width=True):
            if not nome.strip() or not usuario.strip() or not senha.strip():
                st.error("Preencha nome, usuário e senha.")
            elif senha != confirmar_senha:
                st.error("As senhas não conferem.")
            elif len(senha.strip()) < 6:
                st.error("A senha deve ter pelo menos 6 caracteres.")
            else:
                try:
                    concluir_convite(
                        convite=convite,
                        nome=nome.strip(),
                        usuario=usuario.strip(),
                        senha=senha.strip(),
                        cpf=cpf.strip(),
                        funcao=funcao.strip(),
                        email=email.strip(),
                        nome_atendente=nome.strip(),
                    )

                    st.success(
                        "Cadastro concluído com sucesso. Agora você já pode acessar o portal."
                    )

                    portal_url = (
                        st.secrets.get("APP_BASE_URL")
                        or os.getenv("APP_BASE_URL", "")
                        or ""
                    ).rstrip("/")

                    st.info(f"Usuário cadastrado: {usuario}")

                    if portal_url:
                        st.link_button(
                            "Acessar portal", portal_url, use_container_width=True
                        )
                        st.caption(f"Portal: {portal_url}")
                    else:
                        st.warning("URL do portal não configurada.")

                except ValueError as exc:
                    st.error(str(exc))
                except Exception as exc:
                    st.error(f"Erro ao concluir cadastro: {exc}")

        st.markdown("</div>", unsafe_allow_html=True)
        st.stop()


def render_tela_convite(token_convite):
    aplicar_estilo_login()

    st.markdown(
        """
        <style>
        .convite-card {
            width: 100%;
            max-width: 520px;
            margin: 40px auto 0 auto;
            background: rgba(5, 22, 38, 0.72);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 24px;
            padding: 28px 24px 24px 24px;
            box-shadow: 0 18px 54px rgba(0,0,0,0.22);
        }

        .convite-logo {
            display: flex;
            justify-content: center;
            margin-bottom: 14px;
        }

        .convite-logo img {
            max-width: 120px;
            width: 100%;
            height: auto;
            display: block;
        }

        .convite-titulo {
            text-align: center;
            color: white;
            font-size: 24px;
            font-weight: 700;
            line-height: 1.2;
            margin-bottom: 6px;
        }

        .convite-subtitulo {
            text-align: center;
            color: #c7d7e6;
            font-size: 15px;
            margin-bottom: 18px;
        }

        @media (max-width: 640px) {
            .block-container {
                padding-left: 12px !important;
                padding-right: 12px !important;
                padding-top: 18px !important;
                padding-bottom: 18px !important;
            }

            .convite-card {
                max-width: 100%;
                margin-top: 10px;
                padding: 22px 16px 18px 16px;
            }

            .convite-logo img {
                max-width: 88px;
            }

            .convite-titulo {
                font-size: 20px;
            }

            .convite-subtitulo {
                font-size: 14px;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    convite = obter_convite_por_token(token_convite)

    st.markdown('<div class="convite-card">', unsafe_allow_html=True)

    if logo_b64:
        st.markdown(
            f"""
            <div class="convite-logo">
                <img src="data:image/png;base64,{logo_b64}">
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown(
        '<div class="convite-titulo">Gestão RH</div>',
        unsafe_allow_html=True,
    )

    if not convite:
        st.error("Convite inválido.")
        st.markdown("</div>", unsafe_allow_html=True)
        st.stop()

    if convite["status"] == "concluido":
        st.success("Este convite já foi utilizado.")
        portal_url = (
            st.secrets.get("APP_BASE_URL") or os.getenv("APP_BASE_URL", "") or ""
        ).rstrip("/")
        if portal_url:
            st.link_button("Acessar portal", portal_url, use_container_width=True)
            st.caption(f"Portal: {portal_url}")
        st.markdown("</div>", unsafe_allow_html=True)
        st.stop()

    if convite["status"] in ("cancelado", "expirado") or convite_expirado(convite):
        st.error("Este convite expirou ou foi cancelado.")
        st.markdown("</div>", unsafe_allow_html=True)
        st.stop()

    st.markdown(
        '<div class="convite-subtitulo">Concluir cadastro</div>',
        unsafe_allow_html=True,
    )

    st.info(
        f"Convite para {convite['nome']} • Perfil: {convite['tipo_usuario'].capitalize()}"
        + (
            f" • Empresa: {convite['empresa_nome']}"
            if convite.get("empresa_nome")
            else ""
        )
    )

    email = st.text_input("E-mail", value=convite["email"], disabled=True)
    nome = st.text_input("Nome completo", value=convite["nome"])
    usuario = st.text_input(
        "Usuário",
        value=convite.get("usuario_sugerido") or gerar_usuario(convite["nome"]),
    )
    senha = st.text_input("Senha", type="password")
    confirmar_senha = st.text_input("Confirmar senha", type="password")

    cpf = ""
    funcao = ""
    if convite["tipo_usuario"] == "cliente":
        cpf = st.text_input("CPF")
        funcao = st.text_input("Função")
    else:
        funcao = st.text_input("Função / Cargo")

    if st.button("Concluir cadastro", use_container_width=True):
        if not nome.strip() or not usuario.strip() or not senha.strip():
            st.error("Preencha nome, usuário e senha.")
        elif senha != confirmar_senha:
            st.error("As senhas não conferem.")
        elif len(senha.strip()) < 6:
            st.error("A senha deve ter pelo menos 6 caracteres.")
        else:
            try:
                concluir_convite(
                    convite=convite,
                    nome=nome.strip(),
                    usuario=usuario.strip(),
                    senha=senha.strip(),
                    cpf=cpf.strip(),
                    funcao=funcao.strip(),
                    email=email.strip(),
                    nome_atendente=nome.strip(),
                )

                st.success(
                    "Cadastro concluído com sucesso. Agora você já pode acessar o portal."
                )

                portal_url = (
                    st.secrets.get("APP_BASE_URL")
                    or os.getenv("APP_BASE_URL", "")
                    or ""
                ).rstrip("/")

                st.info(f"Usuário cadastrado: {usuario}")

                if portal_url:
                    st.link_button(
                        "Acessar portal", portal_url, use_container_width=True
                    )
                    st.caption(f"Portal: {portal_url}")
                else:
                    st.warning("URL do portal não configurada.")

            except ValueError as exc:
                st.error(str(exc))
            except Exception as exc:
                st.error(f"Erro ao concluir cadastro: {exc}")

    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()


invite_token = st.query_params.get("invite")
if invite_token:
    render_tela_convite(invite_token)

# =========================
# TELA DE LOGIN (SaaS)
# =========================

if not st.session_state.get("logado", False):
    aplicar_estilo_login()

    col_left, col_right = st.columns([1.08, 0.92], gap="large")

    with col_left:
        st.markdown('<div class="glass-card glass-card-left">', unsafe_allow_html=True)

        st.markdown("### Plataforma corporativa")
        if logo_b64:
            st.image(f"data:image/png;base64,{logo_b64}")
        st.markdown("# Gestão RH")
        st.markdown("## Controle e inteligência para sua operação")
        st.write(
            "Centralize estrutura organizacional, usuários, colaboradores e indicadores "
            "em um ambiente seguro, escalável e orientado por dados."
        )
        st.write("✓ Controle do quadro em tempo real")
        st.write("✓ Estrutura por filiais, setores e cargos")
        st.write("✓ Acesso segregado por empresa")
        st.caption("Arquitetura SaaS • Segurança • Performance")

        st.markdown("</div>", unsafe_allow_html=True)

    with col_right:
        st.markdown('<div class="glass-card glass-card-right">', unsafe_allow_html=True)

        st.markdown("## Acessar plataforma")
        st.caption("Entre com seu usuário corporativo.")

        usuario_input = st.text_input(
            "Usuário ou e-mail",
            placeholder="Digite seu usuário ou e-mail",
            key="login_usuario",
        )

        senha_input = st.text_input(
            "Senha",
            type="password",
            placeholder="Digite sua senha",
            key="login_senha",
        )

        if st.button("ENTRAR", use_container_width=True, key="btn_login"):
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
                        "O acesso master legado não está habilitado neste fluxo SaaS."
                    )
                else:
                    st.error("Usuário ou senha inválidos.")

        st.caption("Ambiente seguro e preparado para empresas.")

        st.markdown("</div>", unsafe_allow_html=True)

    st.stop()


if not st.session_state.logado:
    aplicar_estilo_login()

    col_left, col_right = st.columns([1.08, 0.92], gap="large")

    with col_left:
        st.markdown(
            '<div class="login-brand"><div class="login-brand-inner">',
            unsafe_allow_html=True,
        )

        if logo_b64:
            st.markdown(
                f"""
                <div class="login-brand-logo">
                    <img src="data:image/png;base64,{logo_b64}">
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown(
            """
            <div class="brand-kicker">Plataforma corporativa</div>
            <div class="brand-title-main">Gestão RH -</div>
            <div class="brand-title-sub">Para empresas que exigem controle</div>

            <div class="brand-description">
                Centralize estrutura organizacional, usuários, colaboradores e indicadores em um ambiente seguro, profissional e preparado para crescer com a operação.
            </div>

            <ul class="brand-benefits">
                <li><span class="brand-check">✓</span> Controle do quadro em tempo real</li>
                <li><span class="brand-check">✓</span> Estrutura por filiais, setores e cargos</li>
                <li><span class="brand-check">✓</span> Acesso segregado por empresa</li>
            </ul>

            <div class="brand-divider"></div>

            <div class="brand-footer">
                Ambiente seguro, arquitetura SaaS e gestão orientada por dados.
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("</div></div>", unsafe_allow_html=True)

    with col_right:
        st.markdown(
            '<div class="login-panel-wrap"><div class="login-panel">',
            unsafe_allow_html=True,
        )

        st.markdown(
            '<div class="login-panel-top-icon">🔒</div>', unsafe_allow_html=True
        )
        st.markdown("<h2>Acessar plataforma</h2>", unsafe_allow_html=True)
        st.markdown(
            "<div class='sub'>Entre com seu e-mail ou usuário corporativo.</div>",
            unsafe_allow_html=True,
        )

        usuario_input = st.text_input(
            "Usuário ou e-mail",
            placeholder="Digite seu usuário ou e-mail",
        )

        senha_input = st.text_input(
            "Senha",
            type="password",
            placeholder="Digite sua senha",
        )

        if st.button("ENTRAR", use_container_width=True):
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

        st.markdown('<div class="login-panel-divider"></div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="login-panel-footer">Ambiente seguro e preparado para empresas.</div>',
            unsafe_allow_html=True,
        )

        st.markdown("</div></div>", unsafe_allow_html=True)

    st.stop()


def aplicar_design_portal():
    st.markdown(
        """
        <style>
        .stApp {
            background:
                radial-gradient(circle at top left, rgba(58, 28, 113, 0.18), transparent 28%),
                radial-gradient(circle at bottom right, rgba(46, 125, 255, 0.10), transparent 24%),
                linear-gradient(135deg, #031427 0%, #06264A 55%, #0B2F57 100%);
            color: #EAF2FF;
        }

        [data-testid="stHeader"] {
            background: transparent;
        }

        .block-container {
            padding-top: 1.2rem;
            padding-bottom: 1.8rem;
            max-width: 1380px;
        }
        section[data-testid="stSidebar"] {
            background: rgba(3, 16, 29, 0.75);
            backdrop-filter: blur(6px);
            border-right: 1px solid rgba(120,145,170,0.10);
        };
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

        .bv-card {
            background: rgba(10, 34, 69, 0.75);
            border: 1px solid rgba(170, 198, 236, 0.18);
            border-radius: 20px;
            padding: 20px 22px;
            box-shadow: 0 16px 40px rgba(0,0,0,0.25);
            backdrop-filter: blur(6px);
            margin-bottom: 16px;
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
        "Documentos SST": "cadastros",
        "Vencimentos SST": "dashboard",
        "Cadastro de Clientes": "clientes",
        "Cadastro de Empresas": "clientes",
        "Cadastro de Operadores": "atendentes",
        "Painel de Cadastros": "cadastros",
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
st.caption("Gestão de Recursos Humanos orientada por dados para empresas modernas.")

menu_options_admin = [
    "Dashboard RH",
    "Quadro de Funcionários",
    "Cadastro de Colaboradores",
    "Cadastro de Filiais",
    "Cadastro de Setores",
    "Cadastro de Cargos",
    "Documentos SST",
    "Vencimentos SST",
]

menu_options_gestor = [
    "Dashboard RH",
    "Quadro de Funcionários",
    "Cadastro de Colaboradores",
    "Cadastro de Filiais",
    "Cadastro de Setores",
    "Cadastro de Cargos",
    "Documentos SST",
    "Vencimentos SST",
]

st.session_state.setdefault("menu_atual", "Dashboard RH")
menu_options_usuario = ["Nova Solicitação", "Demandas Solicitadas"]

perfil_atual = st.session_state.get("perfil")
is_global = perfil_atual in ("superadmin", "operador")

menu_options_cliente = [
    "Dashboard RH",
    "Quadro de Funcionários",
    "Cadastro de Colaboradores",
    "Cadastro de Filiais",
    "Cadastro de Setores",
    "Cadastro de Cargos",
    "Documentos SST",
    "Vencimentos SST",
]

menu_options_global = menu_options_cliente + [
    "Cadastro de Clientes",
    "Cadastro de Empresas",
    "Cadastro de Operadores",
    "Painel de Cadastros",
]

if is_global:
    menu_options = menu_options_global
elif perfil_atual in ("admin", "gestor"):
    menu_options = menu_options_cliente
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

with st.sidebar:
    empresa_id_contexto = None

    if is_global:
        empresas = conn.execute(
            """
            SELECT
                id,
                COALESCE(fantasia, razao_social, 'Empresa sem nome') AS nome
            FROM empresas
            WHERE ativo = TRUE
            ORDER BY COALESCE(fantasia, razao_social, 'Empresa sem nome')
            """
        ).fetchall()

        if empresas:
            empresa_labels = [e["nome"] for e in empresas]

            empresa_nome_padrao = st.session_state.get("empresa_nome_contexto")
            if empresa_nome_padrao not in empresa_labels:
                empresa_nome_padrao = empresa_labels[0]

            empresa_nome_sel = st.selectbox(
                "Empresa",
                empresa_labels,
                index=empresa_labels.index(empresa_nome_padrao),
                key="empresa_global_filtro",
            )

            empresa_selecionada = next(
                e for e in empresas if e["nome"] == empresa_nome_sel
            )
            empresa_id_contexto = empresa_selecionada["id"]
            st.session_state["empresa_nome_contexto"] = empresa_nome_sel
        else:
            st.warning("Nenhuma empresa ativa encontrada.")
    else:
        empresa_id_contexto = st.session_state.get("empresa_id")
        st.session_state["empresa_nome_contexto"] = (
            st.session_state.get("empresa_nome") or ""
        )

    st.session_state["empresa_id_contexto"] = empresa_id_contexto

    render_sidebar_menu(
        menu_options=menu_options,
        current_menu=menu,
        logo_b64=logo_b64,
    )

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

    if is_global and st.session_state.get("empresa_nome_contexto"):
        st.caption(f"Empresa em contexto: {st.session_state['empresa_nome_contexto']}")

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
    st.header("Painel RH")

    empresa_id = get_empresa_contexto()

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

    if df.empty:
        st.info("Nenhum colaborador cadastrado ainda.")
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

        c1, c2, c3, c4, c5, c6 = st.columns(6)
        c1.metric("Total de colaboradores", total_colaboradores)
        c2.metric("Registros ativos", registros_ativos)
        c3.metric("Admissões no período", admissoes_periodo)
        c4.metric("Desligamentos no período", desligamentos_periodo)
        c5.metric("Turnover", f"{turnover:.2f}%")
        c6.metric("Afastados", afastados_total)

        atualizar_status_documentos_sst_empresa(empresa_id)
        docs_sst = conn.execute(
            """
            SELECT
                COUNT(*) FILTER (WHERE status = 'Vencido') AS vencidos,
                COUNT(*) FILTER (WHERE status = 'A vencer') AS a_vencer,
                COUNT(*) FILTER (WHERE status = 'Revisão necessária') AS revisao_necessaria
            FROM documentos_sst
            WHERE empresa_id = %s
            """,
            (empresa_id,),
        ).fetchone()

        d1, d2, d3 = st.columns(3)
        d1.metric("SST vencidos", int((docs_sst or {}).get("vencidos") or 0))
        d2.metric("SST a vencer (30 dias)", int((docs_sst or {}).get("a_vencer") or 0))
        d3.metric(
            "SST em revisão", int((docs_sst or {}).get("revisao_necessaria") or 0)
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
elif menu == "Cadastro de Empresas" and perfil_atual in ("superadmin", "operador"):
    st.header("Cadastro de Empresas")
    st.caption("Gestão global das empresas da plataforma.")

    with st.expander("Nova empresa", expanded=True):
        c1, c2, c3 = st.columns(3)

        with c1:
            razao_social = st.text_input("Razão Social", key="empresa_razao_social")
            fantasia = st.text_input("Nome Fantasia", key="empresa_fantasia")
            cnpj = st.text_input("CNPJ", key="empresa_cnpj")

        with c2:
            cep = st.text_input("CEP", key="empresa_cep")
            logradouro = st.text_input("Logradouro", key="empresa_logradouro")
            numero = st.text_input("Número", key="empresa_numero")

        with c3:
            bairro = st.text_input("Bairro", key="empresa_bairro")
            cidade = st.text_input("Cidade", key="empresa_cidade")
            ativo_empresa = st.checkbox("Ativa", value=True, key="empresa_ativa")

        if st.button("Cadastrar Empresa", key="btn_cadastrar_empresa"):
            if not razao_social.strip() and not fantasia.strip():
                st.error("Informe ao menos a razão social ou o nome fantasia.")
            else:
                conn.execute(
                    """
                    INSERT INTO empresas
                    (cnpj, razao_social, fantasia, cep, logradouro, numero, bairro, cidade, ativo)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        formatar_cnpj(cnpj.strip()),
                        razao_social.strip(),
                        fantasia.strip(),
                        cep.strip(),
                        logradouro.strip(),
                        numero.strip(),
                        bairro.strip(),
                        cidade.strip(),
                        ativo_empresa,
                    ),
                )
                st.success("Empresa cadastrada com sucesso.")
                st.rerun()

    st.markdown("---")
    st.subheader("Empresas cadastradas")

    if "empresa_editando_id" not in st.session_state:
        st.session_state.empresa_editando_id = None

    empresas = conn.execute(
        """
        SELECT id, cnpj, razao_social, fantasia, cidade, ativo
        FROM empresas
        ORDER BY COALESCE(fantasia, razao_social, 'Empresa sem nome')
        """
    ).fetchall()

    if empresas:
        empresas, _, _ = paginar_registros(
            empresas,
            "pagina_empresas_cadastro",
            page_size=10,
        )

        for empresa in empresas:
            empresa_id_item = empresa["id"]

            with st.container(border=True):
                c1, c2, c3 = st.columns([3.2, 1.2, 3])

                with c1:
                    st.write(
                        f"**ID {empresa['id']} - {empresa['fantasia'] or empresa['razao_social'] or 'Empresa sem nome'}**"
                    )
                    st.caption(empresa["razao_social"] or "Sem razão social")
                    st.caption(empresa["cnpj"] or "Sem CNPJ")

                with c2:
                    st.write("Ativa" if bool(empresa["ativo"]) else "Inativa")
                    st.caption(empresa["cidade"] or "Sem cidade")

                with c3:
                    b1, b2, b3 = st.columns(3)

                    with b1:
                        if bool(empresa["ativo"]):
                            if st.button(
                                "Inativar",
                                key=f"inativar_empresa_{empresa_id_item}",
                                use_container_width=True,
                            ):
                                conn.execute(
                                    "UPDATE empresas SET ativo = FALSE WHERE id = %s",
                                    (empresa_id_item,),
                                )
                                st.rerun()
                        else:
                            if st.button(
                                "Ativar",
                                key=f"ativar_empresa_{empresa_id_item}",
                                use_container_width=True,
                            ):
                                conn.execute(
                                    "UPDATE empresas SET ativo = TRUE WHERE id = %s",
                                    (empresa_id_item,),
                                )
                                st.rerun()

                    with b2:
                        if st.button(
                            "Excluir",
                            key=f"excluir_empresa_{empresa_id_item}",
                            use_container_width=True,
                        ):
                            possui_usuarios = conn.execute(
                                "SELECT 1 FROM usuarios WHERE empresa_id = %s LIMIT 1",
                                (empresa_id_item,),
                            ).fetchone()

                            if possui_usuarios:
                                st.warning(
                                    "Esta empresa possui usuários vinculados. Inative ao invés de excluir."
                                )
                            else:
                                conn.execute(
                                    "DELETE FROM empresas WHERE id = %s",
                                    (empresa_id_item,),
                                )
                                st.success("Empresa excluída.")
                                st.rerun()

                    with b3:
                        if st.button(
                            "Alterar",
                            key=f"alterar_empresa_{empresa_id_item}",
                            use_container_width=True,
                        ):
                            st.session_state.empresa_editando_id = empresa_id_item
                            st.rerun()

                if st.session_state.empresa_editando_id == empresa_id_item:
                    empresa_full = conn.execute(
                        """
                        SELECT id, cnpj, razao_social, fantasia, cep, logradouro, numero, bairro, cidade
                        FROM empresas
                        WHERE id = %s
                        """,
                        (empresa_id_item,),
                    ).fetchone()

                    e1, e2, e3 = st.columns(3)

                    with e1:
                        novo_cnpj = st.text_input(
                            "CNPJ",
                            value=empresa_full["cnpj"] or "",
                            key=f"edit_empresa_cnpj_{empresa_id_item}",
                        )
                        nova_razao = st.text_input(
                            "Razão Social",
                            value=empresa_full["razao_social"] or "",
                            key=f"edit_empresa_razao_{empresa_id_item}",
                        )
                        nova_fantasia = st.text_input(
                            "Nome Fantasia",
                            value=empresa_full["fantasia"] or "",
                            key=f"edit_empresa_fantasia_{empresa_id_item}",
                        )

                    with e2:
                        novo_cep = st.text_input(
                            "CEP",
                            value=empresa_full["cep"] or "",
                            key=f"edit_empresa_cep_{empresa_id_item}",
                        )
                        novo_logradouro = st.text_input(
                            "Logradouro",
                            value=empresa_full["logradouro"] or "",
                            key=f"edit_empresa_logradouro_{empresa_id_item}",
                        )
                        novo_numero = st.text_input(
                            "Número",
                            value=empresa_full["numero"] or "",
                            key=f"edit_empresa_numero_{empresa_id_item}",
                        )

                    with e3:
                        novo_bairro = st.text_input(
                            "Bairro",
                            value=empresa_full["bairro"] or "",
                            key=f"edit_empresa_bairro_{empresa_id_item}",
                        )
                        nova_cidade = st.text_input(
                            "Cidade",
                            value=empresa_full["cidade"] or "",
                            key=f"edit_empresa_cidade_{empresa_id_item}",
                        )

                    a1, a2 = st.columns(2)

                    with a1:
                        if st.button(
                            "Salvar alteração",
                            key=f"salvar_empresa_{empresa_id_item}",
                            use_container_width=True,
                        ):
                            conn.execute(
                                """
                                UPDATE empresas
                                SET cnpj = %s,
                                    razao_social = %s,
                                    fantasia = %s,
                                    cep = %s,
                                    logradouro = %s,
                                    numero = %s,
                                    bairro = %s,
                                    cidade = %s
                                WHERE id = %s
                                """,
                                (
                                    formatar_cnpj(novo_cnpj.strip()),
                                    nova_razao.strip(),
                                    nova_fantasia.strip(),
                                    novo_cep.strip(),
                                    novo_logradouro.strip(),
                                    novo_numero.strip(),
                                    novo_bairro.strip(),
                                    nova_cidade.strip(),
                                    empresa_id_item,
                                ),
                            )
                            st.session_state.empresa_editando_id = None
                            st.success("Empresa atualizada com sucesso.")
                            st.rerun()

                    with a2:
                        if st.button(
                            "Cancelar alteração",
                            key=f"cancelar_empresa_{empresa_id_item}",
                            use_container_width=True,
                        ):
                            st.session_state.empresa_editando_id = None
                            st.rerun()
    else:
        st.info("Nenhuma empresa cadastrada ainda.")


elif menu == "Cadastro de Filiais" and perfil_atual in ("admin", "gestor"):
    exigir_perfil("admin", "gestor")
    st.header("Cadastro de Filiais")
    empresa_id = get_empresa_contexto()

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
    empresa_id = get_empresa_contexto()

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
    empresa_id = get_empresa_contexto()

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
    empresa_id = get_empresa_contexto()

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

elif menu == "Cadastro de Clientes" and perfil_atual in ("superadmin", "operador"):
    st.header("Cadastro de Clientes")
    st.caption("Gestão global dos clientes vinculados às empresas.")

    empresas = conn.execute(
        """
        SELECT id, COALESCE(fantasia, razao_social, 'Empresa sem nome') AS nome
        FROM empresas
        WHERE ativo = TRUE
        ORDER BY COALESCE(fantasia, razao_social, 'Empresa sem nome')
        """
    ).fetchall()

    empresa_id_filtro = None
    if empresas:
        empresa_labels = ["Todas"] + [e["nome"] for e in empresas]
        empresa_nome_filtro = st.selectbox(
            "Filtrar por empresa",
            empresa_labels,
            key="clientes_empresa_filtro",
        )

        if empresa_nome_filtro != "Todas":
            empresa_id_filtro = next(
                e["id"] for e in empresas if e["nome"] == empresa_nome_filtro
            )

    with st.expander("Novo cliente", expanded=True):
        c1, c2, c3 = st.columns(3)

        empresa_id_cliente = None
        with c1:
            nome_cliente = st.text_input("Nome", key="cliente_nome")
            usuario_cliente = st.text_input("Usuário", key="cliente_usuario")
            email_cliente = st.text_input("E-mail", key="cliente_email")

        with c2:
            cpf_cliente = st.text_input("CPF", key="cliente_cpf")
            funcao_cliente = st.text_input("Função", key="cliente_funcao")
            senha_cliente = st.text_input("Senha", type="password", key="cliente_senha")

        with c3:
            ativo_cliente = st.checkbox("Ativo", value=True, key="cliente_ativo")

            if empresas:
                empresa_nome_cliente = st.selectbox(
                    "Empresa",
                    [e["nome"] for e in empresas],
                    key="cliente_empresa",
                )
                empresa_id_cliente = next(
                    e["id"] for e in empresas if e["nome"] == empresa_nome_cliente
                )
            else:
                st.warning("Cadastre ao menos uma empresa ativa.")

        if st.button("Cadastrar Cliente", key="btn_cadastrar_cliente"):
            if not nome_cliente.strip() or not usuario_cliente.strip():
                st.error("Preencha nome e usuário.")
            elif not empresa_id_cliente:
                st.error("Selecione a empresa.")
            else:
                existe = conn.execute(
                    "SELECT 1 FROM clientes WHERE usuario = %s LIMIT 1",
                    (usuario_cliente.strip(),),
                ).fetchone()

                if existe:
                    st.error("Já existe um cliente com esse usuário.")
                else:
                    conn.execute(
                        """
                        INSERT INTO clientes
                        (usuario, senha, nome, ativo, cpf, empresa_id, funcao, email)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            usuario_cliente.strip(),
                            (
                                gerar_hash_senha(senha_cliente.strip())
                                if senha_cliente.strip()
                                else ""
                            ),
                            nome_cliente.strip(),
                            ativo_cliente,
                            formatar_cpf(cpf_cliente.strip()),
                            empresa_id_cliente,
                            funcao_cliente.strip(),
                            email_cliente.strip().lower(),
                        ),
                    )
                    st.success("Cliente cadastrado com sucesso.")
                    st.rerun()

    st.markdown("---")
    st.subheader("Clientes cadastrados")

    filtros = []
    params = []

    if empresa_id_filtro:
        filtros.append("c.empresa_id = %s")
        params.append(empresa_id_filtro)

    where_clause = " AND ".join(filtros) if filtros else "TRUE"

    clientes = conn.execute(
        f"""
        SELECT
            c.id,
            c.nome,
            c.usuario,
            c.email,
            c.funcao,
            c.ativo,
            e.fantasia AS empresa_nome
        FROM clientes c
        LEFT JOIN empresas e ON e.id = c.empresa_id
        WHERE {where_clause}
        ORDER BY c.nome, c.usuario
        """,
        params,
    ).fetchall()

    if clientes:
        clientes, _, _ = paginar_registros(
            clientes,
            "pagina_clientes_cadastro_global",
            page_size=10,
        )

        for cliente in clientes:
            with st.container(border=True):
                c1, c2, c3 = st.columns([2.4, 2.2, 2.8])

                with c1:
                    st.write(f"**{cliente['nome'] or cliente['usuario']}**")
                    st.caption(cliente["usuario"])

                with c2:
                    st.write(cliente["empresa_nome"] or "Sem empresa")
                    st.caption(cliente["funcao"] or "Sem função")

                with c3:
                    st.write(cliente["email"] or "Sem e-mail")
                    st.caption("Ativo" if bool(cliente["ativo"]) else "Inativo")
    else:
        st.info("Nenhum cliente cadastrado ainda.")

elif menu == "Painel de Cadastros" and perfil_atual in ("superadmin", "operador"):
    st.header("Painel de Cadastros")
    st.caption("Convites e pré-cadastros globais da plataforma.")

    tab1, tab2, tab3 = st.tabs(["Novo convite", "Pendentes / enviados", "Concluídos"])

    with tab1:
        empresas = conn.execute(
            """
            SELECT id, COALESCE(fantasia, razao_social, 'Empresa sem nome') AS nome
            FROM empresas
            WHERE ativo = TRUE
            ORDER BY COALESCE(fantasia, razao_social, 'Empresa sem nome')
            """
        ).fetchall()

        nome_convite = st.text_input("Nome", key="convite_nome_global")
        email_convite = st.text_input("E-mail", key="convite_email_global")
        tipo_convite = st.selectbox(
            "Perfil do usuário",
            ["admin", "gestor", "usuario"],
            key="convite_tipo_global",
        )
        obs_convite = st.text_area("Observação", key="convite_obs_global")

        empresa_id_convite = None
        if empresas:
            empresa_nome = st.selectbox(
                "Empresa",
                [row["nome"] for row in empresas],
                key="convite_empresa_global",
            )
            empresa_id_convite = next(
                row["id"] for row in empresas if row["nome"] == empresa_nome
            )
        else:
            st.warning("Cadastre ao menos uma empresa ativa.")

        if st.button("Gerar convite e link", key="criar_convite_btn_global"):
            if not nome_convite.strip() or not email_convite.strip():
                st.error("Preencha nome e e-mail.")
            elif not empresa_id_convite:
                st.error("Selecione a empresa.")
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
                st.session_state["ultimo_link_convite_global"] = link

        ultimo_link = st.session_state.get("ultimo_link_convite_global")
        if ultimo_link:
            st.caption("Último link gerado")
            st.code(ultimo_link, language="text")

    with tab2:
        convites = conn.execute(
            """
            SELECT
                c.*,
                e.fantasia AS empresa_nome
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
                                key=f"reenviar_convite_global_{convite['id']}",
                                use_container_width=True,
                            ):
                                resultado_reenvio = reenviar_convite(convite["id"])
                                st.session_state[
                                    f"link_convite_global_{convite['id']}"
                                ] = resultado_reenvio["link"]
                                if resultado_reenvio["email_enviado"]:
                                    st.success(
                                        "Convite reenviado por e-mail com novo link."
                                    )
                                else:
                                    st.warning(
                                        f"Convite renovado, mas o e-mail não foi enviado. Motivo: {resultado_reenvio['email_msg']}"
                                    )
                                st.rerun()

                        with a2:
                            if st.button(
                                "Cancelar",
                                key=f"cancelar_convite_global_{convite['id']}",
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
                                    f"link_convite_global_{convite['id']}",
                                    link,
                                ),
                                language="text",
                            )

    with tab3:
        concluidos = conn.execute(
            """
            SELECT
                c.*,
                e.fantasia AS empresa_nome
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
                        f"Perfil: {convite['tipo_usuario'].capitalize()} • "
                        f"Empresa: {convite.get('empresa_nome') or 'Sem empresa'} • "
                        f"Concluído em: {convite['utilizado_em'].strftime('%d/%m/%Y %H:%M') if convite['utilizado_em'] else '-'}"
                    )


elif menu == "Quadro de Funcionários" and perfil_atual in ("admin", "gestor"):
    exigir_perfil("admin", "gestor")
    st.header("Quadro de Funcionários")
    empresa_id = get_empresa_contexto()

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


elif menu == "Documentos SST" and perfil_atual in ("admin", "gestor"):
    exigir_perfil("admin", "gestor")
    st.header("Documentos SST")
    empresa_id = get_empresa_contexto()
    # atualizar_status_documentos_sst_empresa(empresa_id)

    t0 = time.perf_counter()
    tipos_documento = listar_tipos_documento_sst()
    t1 = time.perf_counter()

    mapa_tipos = {row["nome"]: row for row in tipos_documento}

    filiais = listar_filiais_ativas(empresa_id)
    t2 = time.perf_counter()

    colaboradores = listar_colaboradores_ativos(empresa_id)
    t3 = time.perf_counter()

    st.caption(
        f"Tipos: {t1-t0:.3f}s | Filiais: {t2-t1:.3f}s | Colaboradores: {t3-t2:.3f}s"
    )

    with st.expander("Novo documento", expanded=True):
        c1, c2, c3 = st.columns(3)

        with c1:
            tipo_nome = st.selectbox(
                "Tipo de documento",
                list(mapa_tipos.keys()) if mapa_tipos else [],
                key="sst_tipo_documento",
            )
            titulo_documento = st.text_input("Título", key="sst_titulo")
            data_emissao = st.date_input(
                "Data de emissão",
                key="sst_data_emissao",
                value=datetime.now().date(),
            )

        tipo_selecionado = mapa_tipos.get(tipo_nome) if mapa_tipos else None
        periodicidade = (
            tipo_selecionado["periodicidade_meses"] if tipo_selecionado else None
        )
        escopo_tipo = tipo_selecionado["escopo"] if tipo_selecionado else "empresa"
        data_vencimento_calculada = calcular_data_vencimento_documento(
            data_emissao,
            periodicidade,
        )
        colaborador_id_sel = None

        with c2:
            filial_labels = ["Empresa / Geral"] + [row["nome"] for row in filiais]
            filial_nome_sel = st.selectbox(
                "Filial",
                filial_labels,
                key="sst_filial",
            )
            filial_id_sel = None
            if filial_nome_sel != "Empresa / Geral":
                filial_id_sel = next(
                    row["id"] for row in filiais if row["nome"] == filial_nome_sel
                )

            colaborador_id_sel = None
            if escopo_tipo == "colaborador":
                colab_labels = [
                    f"{row['nome']} ({row['matricula'] or 'Sem matrícula'})"
                    for row in colaboradores
                ]
                if colab_labels:
                    colab_sel = st.selectbox(
                        "Colaborador",
                        colab_labels,
                        key="sst_colaborador",
                    )
                    colaborador_id_sel = colaboradores[colab_labels.index(colab_sel)][
                        "id"
                    ]
                else:
                    st.warning(
                        "Cadastre colaboradores para usar documentos com escopo de colaborador."
                    )
            else:
                st.text_input(
                    "Colaborador",
                    value="Não aplicável para este tipo",
                    disabled=True,
                    key="sst_colaborador_info",
                )

        with c3:
            st.text_input(
                "Periodicidade",
                value=(
                    f"{periodicidade} meses"
                    if periodicidade
                    else "Sem vencimento automático"
                ),
                disabled=True,
                key="sst_periodicidade_info",
            )
            st.text_input(
                "Vencimento calculado",
                value=(
                    data_vencimento_calculada.strftime("%d/%m/%Y")
                    if data_vencimento_calculada
                    else "Não calculado"
                ),
                disabled=True,
                key="sst_vencimento_calculado",
            )
            revisao_manual = st.checkbox(
                "Marcar revisão necessária",
                value=False,
                key="sst_revisao_manual",
            )

        observacao = st.text_area("Observação", key="sst_observacao")
        arquivo_sst = st.file_uploader(
            "Anexar documento",
            type=["pdf", "png", "jpg", "jpeg"],
            key="sst_arquivo",
        )

        if st.button("Cadastrar documento SST", key="btn_cadastrar_documento_sst"):
            if not tipo_selecionado:
                st.error("Selecione o tipo de documento.")
            elif not titulo_documento.strip():
                st.error("Informe o título do documento.")
            elif escopo_tipo == "colaborador" and not colaborador_id_sel:
                st.error("Selecione o colaborador para este documento.")
            else:
                arquivo_nome = None
                arquivo_bytes = None

                if arquivo_sst is not None:
                    ok, msg = validar_upload_documento_sst(arquivo_sst)
                    if not ok:
                        st.error(msg)
                        st.stop()
                    arquivo_nome = arquivo_sst.name
                    arquivo_bytes = arquivo_sst.getvalue()

                status_documento = classificar_status_vencimento(
                    data_vencimento_calculada,
                    revisao_manual,
                )

                conn.execute(
                    """
                    INSERT INTO documentos_sst
                    (
                        empresa_id,
                        filial_id,
                        colaborador_id,
                        tipo_documento_id,
                        titulo,
                        data_emissao,
                        data_vencimento,
                        status,
                        observacao,
                        arquivo_nome,
                        arquivo,
                        revisao_necessaria,
                        criado_por,
                        created_at,
                        updated_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        empresa_id,
                        filial_id_sel,
                        colaborador_id_sel,
                        tipo_selecionado["id"],
                        titulo_documento.strip(),
                        data_emissao,
                        data_vencimento_calculada,
                        status_documento,
                        observacao.strip(),
                        arquivo_nome,
                        arquivo_bytes,
                        revisao_manual,
                        get_user_id(),
                        agora(),
                        agora(),
                    ),
                )
                # ✅ LIMPA CACHE AQUI
                listar_documentos_sst_resumo.clear()
                listar_tipos_documento_sst.clear()
                listar_filiais_ativas.clear()
                listar_colaboradores_ativos.clear()

                st.success("Documento SST cadastrado com sucesso.")
                st.rerun()

    st.markdown("---")
    st.subheader("Eventos que exigem revisão")
    with st.expander("Registrar evento de revisão", expanded=False):
        ev1, ev2, ev3 = st.columns(3)
        with ev1:
            tipo_evento = st.selectbox(
                "Tipo de evento",
                ["mudança_layout", "nova_atividade", "mudança_processo"],
                key="sst_tipo_evento",
            )
        with ev2:
            filial_evento_labels = ["Empresa / Geral"] + [
                row["nome"] for row in filiais
            ]
            filial_evento_nome = st.selectbox(
                "Filial do evento",
                filial_evento_labels,
                key="sst_evento_filial",
            )
        with ev3:
            data_evento = st.date_input(
                "Data do evento",
                key="sst_evento_data",
                value=datetime.now().date(),
            )

        descricao_evento = st.text_area(
            "Descrição do evento", key="sst_evento_descricao"
        )

        if st.button("Registrar evento", key="btn_registrar_evento_sst"):
            filial_evento_id = None
            if filial_evento_nome != "Empresa / Geral":
                filial_evento_id = next(
                    row["id"] for row in filiais if row["nome"] == filial_evento_nome
                )

            if not descricao_evento.strip():
                st.error("Descreva o evento.")
            else:
                registrar_evento_revisao_sst(
                    empresa_id=empresa_id,
                    filial_id=filial_evento_id,
                    tipo_evento=tipo_evento,
                    descricao=descricao_evento,
                    data_evento=data_evento,
                )

                conn.execute(
                    """
                    UPDATE documentos_sst d
                    SET revisao_necessaria = TRUE,
                        status = 'Revisão necessária',
                        updated_at = %s
                    FROM tipos_documento_sst t
                    WHERE d.tipo_documento_id = t.id
                      AND d.empresa_id = %s
                      AND t.exige_revisao_por_evento = TRUE
                      AND (%s IS NULL OR d.filial_id = %s OR d.filial_id IS NULL)
                    """,
                    (agora(), empresa_id, filial_evento_id, filial_evento_id),
                )

                st.success(
                    "Evento registrado e documentos elegíveis marcados para revisão."
                )
                st.rerun()

    st.markdown("---")
    st.subheader("Documentos cadastrados")

    filtro1, filtro2, filtro3 = st.columns(3)
    with filtro1:
        filtro_status_sst = st.selectbox(
            "Status",
            [
                "Todos",
                "Vigente",
                "A vencer",
                "Vencido",
                "Revisão necessária",
                "Sem vencimento",
            ],
            key="filtro_status_sst",
        )
    with filtro2:
        filtro_tipo_sst = st.selectbox(
            "Tipo",
            ["Todos"] + list(mapa_tipos.keys()),
            key="filtro_tipo_sst",
        )
    with filtro3:
        filtro_filial_sst = st.selectbox(
            "Filial",
            ["Todas"] + [row["nome"] for row in filiais],
            key="filtro_filial_sst",
        )

    documentos = conn.execute(
        """
    SELECT
        d.id,
        td.nome AS tipo_documento,
        td.escopo,
        d.titulo,
        d.data_emissao,
        d.data_vencimento,
        d.revisao_necessaria,
        c.nome AS colaborador_nome,
        c.matricula,
        f.nome AS filial_nome,
        CASE
            WHEN d.revisao_necessaria = TRUE THEN 'Revisão necessária'
            WHEN d.data_vencimento IS NULL THEN 'Vigente'
            WHEN d.data_vencimento < CURRENT_DATE THEN 'Vencido'
            WHEN d.data_vencimento <= CURRENT_DATE + INTERVAL '30 days' THEN 'A vencer'
            ELSE 'Vigente'
        END AS status_calculado
    FROM documentos_sst d
    JOIN tipos_documento_sst td ON td.id = d.tipo_documento_id
    LEFT JOIN colaboradores c ON c.id = d.colaborador_id
    LEFT JOIN filiais f ON f.id = d.filial_id
    WHERE d.empresa_id = %s
    ORDER BY d.data_vencimento NULLS LAST, d.id DESC
    """,
        (empresa_id,),
    ).fetchall()

    docs_filtrados = []
    for doc in documentos:
        if filtro_status_sst != "Todos" and doc["status"] != filtro_status_sst:
            continue
        if filtro_tipo_sst != "Todos" and doc["tipo_documento"] != filtro_tipo_sst:
            continue
        filial_nome_doc = doc.get("filial_nome") or "Empresa / Geral"
        if filtro_filial_sst != "Todas" and filial_nome_doc != filtro_filial_sst:
            continue
        docs_filtrados.append(doc)

    if docs_filtrados:
        docs_filtrados, _, _ = paginar_registros(
            docs_filtrados,
            "pagina_documentos_sst",
            page_size=10,
        )
        for doc in docs_filtrados:
            doc_id = doc["id"]
            with st.container(border=True):
                c1, c2, c3, c4 = st.columns([2.4, 1.2, 1.2, 1.5])
                with c1:
                    st.write(f"**{doc['titulo']}**")
                    st.caption(doc["tipo_documento"])
                    st.caption(
                        f"Filial: {doc.get('filial_nome') or 'Empresa / Geral'}"
                        + (
                            f" • Colaborador: {doc.get('colaborador_nome')}"
                            if doc.get("colaborador_nome")
                            else ""
                        )
                    )
                with c2:
                    st.write(
                        f"Emissão: {doc['data_emissao'].strftime('%d/%m/%Y') if doc.get('data_emissao') else '-'}"
                    )
                    st.caption(
                        f"Vencimento: {doc['data_vencimento'].strftime('%d/%m/%Y') if doc.get('data_vencimento') else '-'}"
                    )
                with c3:
                    st.write(f"Status: **{doc['status']}**")
                    st.caption(
                        "Revisão pendente"
                        if doc.get("revisao_necessaria")
                        else "Sem revisão pendente"
                    )
                with c4:
                    a1, a2 = st.columns(2)
                    with a1:
                        if st.button(
                            "Baixar",
                            key=f"baixar_sst_{doc_id}",
                            use_container_width=True,
                        ):
                            pass
                    with a2:
                        if st.button(
                            "Excluir",
                            key=f"excluir_sst_{doc_id}",
                            use_container_width=True,
                        ):
                            conn.execute(
                                "DELETE FROM documentos_sst WHERE id = %s AND empresa_id = %s",
                                (doc_id, empresa_id),
                            )
                            st.success("Documento excluído.")
                            st.rerun()

                if doc.get("observacao"):
                    st.caption(doc["observacao"])

                render_documento_sst_arquivo(doc_id, prefixo="sst_download")
    else:
        st.info("Nenhum documento SST encontrado com os filtros aplicados.")

elif menu == "Vencimentos SST" and perfil_atual in ("admin", "gestor"):
    exigir_perfil("admin", "gestor")
    st.header("Vencimentos SST")
    empresa_id = get_empresa_contexto()
    atualizar_status_documentos_sst_empresa(empresa_id)

    resumo = conn.execute(
        """
        SELECT
            COUNT(*) FILTER (WHERE status = 'Vencido') AS vencidos,
            COUNT(*) FILTER (WHERE status = 'A vencer') AS a_vencer,
            COUNT(*) FILTER (WHERE status = 'Revisão necessária') AS revisao,
            COUNT(*) FILTER (WHERE status = 'Vigente') AS vigentes
        FROM documentos_sst
        WHERE empresa_id = %s
        """,
        (empresa_id,),
    ).fetchone()

    r1, r2, r3, r4 = st.columns(4)
    r1.metric("Vencidos", int((resumo or {}).get("vencidos") or 0))
    r2.metric("A vencer em 30 dias", int((resumo or {}).get("a_vencer") or 0))
    r3.metric("Em revisão", int((resumo or {}).get("revisao") or 0))
    r4.metric("Vigentes", int((resumo or {}).get("vigentes") or 0))

    tabela = conn.execute(
        """
        SELECT
            d.id,
            t.nome AS tipo_documento,
            d.titulo,
            f.nome AS filial_nome,
            c.nome AS colaborador_nome,
            d.data_emissao,
            d.data_vencimento,
            d.status
        FROM documentos_sst d
        JOIN tipos_documento_sst t ON t.id = d.tipo_documento_id
        LEFT JOIN filiais f ON f.id = d.filial_id
        LEFT JOIN colaboradores c ON c.id = d.colaborador_id
        WHERE d.empresa_id = %s
        ORDER BY
            CASE d.status
                WHEN 'Vencido' THEN 1
                WHEN 'A vencer' THEN 2
                WHEN 'Revisão necessária' THEN 3
                WHEN 'Vigente' THEN 4
                ELSE 5
            END,
            d.data_vencimento NULLS LAST,
            d.id DESC
        """,
        (empresa_id,),
    ).fetchall()

    if tabela:
        df_sst = pd.DataFrame(tabela)
        for coluna in ["data_emissao", "data_vencimento"]:
            if coluna in df_sst.columns:
                df_sst[coluna] = pd.to_datetime(
                    df_sst[coluna], errors="coerce"
                ).dt.strftime("%d/%m/%Y")
                df_sst[coluna] = df_sst[coluna].fillna("-")
        df_sst = df_sst.rename(
            columns={
                "tipo_documento": "Tipo",
                "titulo": "Título",
                "filial_nome": "Filial",
                "colaborador_nome": "Colaborador",
                "data_emissao": "Emissão",
                "data_vencimento": "Vencimento",
                "status": "Status",
            }
        )
        df_sst["Filial"] = df_sst["Filial"].fillna("Empresa / Geral")
        df_sst["Colaborador"] = df_sst["Colaborador"].fillna("-")
        st.dataframe(
            df_sst[
                [
                    "Tipo",
                    "Título",
                    "Filial",
                    "Colaborador",
                    "Emissão",
                    "Vencimento",
                    "Status",
                ]
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("Nenhum documento SST cadastrado ainda.")

elif menu == "Cadastro de Operadores" and perfil_atual in ("superadmin", "operador"):
    st.header("Cadastro de Operadores")
    st.caption("Gestão de usuários internos da plataforma.")

    with st.expander("Novo operador", expanded=True):
        nome_operador = st.text_input("Nome do operador", key="novo_operador_nome")
        usuario_operador = st.text_input(
            "Usuário do operador",
            value=gerar_usuario(nome_operador) if nome_operador.strip() else "",
            key="novo_operador_usuario",
        )
        email_operador = st.text_input("E-mail", key="novo_operador_email")
        senha_operador = st.text_input(
            "Senha", type="password", key="novo_operador_senha"
        )
        ativo_operador = st.checkbox("Ativo", value=True, key="novo_operador_ativo")

        if st.button("Cadastrar Operador", key="btn_cadastrar_operador"):
            if (
                not nome_operador.strip()
                or not usuario_operador.strip()
                or not senha_operador.strip()
            ):
                st.error("Preencha nome, usuário e senha.")
            else:
                existe = conn.execute(
                    "SELECT 1 FROM atendentes WHERE usuario = %s",
                    (usuario_operador.strip(),),
                ).fetchone()

                if existe:
                    st.error("Já existe um operador com esse usuário.")
                else:
                    conn.execute(
                        """
                        INSERT INTO atendentes (nome, usuario, senha, email, ativo)
                        VALUES (%s, %s, %s, %s, %s)
                        """,
                        (
                            nome_operador.strip(),
                            usuario_operador.strip(),
                            gerar_hash_senha(senha_operador.strip()),
                            email_operador.strip().lower(),
                            ativo_operador,
                        ),
                    )
                    st.success("Operador cadastrado com sucesso.")
                    st.rerun()

    st.markdown("---")
    st.subheader("Operadores cadastrados")

    if "operador_editando_id" not in st.session_state:
        st.session_state.operador_editando_id = None

    operadores = obter_todos_atendentes()

    if operadores:
        operadores, _, _ = paginar_registros(
            operadores, "pagina_operadores_cadastro", page_size=10
        )

        for operador in operadores:
            operador_id = operador["id"]

            with st.container(border=True):
                col1, col2, col3 = st.columns([2.2, 2.4, 3.4])

                with col1:
                    st.write(f"**{operador['usuario']}**")
                    st.caption(operador["nome"] or "")

                with col2:
                    st.write(operador["email"] or "Sem e-mail")
                    st.write("Ativo" if bool(operador["ativo"]) else "Inativo")

                with col3:
                    b1, b2, b3 = st.columns(3)

                    with b1:
                        if bool(operador["ativo"]):
                            if st.button(
                                "Inativar",
                                key=f"inativar_operador_{operador_id}",
                                use_container_width=True,
                            ):
                                conn.execute(
                                    "UPDATE atendentes SET ativo = FALSE WHERE id = %s",
                                    (operador_id,),
                                )
                                st.rerun()
                        else:
                            if st.button(
                                "Ativar",
                                key=f"ativar_operador_{operador_id}",
                                use_container_width=True,
                            ):
                                conn.execute(
                                    "UPDATE atendentes SET ativo = TRUE WHERE id = %s",
                                    (operador_id,),
                                )
                                st.rerun()

                    with b2:
                        if st.button(
                            "Excluir",
                            key=f"excluir_operador_{operador_id}",
                            use_container_width=True,
                        ):
                            possui_vinculo = conn.execute(
                                "SELECT 1 FROM solicitacoes WHERE atendente_id = %s LIMIT 1",
                                (operador_id,),
                            ).fetchone()

                            if possui_vinculo:
                                st.warning(
                                    "Este operador já está vinculado a registros. Inative ao invés de excluir."
                                )
                            else:
                                conn.execute(
                                    "DELETE FROM atendentes WHERE id = %s",
                                    (operador_id,),
                                )
                                st.success("Operador excluído.")
                                st.rerun()

                    with b3:
                        if st.button(
                            "Alterar",
                            key=f"alterar_operador_{operador_id}",
                            use_container_width=True,
                        ):
                            st.session_state.operador_editando_id = operador_id
                            st.rerun()

                if st.session_state.operador_editando_id == operador_id:
                    ed1, ed2 = st.columns(2)

                    with ed1:
                        novo_nome_op = st.text_input(
                            "Nome",
                            value=operador["nome"] or "",
                            key=f"edit_op_nome_{operador_id}",
                        )
                        novo_usuario_op = st.text_input(
                            "Usuário",
                            value=operador["usuario"] or "",
                            key=f"edit_op_usuario_{operador_id}",
                        )

                    with ed2:
                        novo_email_op = st.text_input(
                            "E-mail",
                            value=operador["email"] or "",
                            key=f"edit_op_email_{operador_id}",
                        )
                        nova_senha_op = st.text_input(
                            "Nova senha (opcional)",
                            type="password",
                            key=f"edit_op_senha_{operador_id}",
                        )

                    a1, a2 = st.columns(2)

                    with a1:
                        if st.button(
                            "Salvar alteração",
                            key=f"salvar_operador_{operador_id}",
                            use_container_width=True,
                        ):
                            if not novo_nome_op.strip() or not novo_usuario_op.strip():
                                st.error("Preencha nome e usuário.")
                            else:
                                usuario_existente = conn.execute(
                                    "SELECT 1 FROM atendentes WHERE usuario = %s AND id <> %s",
                                    (novo_usuario_op.strip(), operador_id),
                                ).fetchone()

                                if usuario_existente:
                                    st.error(
                                        "Já existe outro operador com esse usuário."
                                    )
                                else:
                                    if nova_senha_op.strip():
                                        conn.execute(
                                            """
                                            UPDATE atendentes
                                            SET nome = %s, usuario = %s, email = %s, senha = %s
                                            WHERE id = %s
                                            """,
                                            (
                                                novo_nome_op.strip(),
                                                novo_usuario_op.strip(),
                                                novo_email_op.strip().lower(),
                                                gerar_hash_senha(nova_senha_op.strip()),
                                                operador_id,
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
                                                novo_nome_op.strip(),
                                                novo_usuario_op.strip(),
                                                novo_email_op.strip().lower(),
                                                operador_id,
                                            ),
                                        )

                                    st.session_state.operador_editando_id = None
                                    st.success("Operador atualizado com sucesso.")
                                    st.rerun()

                    with a2:
                        if st.button(
                            "Cancelar alteração",
                            key=f"cancelar_operador_{operador_id}",
                            use_container_width=True,
                        ):
                            st.session_state.operador_editando_id = None
                            st.rerun()
    else:
        st.info("Nenhum operador cadastrado ainda.")


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
