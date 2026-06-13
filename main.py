import io
import logging
import os
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fastapi import FastAPI, File, Header, UploadFile
from fastapi.responses import JSONResponse
from pyhanko.keys.pemder import load_certs_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko_certvalidator import ValidationContext


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("unilab_validacao_assinatura")

APP_VERSION = "1.3.2"

app = FastAPI(
    title="UNILAB - Validação de Assinatura Digital",
    version=APP_VERSION,
    description="API para validação de assinaturas digitais em arquivos PDF.",
)

API_TOKEN = os.getenv("API_TOKEN", "").strip()
MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "20"))
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

# Os certificados ICP-Brasil podem estar na raiz do repositório ou em certs/.
# Ao varrer a raiz, a busca é limitada aos arquivos diretamente na raiz para
# evitar carregar certificados de dependências instaladas no Render, como .venv/certifi.
CERTS_DIR = Path(os.getenv("CERTS_DIR", ".")).resolve()
PROJECT_ROOT = Path(".").resolve()
CERTS_SUBDIR = (PROJECT_ROOT / "certs").resolve()

REVOCATION_MODE = os.getenv("REVOCATION_MODE", "soft-fail").strip() or "soft-fail"
CERT_EXTENSIONS = (".crt", ".cer", ".pem", ".der")
EXCLUDED_CERT_DIR_NAMES = {
    ".git",
    ".github",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "env",
    "node_modules",
    "site-packages",
    "venv",
}


def bool_env_(nome: str, padrao: bool = False) -> bool:
    valor = os.getenv(nome)
    if valor is None:
        return padrao
    return valor.strip().lower() in {"1", "true", "yes", "sim", "on"}


ALLOW_FETCHING_CERTS = bool_env_("ALLOW_FETCHING_CERTS", False)


def resposta_erro(
    error_type: str,
    message: str,
    status_code: int = 400,
    details: Optional[str] = None,
):
    payload = {
        "success": False,
        "error": message,
        "error_type": error_type,
        "total_signatures": 0,
        "signatures": [],
    }
    if details:
        payload["details"] = details
    return JSONResponse(status_code=status_code, content=payload)


def validar_token_(authorization: Optional[str]):
    if not API_TOKEN:
        return None

    esperado = f"Bearer {API_TOKEN}"
    if authorization != esperado:
        return resposta_erro(
            "unauthorized",
            "Token de acesso ausente ou inválido.",
            status_code=401,
        )
    return None


def serializar_valor_(valor: Any) -> Any:
    if valor is None:
        return None
    if isinstance(valor, datetime):
        return valor.isoformat()
    if hasattr(valor, "name"):
        return valor.name
    if hasattr(valor, "native"):
        try:
            return valor.native
        except Exception:
            return str(valor)
    return valor


def caminho_relativo_(caminho: Path) -> str:
    try:
        return str(caminho.resolve().relative_to(PROJECT_ROOT))
    except Exception:
        return str(caminho)


def diretorios_de_certificados_() -> List[Path]:
    diretorios: List[Path] = []

    for diretorio in (CERTS_DIR, CERTS_SUBDIR, PROJECT_ROOT):
        if diretorio.exists() and diretorio.is_dir():
            resolvido = diretorio.resolve()
            if resolvido not in diretorios:
                diretorios.append(resolvido)

    return diretorios


def caminho_em_diretorio_excluido_(caminho: Path) -> bool:
    partes = {parte.lower() for parte in caminho.parts}
    return bool(partes.intersection(EXCLUDED_CERT_DIR_NAMES))


def adicionar_arquivo_certificado_(arquivos: set, caminho: Path):
    if not caminho.is_file():
        return
    if caminho.suffix.lower() not in CERT_EXTENSIONS:
        return
    if caminho_em_diretorio_excluido_(caminho):
        return
    arquivos.add(caminho.resolve())


def coletar_arquivos_certificado_(diretorios: Iterable[Path]) -> List[Path]:
    arquivos = set()

    for diretorio in diretorios:
        if not diretorio.exists() or not diretorio.is_dir():
            continue

        # Na raiz do projeto, coletar apenas arquivos soltos. Isso evita que a
        # varredura entre em .venv/ e carregue certificados de pacotes Python.
        if diretorio.resolve() == PROJECT_ROOT:
            for caminho in diretorio.iterdir():
                adicionar_arquivo_certificado_(arquivos, caminho)
            continue

        # Fora da raiz, como em certs/, a varredura é recursiva.
        for caminho in diretorio.rglob("*"):
            adicionar_arquivo_certificado_(arquivos, caminho)

    return sorted(arquivos, key=lambda p: str(p).lower())


def certificado_para_json_(cert) -> Dict[str, Any]:
    if not cert:
        return {}

    try:
        subject = cert.subject.native
    except Exception:
        subject = {}

    try:
        issuer = cert.issuer.native
    except Exception:
        issuer = {}

    try:
        validity = cert["tbs_certificate"]["validity"]
        not_before = serializar_valor_(validity["not_before"].native)
        not_after = serializar_valor_(validity["not_after"].native)
    except Exception:
        not_before = None
        not_after = None

    try:
        serial_number = str(cert.serial_number)
    except Exception:
        try:
            serial_number = str(cert["tbs_certificate"]["serial_number"].native)
        except Exception:
            serial_number = ""

    return {
        "subject_common_name": subject.get("common_name") if isinstance(subject, dict) else None,
        "subject": subject,
        "issuer_common_name": issuer.get("common_name") if isinstance(issuer, dict) else None,
        "issuer": issuer,
        "serial_number": serial_number,
        "not_before": not_before,
        "not_after": not_after,
    }


def certificado_eh_autoassinado_(cert) -> bool:
    try:
        return cert.subject.dump() == cert.issuer.dump()
    except Exception:
        try:
            return cert.subject.native == cert.issuer.native
        except Exception:
            return False


def certificado_eh_ca_(cert) -> bool:
    try:
        extensions = cert["tbs_certificate"]["extensions"]
    except Exception:
        return False

    for extension in extensions:
        try:
            if extension["extn_id"].native != "basic_constraints":
                continue
            parsed = extension["extn_value"].parsed.native
            if isinstance(parsed, dict):
                return bool(parsed.get("ca"))
        except Exception:
            continue

    return False


def classificar_certificado_(cert, caminho: Path) -> Tuple[str, str]:
    eh_autoassinado = certificado_eh_autoassinado_(cert)
    eh_ca = certificado_eh_ca_(cert)

    if eh_autoassinado:
        return "trust_root", "Certificado autoassinado identificado como raiz confiável."

    if eh_ca:
        return "intermediate", "Certificado de autoridade certificadora não autoassinado identificado como intermediário."

    return "ignored_end_entity", "Certificado final não usado como raiz nem intermediário."


def resumo_certificado_classificado_(cert, caminho: Path, tipo: str, motivo: str) -> Dict[str, Any]:
    dados = certificado_para_json_(cert)
    return {
        "path": caminho_relativo_(caminho),
        "type": tipo,
        "reason": motivo,
        "is_self_signed": certificado_eh_autoassinado_(cert),
        "is_ca": certificado_eh_ca_(cert),
        "subject_common_name": dados.get("subject_common_name"),
        "issuer_common_name": dados.get("issuer_common_name"),
        "serial_number": dados.get("serial_number"),
        "not_before": dados.get("not_before"),
        "not_after": dados.get("not_after"),
    }


def carregar_e_classificar_certificados_(caminhos: Iterable[Path]) -> Dict[str, Any]:
    trust_roots: List[Any] = []
    intermediate_certs: List[Any] = []
    ignored_certs: List[Any] = []
    classified: List[Dict[str, Any]] = []
    erros: List[Dict[str, str]] = []

    for caminho in caminhos:
        try:
            carregados = list(load_certs_from_pemder([str(caminho)]))
            if not carregados:
                erros.append({
                    "path": caminho_relativo_(caminho),
                    "error": "Nenhum certificado foi encontrado no arquivo.",
                })
                continue

            for cert in carregados:
                tipo, motivo = classificar_certificado_(cert, caminho)
                classified.append(resumo_certificado_classificado_(cert, caminho, tipo, motivo))

                if tipo == "trust_root":
                    trust_roots.append(cert)
                elif tipo == "intermediate":
                    intermediate_certs.append(cert)
                else:
                    ignored_certs.append(cert)

        except Exception as exc:
            logger.warning("Falha ao carregar certificado %s: %s", caminho, exc)
            erros.append({
                "path": caminho_relativo_(caminho),
                "error": str(exc),
            })

    return {
        "trust_roots": trust_roots,
        "intermediate_certs": intermediate_certs,
        "ignored_certs": ignored_certs,
        "classified": sorted(classified, key=lambda item: (item["type"], item["path"].lower())),
        "load_errors": erros,
    }


@lru_cache(maxsize=1)
def carregar_material_confianca_() -> Dict[str, Any]:
    diretorios = diretorios_de_certificados_()
    certificate_paths = coletar_arquivos_certificado_(diretorios)
    material = carregar_e_classificar_certificados_(certificate_paths)

    logger.info(
        "Material de confiança carregado: %s arquivo(s), %s raiz(es), %s intermediário(s), %s ignorado(s), %s erro(s).",
        len(certificate_paths),
        len(material["trust_roots"]),
        len(material["intermediate_certs"]),
        len(material["ignored_certs"]),
        len(material["load_errors"]),
    )

    return {
        "certs_dir": caminho_relativo_(CERTS_DIR),
        "scanned_dirs": [caminho_relativo_(d) for d in diretorios],
        "excluded_dir_names": sorted(EXCLUDED_CERT_DIR_NAMES),
        "certificate_files": [caminho_relativo_(p) for p in certificate_paths],
        "trust_root_files": [
            item["path"] for item in material["classified"] if item["type"] == "trust_root"
        ],
        "intermediate_files": [
            item["path"] for item in material["classified"] if item["type"] == "intermediate"
        ],
        "ignored_files": [
            item["path"] for item in material["classified"] if item["type"] == "ignored_end_entity"
        ],
        "trust_roots": material["trust_roots"],
        "intermediate_certs": material["intermediate_certs"],
        "ignored_certs": material["ignored_certs"],
        "classified_certificates": material["classified"],
        "load_errors": material["load_errors"],
    }


def resumo_material_confianca_(material: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    material = material or carregar_material_confianca_()
    return {
        "certs_dir": material["certs_dir"],
        "scanned_dirs": material["scanned_dirs"],
        "excluded_dir_names": material["excluded_dir_names"],
        "certificate_files_total": len(material["certificate_files"]),
        "trust_roots_loaded": len(material["trust_roots"]),
        "intermediate_certs_loaded": len(material["intermediate_certs"]),
        "ignored_end_entity_certs": len(material["ignored_certs"]),
        "trust_root_files": material["trust_root_files"],
        "intermediate_files": material["intermediate_files"],
        "ignored_files": material["ignored_files"],
        "classified_certificates": material["classified_certificates"],
        "load_errors": material["load_errors"],
        "allow_fetching_certs": ALLOW_FETCHING_CERTS,
        "revocation_mode": REVOCATION_MODE,
    }


def montar_contexto_validacao_() -> Tuple[Optional[ValidationContext], Dict[str, Any]]:
    material = carregar_material_confianca_()
    trust_roots = material["trust_roots"]
    intermediate_certs = material["intermediate_certs"]

    if not trust_roots:
        logger.info("Nenhum certificado raiz confiável carregado no projeto.")
        return None, material

    try:
        contexto = ValidationContext(
            trust_roots=trust_roots,
            other_certs=intermediate_certs or None,
            allow_fetching=ALLOW_FETCHING_CERTS,
            revocation_mode=REVOCATION_MODE,
        )
        return contexto, material
    except Exception as exc:
        logger.warning("Falha ao criar ValidationContext: %s", exc)
        material = dict(material)
        material["load_errors"] = list(material.get("load_errors", [])) + [{
            "path": "ValidationContext",
            "error": str(exc),
        }]
        return None, material


def obter_nome_assinante_(sig) -> str:
    try:
        return sig.signer_cert.subject.native.get("common_name", "Desconhecido")
    except Exception:
        return "Desconhecido"


def mensagem_assinatura_(integro: bool, cadeia_confiavel: bool, contexto_configurado: bool) -> str:
    if integro and cadeia_confiavel:
        return "Assinatura íntegra e cadeia do certificado reconhecida."
    if not integro:
        return "Assinatura inválida: integridade comprometida ou alteração detectada."
    if not contexto_configurado:
        return "Assinatura íntegra, mas sem certificados confiáveis configurados no servidor."
    return "Assinatura íntegra, mas a cadeia do certificado não foi reconhecida como confiável."


def dados_validacao_(status_validacao) -> Dict[str, Any]:
    timestamp_validity = getattr(status_validacao, "timestamp_validity", None)
    revocation_details = getattr(status_validacao, "revocation_details", None)
    trust_problem = getattr(status_validacao, "trust_problem_indic", None)

    return {
        "md_algorithm": serializar_valor_(getattr(status_validacao, "md_algorithm", None)),
        "pkcs7_signature_mechanism": serializar_valor_(getattr(status_validacao, "pkcs7_signature_mechanism", None)),
        "validation_time": serializar_valor_(getattr(status_validacao, "validation_time", None)),
        "signer_reported_at": serializar_valor_(getattr(status_validacao, "signer_reported_dt", None)),
        "has_timestamp": timestamp_validity is not None,
        "timestamp_valid": bool(getattr(timestamp_validity, "valid", False)) if timestamp_validity else None,
        "trust_problem": serializar_valor_(trust_problem),
        "revocation_details": str(revocation_details) if revocation_details else None,
        "coverage": serializar_valor_(getattr(status_validacao, "coverage", None)),
        "docmdp_ok": serializar_valor_(getattr(status_validacao, "docmdp_ok", None)),
    }


@app.get("/health")
def health_check():
    return {
        "success": True,
        "status": "ok",
        "service": "unilab_validacao_assinatura",
        "version": app.version,
    }


@app.get("/trust-info")
def trust_info():
    return {
        "success": True,
        "trust_configuration": resumo_material_confianca_(),
    }


@app.post("/report")
async def validar_assinatura(
    file: UploadFile = File(...),
    authorization: Optional[str] = Header(default=None),
):
    erro_token = validar_token_(authorization)
    if erro_token:
        return erro_token

    try:
        content = await file.read()

        if not content:
            return resposta_erro("empty_file", "Arquivo vazio ou não enviado.")

        if len(content) > MAX_FILE_SIZE_BYTES:
            return resposta_erro(
                "file_too_large",
                f"Arquivo excede o limite de {MAX_FILE_SIZE_MB} MB.",
                status_code=413,
            )

        if not content.startswith(b"%PDF"):
            return resposta_erro(
                "invalid_pdf",
                "O arquivo enviado não parece ser um PDF válido.",
            )

        pdf_file = io.BytesIO(content)
        reader = PdfFileReader(pdf_file)
        assinaturas_embutidas = list(reader.embedded_signatures)

        vc, material_confianca = montar_contexto_validacao_()
        resumo_confianca = resumo_material_confianca_(material_confianca)

        if not assinaturas_embutidas:
            return {
                "success": True,
                "total_signatures": 0,
                "signatures": [],
                "message": "PDF sem assinatura digital incorporada.",
                "trust_configuration": resumo_confianca,
            }

        assinaturas = []
        contexto_configurado = vc is not None

        for sig in assinaturas_embutidas:
            nome_assinante = obter_nome_assinante_(sig)
            signer_cert = getattr(sig, "signer_cert", None)

            try:
                status_validacao = await async_validate_pdf_signature(
                    sig,
                    signer_validation_context=vc,
                    ts_validation_context=vc,
                )

                esta_integro = bool(getattr(status_validacao, "intact", False))
                validation_path = getattr(status_validacao, "validation_path", None)
                trust_problem = getattr(status_validacao, "trust_problem_indic", None)
                cadeia_confiavel = bool(validation_path is not None and trust_problem is None)
                status_geral_valido = bool(getattr(status_validacao, "valid", False))
                status = "valid" if esta_integro and cadeia_confiavel and status_geral_valido else "invalid"

                assinaturas.append({
                    "signer_name": nome_assinante,
                    "integrity": esta_integro,
                    "trusted_chain": cadeia_confiavel,
                    "status": status,
                    "message": mensagem_assinatura_(esta_integro, cadeia_confiavel, contexto_configurado),
                    "certificate": certificado_para_json_(signer_cert),
                    "validation": dados_validacao_(status_validacao),
                })

            except Exception as exc:
                logger.warning("Falha ao validar assinatura de %s: %s", nome_assinante, exc)
                assinaturas.append({
                    "signer_name": nome_assinante,
                    "integrity": False,
                    "trusted_chain": False,
                    "status": "invalid",
                    "message": "Falha ao validar esta assinatura.",
                    "certificate": certificado_para_json_(signer_cert),
                    "error": str(exc),
                })

        return {
            "success": True,
            "total_signatures": len(assinaturas),
            "signatures": assinaturas,
            "trust_configuration": resumo_confianca,
        }

    except Exception as exc:
        logger.exception("Falha no processamento do PDF")
        return resposta_erro(
            "processing_error",
            "Falha no processamento do PDF.",
            status_code=500,
            details=str(exc),
        )
