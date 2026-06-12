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

APP_VERSION = "1.2.0"

app = FastAPI(
    title="UNILAB - Validação de Assinatura Digital",
    version=APP_VERSION,
    description="API para validação de assinaturas digitais em arquivos PDF.",
)

API_TOKEN = os.getenv("API_TOKEN", "").strip()
MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "20"))
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
CERTS_DIR = Path(os.getenv("CERTS_DIR", "certs"))
REVOCATION_MODE = os.getenv("REVOCATION_MODE", "soft-fail").strip() or "soft-fail"
CERT_EXTENSIONS = (".crt", ".cer", ".pem", ".der")


def bool_env_(nome: str, padrao: bool = False) -> bool:
    valor = os.getenv(nome)
    if valor is None:
        return padrao
    return valor.strip().lower() in {"1", "true", "yes", "sim", "on"}


ALLOW_FETCHING_CERTS = bool_env_("ALLOW_FETCHING_CERTS", False)


def resposta_erro(error_type: str, message: str, status_code: int = 400, details: Optional[str] = None):
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


def coletar_arquivos_certificado_(diretorios: Iterable[Path], somente_direto: bool = False) -> List[Path]:
    arquivos = set()

    for diretorio in diretorios:
        if not diretorio.exists() or not diretorio.is_dir():
            continue

        candidatos = diretorio.iterdir() if somente_direto else diretorio.rglob("*")
        for caminho in candidatos:
            if caminho.is_file() and caminho.suffix.lower() in CERT_EXTENSIONS:
                arquivos.add(caminho)

    return sorted(arquivos, key=lambda p: str(p).lower())


def localizar_arquivos_certificados_() -> Tuple[List[Path], List[Path]]:
    """
    Convenção adotada:
    - certs/trust_roots, certs/roots ou certs/raizes: certificados raiz confiáveis.
    - certs/intermediates, certs/intermediarios ou certs/extra: certificados intermediários/auxiliares.
    - arquivos diretamente em certs/: tratados como raízes confiáveis por compatibilidade operacional.
    """
    trust_dirs = [
        CERTS_DIR / "trust_roots",
        CERTS_DIR / "roots",
        CERTS_DIR / "raizes",
    ]
    intermediate_dirs = [
        CERTS_DIR / "intermediates",
        CERTS_DIR / "intermediarios",
        CERTS_DIR / "extra",
    ]

    trust_paths = coletar_arquivos_certificado_(trust_dirs)
    trust_paths += coletar_arquivos_certificado_([CERTS_DIR], somente_direto=True)

    intermediate_paths = coletar_arquivos_certificado_(intermediate_dirs)

    trust_paths = sorted(set(trust_paths), key=lambda p: str(p).lower())
    intermediate_paths = sorted(set(intermediate_paths), key=lambda p: str(p).lower())

    return trust_paths, intermediate_paths


def carregar_certificados_(caminhos: Iterable[Path]) -> Tuple[List[Any], List[Dict[str, str]]]:
    certificados: List[Any] = []
    erros: List[Dict[str, str]] = []

    for caminho in caminhos:
        try:
            carregados = list(load_certs_from_pemder([str(caminho)]))
            if not carregados:
                erros.append({
                    "path": str(caminho),
                    "error": "Nenhum certificado foi encontrado no arquivo.",
                })
                continue
            certificados.extend(carregados)
        except Exception as exc:
            logger.warning("Falha ao carregar certificado %s: %s", caminho, exc)
            erros.append({
                "path": str(caminho),
                "error": str(exc),
            })

    return certificados, erros


@lru_cache(maxsize=1)
def carregar_material_confianca_() -> Dict[str, Any]:
    trust_paths, intermediate_paths = localizar_arquivos_certificados_()
    trust_roots, trust_errors = carregar_certificados_(trust_paths)
    intermediate_certs, intermediate_errors = carregar_certificados_(intermediate_paths)

    logger.info(
        "Material de confiança carregado: %s raízes, %s intermediários, %s erro(s).",
        len(trust_roots),
        len(intermediate_certs),
        len(trust_errors) + len(intermediate_errors),
    )

    return {
        "certs_dir": str(CERTS_DIR),
        "trust_root_files": [str(p) for p in trust_paths],
        "intermediate_files": [str(p) for p in intermediate_paths],
        "trust_roots": trust_roots,
        "intermediate_certs": intermediate_certs,
        "load_errors": trust_errors + intermediate_errors,
    }


def resumo_material_confianca_(material: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    material = material or carregar_material_confianca_()
    return {
        "certs_dir": material["certs_dir"],
        "trust_roots_loaded": len(material["trust_roots"]),
        "intermediate_certs_loaded": len(material["intermediate_certs"]),
        "trust_root_files": material["trust_root_files"],
        "intermediate_files": material["intermediate_files"],
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
