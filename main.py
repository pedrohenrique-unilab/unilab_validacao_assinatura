import io
import logging
import os
from typing import Optional

from fastapi import FastAPI, File, Header, UploadFile
from fastapi.responses import JSONResponse
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko_certvalidator import ValidationContext


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("unilab_validacao_assinatura")

app = FastAPI(
    title="UNILAB - Validação de Assinatura Digital",
    version="1.1.0",
    description="API para validação de assinaturas digitais em arquivos PDF.",
)

API_TOKEN = os.getenv("API_TOKEN", "").strip()
MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "20"))
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024


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


def carregar_raizes_confianca():
    """
    Mantém compatibilidade com a implementação anterior.

    Observação: a validação ICP-Brasil completa exige carregar certificados raiz e
    intermediários como objetos de certificado aceitos pelo pyHanko. Esta função
    apenas localiza arquivos candidatos. A revisão completa da cadeia de confiança
    deve ser feita em etapa própria.
    """
    raizes = []
    extensoes_permitidas = (".crt", ".pem")
    diretorios = (".", "certs", "certificados")

    for diretorio in diretorios:
        if not os.path.isdir(diretorio):
            continue

        for arquivo in os.listdir(diretorio):
            if arquivo.lower().endswith(extensoes_permitidas):
                raizes.append(os.path.join(diretorio, arquivo))

    return raizes


def montar_contexto_validacao_():
    lista_certificados = carregar_raizes_confianca()

    if not lista_certificados:
        logger.info("Nenhum certificado raiz/intermediário localizado no projeto.")
        return None

    try:
        return ValidationContext(trust_roots=lista_certificados)
    except Exception as exc:
        logger.warning("Falha ao criar ValidationContext: %s", exc)
        return None


def obter_nome_assinante_(sig):
    try:
        return sig.signer_cert.subject.native.get("common_name", "Desconhecido")
    except Exception:
        return "Desconhecido"


@app.get("/health")
def health_check():
    return {
        "success": True,
        "status": "ok",
        "service": "unilab_validacao_assinatura",
        "version": app.version,
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

        if not assinaturas_embutidas:
            return {
                "success": True,
                "total_signatures": 0,
                "signatures": [],
                "message": "PDF sem assinatura digital incorporada.",
            }

        vc = montar_contexto_validacao_()
        assinaturas = []

        for sig in assinaturas_embutidas:
            nome_assinante = obter_nome_assinante_(sig)

            try:
                status_validacao = await async_validate_pdf_signature(
                    sig,
                    ts_validation_context=vc,
                )

                esta_integro = bool(status_validacao.intact)
                eh_confiavel = bool(status_validacao.valid)
                status = "valid" if esta_integro and eh_confiavel else "invalid"
                mensagem = (
                    "Assinatura válida e reconhecida."
                    if esta_integro and eh_confiavel
                    else "Cadeia não confiável, certificado não validado ou arquivo alterado."
                )

                assinaturas.append({
                    "signer_name": nome_assinante,
                    "integrity": esta_integro,
                    "trusted_chain": eh_confiavel,
                    "status": status,
                    "message": mensagem,
                })

            except Exception as exc:
                logger.warning("Falha ao validar assinatura de %s: %s", nome_assinante, exc)
                assinaturas.append({
                    "signer_name": nome_assinante,
                    "integrity": False,
                    "trusted_chain": False,
                    "status": "invalid",
                    "message": "Falha ao validar esta assinatura.",
                    "error": str(exc),
                })

        return {
            "success": True,
            "total_signatures": len(assinaturas),
            "signatures": assinaturas,
        }

    except Exception as exc:
        logger.exception("Falha no processamento do PDF")
        return resposta_erro(
            "processing_error",
            "Falha no processamento do PDF.",
            status_code=500,
            details=str(exc),
        )
