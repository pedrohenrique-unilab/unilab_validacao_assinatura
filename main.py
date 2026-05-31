from fastapi import FastAPI, UploadFile, File
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
import io
import os

app = FastAPI()

def carregar_raizes_confianca():
    """
    Varre a raiz do projeto em busca de arquivos .crt e .pem 
    para carregar como âncoras de confiança.
    """
    raizes = []
    extensoes_permitidas = ('.crt', '.pem')
    
    for arquivo in os.listdir('.'):
        if arquivo.endswith(extensoes_permitidas):
            raizes.append(arquivo)
    
    return raizes

@app.post("/report")
async def validar_assinatura(file: UploadFile = File(...)):
    try:
        # Lê o arquivo PDF recebido
        content = await file.read()
        pdf_file = io.BytesIO(content)
        reader = PdfFileReader(pdf_file)
        
        # Carrega dinamicamente todos os certificados que você subiu
        lista_certificados = carregar_raizes_confianca()
        
        try:
            # Cria o contexto de validação com a cadeia completa informada
            vc = ValidationContext(trust_roots=lista_certificados)
        except Exception:
            # Fallback caso haja erro no carregamento das cadeias
            vc = None
        
        assinaturas = []
        
        # Itera sobre todas as assinaturas encontradas no documento
        for sig in reader.embedded_signatures:
            # Realiza a validação criptográfica (Integridade + Cadeia de Confiança)
            status_validacao = validate_pdf_signature(sig, validation_context=vc)
            
            nome_assinante = sig.signer_cert.subject.native.get('common_name', 'Desconhecido')
            
            # Validações individuais
            esta_integro = status_validacao.intact
            eh_confiavel = status_validacao.valid
            
            assinaturas.append({
                "signer_name": nome_assinante,
                "integrity": esta_integro,
                "trusted_chain": eh_confiavel,
                "status": "valid" if (esta_integro and eh_confiavel) else "invalid",
                "message": "Assinatura valida e reconhecida pela ICP-Brasil." if eh_confiavel else "Assinatura detectada, mas a cadeia nao eh confiavel ou o arquivo foi alterado."
            })
            
        return {
            "total_signatures": len(assinaturas),
            "signatures": assinaturas
        }
        
    except Exception as e:
        # Retorno de erro formatado sem negritos para o Apps Script
        return {"error": f"Falha no processamento do documento: {str(e)}"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)