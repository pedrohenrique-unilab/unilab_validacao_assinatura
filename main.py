from fastapi import FastAPI, UploadFile, File
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
import io
import os

app = FastAPI()

def carregar_raizes_confianca():
    raizes = []
    extensoes_permitidas = ('.crt', '.pem')
    # Lista os arquivos de certificado na raiz para validar a ICP-Brasil
    for arquivo in os.listdir('.'):
        if arquivo.endswith(extensoes_permitidas):
            raizes.append(arquivo)
    return raizes

@app.post("/report")
async def validar_assinatura(file: UploadFile = File(...)):
    try:
        content = await file.read()
        pdf_file = io.BytesIO(content)
        reader = PdfFileReader(pdf_file)
        
        lista_certificados = carregar_raizes_confianca()
        
        try:
            # Carrega a cadeia de confiança enviada ao GitHub
            vc = ValidationContext(trust_roots=lista_certificados)
        except Exception:
            vc = None
        
        assinaturas = []
        
        for sig in reader.embedded_signatures:
            # Validação criptográfica usando o contexto de certificados
            status_validacao = validate_pdf_signature(
                sig, 
                ts_validation_context=vc 
            )
            
            nome_assinante = sig.signer_cert.subject.native.get('common_name', 'Desconhecido')
            
            assinaturas.append({
                "signer_name": nome_assinante,
                "integrity": status_validacao.intact,
                "trusted_chain": status_validacao.valid,
                "status": "valid" if (status_validacao.intact and status_validacao.valid) else "invalid",
                "message": "Assinatura valida e reconhecida." if status_validacao.valid else "Cadeia nao confiavel ou arquivo alterado."
            })
            
        return {
            "total_signatures": len(assinaturas),
            "signatures": assinaturas
        }
        
    except Exception as e:
        return {"error": f"Falha no processamento: {str(e)}"}

# Removido o uvicorn.run daqui para evitar conflito de loops no Render