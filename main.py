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
            vc = ValidationContext(trust_roots=lista_certificados)
        except Exception:
            vc = None
        
        assinaturas = []
        
        for sig in reader.embedded_signatures:
            # CORREÇÃO: Usando ts_validation_context conforme sugerido pelo erro
            status_validacao = validate_pdf_signature(
                sig, 
                ts_validation_context=vc 
            )
            
            nome_assinante = sig.signer_cert.subject.native.get('common_name', 'Desconhecido')
            
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
        return {"error": f"Falha no processamento do documento: {str(e)}"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)