from fastapi import FastAPI, UploadFile, File
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
import io

app = FastAPI()

def extrair_cpf_cnpj_icp_brasil(cert):
    # OID 2.16.76.1.3.1 é o padrão para CPF na ICP-Brasil
    # OID 2.16.76.1.3.3 é o padrão para CNPJ na ICP-Brasil
    try:
        for extension in cert.extensions:
            if extension.oid.dotted == '2.5.29.17':  # Subject Alternative Name
                # A lógica aqui exigiria o parse do GeneralNames para buscar os OIDs da ICP-Brasil
                # Para simplificar, muitas vezes o serial_number contém o CPF ao final do nome
                pass
        return cert.subject.native.get('serial_number', '')
    except:
        return ""

@app.post("/report")
async def validar_assinatura(file: UploadFile = File(...)):
    try:
        content = await file.read()
        pdf_file = io.BytesIO(content)
        reader = PdfFileReader(pdf_file)
        
        assinaturas = []
        
        # O pyHanko permite validar a assinatura criptograficamente
        for sig in reader.embedded_signatures:
            # Validação básica de integridade (o arquivo foi mexido?)
            status_validacao = validate_pdf_signature(sig)
            
            nome_assinante = sig.signer_cert.subject.native.get('common_name', 'Desconhecido')
            documento = extrair_cpf_cnpj_icp_brasil(sig.signer_cert)
            
            # Verificamos se o hash bate e se a assinatura cobre o documento
            esta_integro = status_validacao.intact and status_validacao.valid
            
            assinaturas.append({
                "signer_name": nome_assinante,
                "document": documento,
                "status": "valid" if esta_integro else "invalid",
                "integrity": status_validacao.intact,
                "authentic": status_validacao.valid,
                "message": "Assinatura verificada criptograficamente." if esta_integro else "Falha na integridade da assinatura."
            })
            
        return {"signatures": assinaturas}
        
    except Exception as e:
        return {"error": f"Erro no processamento: {str(e)}"}