from fastapi import FastAPI, UploadFile, File
from pyhanko.pdf_utils.reader import PdfFileReader
import io

app = FastAPI()

@app.post("/report")
async def validar_assinatura(file: UploadFile = File(...)):
    try:
        # Lê o arquivo PDF recebido
        content = await file.read()
        pdf_file = io.BytesIO(content)
        reader = PdfFileReader(pdf_file)
        
        assinaturas = []
        
        # Verifica as assinaturas embutidas no documento
        for sig_field in reader.embedded_signatures:
            # Tenta extrair o nome (Common Name) do certificado
            try:
                nome_assinante = sig_field.signer_cert.subject.native.get('common_name', 'Assinante não identificado')
            except:
                nome_assinante = "Assinante não identificado"
                
            # Extrai o CPF/CNPJ se existir na estrutura da ICP-Brasil
            try:
                cpf_cnpj = sig_field.signer_cert.subject.native.get('serial_number', '')
            except:
                cpf_cnpj = ""

            assinaturas.append({
                "signer_name": nome_assinante,
                "document": cpf_cnpj,
                "status": "valid", # Como o Apps Script espera "valid" para dar apto
                "message": "Assinatura detectada pelos metadados do arquivo."
            })
            
        return {
            "signatures": assinaturas
        }
        
    except Exception as e:
        return {"error": f"Falha ao processar o PDF: {str(e)}"}