# UNILAB - Validação de Assinatura Digital

API em FastAPI para validar assinaturas digitais em arquivos PDF, integrada ao Google Apps Script e publicada no Render.

## Endpoints

### GET /health

Verifica se o serviço está ativo.

Resposta esperada:

```json
{
  "success": true,
  "status": "ok",
  "service": "unilab_validacao_assinatura"
}
```

### POST /report

Recebe um arquivo PDF no campo `file` via multipart/form-data e retorna as assinaturas digitais encontradas.

Resposta de sucesso:

```json
{
  "success": true,
  "total_signatures": 1,
  "signatures": [
    {
      "signer_name": "Nome do assinante",
      "integrity": true,
      "trusted_chain": true,
      "status": "valid",
      "message": "Assinatura válida e reconhecida."
    }
  ]
}
```

## Segurança opcional

Se a variável de ambiente `API_TOKEN` for definida no Render, o endpoint `/report` passa a exigir o cabeçalho:

```http
Authorization: Bearer SEU_TOKEN
```

Se `API_TOKEN` não estiver definida, o endpoint continua funcionando sem autenticação, preservando compatibilidade com o Apps Script atual.

## Render

Build Command:

```bash
pip install -r requirements.txt
```

Start Command:

```bash
uvicorn main:app --host 0.0.0.0 --port $PORT
```

Health Check Path recomendado:

```text
/health
```

## Observação técnica

A validação completa da cadeia ICP-Brasil ainda exige uma etapa específica de configuração e carregamento adequado dos certificados raiz e intermediários no pyHanko.
