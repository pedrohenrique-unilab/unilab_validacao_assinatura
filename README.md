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
  "service": "unilab_validacao_assinatura",
  "version": "1.3.0"
}
```

### GET /trust-info

Informa como está a configuração local dos certificados de confiança usados na validação da cadeia.

A API faz a classificação automática dos certificados encontrados dentro da pasta `certs/`:

- `trust_root`: certificado autoassinado, tratado como raiz confiável.
- `intermediate`: certificado de autoridade certificadora não autoassinado, tratado como intermediário.
- `ignored_end_entity`: certificado final de pessoa, empresa ou servidor, ignorado no contexto de confiança.

Resposta esperada:

```json
{
  "success": true,
  "trust_configuration": {
    "certs_dir": "certs",
    "certificate_files_total": 10,
    "trust_roots_loaded": 1,
    "intermediate_certs_loaded": 8,
    "ignored_end_entity_certs": 1,
    "trust_root_files": ["certs/AC_RAIZ.crt"],
    "intermediate_files": ["certs/AC_INTERMEDIARIA.crt"],
    "ignored_files": ["certs/certificado-final.crt"],
    "classified_certificates": [
      {
        "path": "certs/AC_RAIZ.crt",
        "type": "trust_root",
        "reason": "Certificado autoassinado identificado como raiz confiável.",
        "is_self_signed": true,
        "is_ca": true,
        "subject_common_name": "AC Raiz",
        "issuer_common_name": "AC Raiz",
        "serial_number": "123456789",
        "not_before": "2025-01-01T00:00:00+00:00",
        "not_after": "2035-01-01T00:00:00+00:00"
      }
    ],
    "load_errors": [],
    "allow_fetching_certs": false,
    "revocation_mode": "soft-fail"
  }
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
      "message": "Assinatura íntegra e cadeia do certificado reconhecida.",
      "certificate": {
        "subject_common_name": "Nome do assinante",
        "issuer_common_name": "Nome da autoridade certificadora",
        "serial_number": "123456789",
        "not_before": "2025-01-01T00:00:00+00:00",
        "not_after": "2026-01-01T00:00:00+00:00"
      },
      "validation": {
        "has_timestamp": true,
        "timestamp_valid": true,
        "trust_problem": null,
        "revocation_details": null
      }
    }
  ]
}
```

## Segurança

Se a variável de ambiente `API_TOKEN` for definida no Render, o endpoint `/report` exige o cabeçalho:

```http
Authorization: Bearer SEU_TOKEN
```

Se `API_TOKEN` não estiver definida, o endpoint continua funcionando sem autenticação.

## Certificados de confiança

A API carrega todos os arquivos de certificado encontrados recursivamente dentro da pasta `certs/`.

Formatos aceitos:

```text
.crt
.cer
.pem
.der
```

A separação manual por pasta não é obrigatória. A API identifica automaticamente:

```text
subject == issuer          -> raiz confiável
BasicConstraints CA=True   -> intermediário, quando não for autoassinado
CA=False ou sem CA         -> certificado final ignorado
```

A estrutura recomendada continua sendo:

```text
certs/
  trust_roots/        certificados raiz confiáveis
  intermediates/      certificados intermediários e auxiliares
```

Também são aceitos os nomes alternativos:

```text
certs/roots/
certs/raizes/
certs/intermediarios/
certs/extra/
```

Variáveis de ambiente relacionadas:

```text
CERTS_DIR=certs
ALLOW_FETCHING_CERTS=false
REVOCATION_MODE=soft-fail
```

Recomendação operacional: depois de cada alteração nos certificados, consulte `/trust-info` e confirme se `trust_roots_loaded` e `intermediate_certs_loaded` estão coerentes.

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

A validação da cadeia de confiança depende dos certificados colocados na pasta `certs/`. Sem certificados raiz confiáveis carregados, a API pode indicar integridade da assinatura, mas não deve considerar a cadeia como confiável.
