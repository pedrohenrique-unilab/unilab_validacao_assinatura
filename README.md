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
  "version": "1.3.3"
}
```

### GET /trust-info

Informa como está a configuração local dos certificados usados na validação da cadeia.

A API varre a raiz do projeto e a pasta `certs/`, ignorando diretórios de ambiente e dependências como `.venv`, `venv`, `site-packages`, `node_modules`, `.git` e caches.

A classificação automática é:

- `trust_root`: certificado autoassinado cujo arquivo está na lista de raízes confiáveis permitidas.
- `ignored_untrusted_root`: certificado autoassinado encontrado no repositório, mas fora da lista de raízes confiáveis permitidas.
- `intermediate`: certificado de autoridade certificadora não autoassinado, tratado como intermediário.
- `ignored_end_entity`: certificado final de pessoa, empresa ou servidor, ignorado no contexto de confiança.

Raízes confiáveis permitidas no código:

```text
ICP-Brasilv4.crt
ICP-Brasilv5.crt
ICP-Brasilv6.crt
ICP-Brasilv7.crt
ICP-Brasilv10.crt
ICP-Brasilv11.crt
ICP-Brasilv12.crt
ICP-Brasilv13.crt
```

Raízes antigas, expiradas ou revogadas podem continuar no repositório para referência, mas não entram no `ValidationContext` se não estiverem nessa lista.

Resposta esperada:

```json
{
  "success": true,
  "trust_configuration": {
    "certs_dir": ".",
    "scanned_dirs": [".", "certs"],
    "certificate_files_total": 332,
    "trust_roots_loaded": 8,
    "intermediate_certs_loaded": 320,
    "ignored_certs_total": 4,
    "ignored_untrusted_root_certs": 4,
    "ignored_end_entity_certs": 0,
    "trust_root_files": ["ICP-Brasilv4.crt"],
    "untrusted_root_files": ["ICP-Brasilv3.crt"],
    "intermediate_files": ["AC_INTERMEDIARIA.crt"],
    "classified_certificates": [],
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

Formatos aceitos:

```text
.crt
.cer
.pem
.der
```

A separação manual por pasta não é obrigatória. A API aceita certificados soltos na raiz do repositório e também em `certs/`.

A estrutura recomendada para organização futura é:

```text
certs/
  trust_roots/        certificados raiz confiáveis
  intermediates/      certificados intermediários e auxiliares
```

Variáveis de ambiente relacionadas:

```text
CERTS_DIR=.
ALLOW_FETCHING_CERTS=false
REVOCATION_MODE=soft-fail
```

Recomendação operacional: depois de cada alteração nos certificados, consulte `/trust-info` e confirme se `trust_roots_loaded`, `untrusted_root_files` e `intermediate_certs_loaded` estão coerentes.

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

A validação da cadeia de confiança depende dos certificados configurados como raízes confiáveis. Certificados intermediários auxiliam a montagem da cadeia, mas somente os arquivos listados em `TRUSTED_ROOT_FILE_NAMES` são usados como âncoras de confiança.
