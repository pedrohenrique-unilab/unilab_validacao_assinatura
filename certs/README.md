# Certificados de confiança

Coloque nesta pasta os certificados usados pela API para validar a cadeia de confiança das assinaturas digitais.

Estrutura recomendada:

```text
certs/
  trust_roots/        certificados raiz confiáveis
  intermediates/      certificados intermediários e auxiliares
```

Arquivos diretamente em `certs/` também são tratados como certificados raiz confiáveis por compatibilidade operacional.

Formatos aceitos: `.crt`, `.cer`, `.pem` e `.der`.
