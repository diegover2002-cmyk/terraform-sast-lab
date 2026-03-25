## Descripción

<!-- Qué cambia y por qué -->

## Tipo de cambio

- [ ] Nuevo módulo Terraform
- [ ] Modificación de módulo gold-tier (storage / keyvault / aks)
- [ ] Nuevo control MCSB o actualización de controls.md
- [ ] Registro de excepción en exceptions-registry.json
- [ ] Cambio en el pipeline de seguridad
- [ ] Documentación
- [ ] Otro: <!-- describir -->

---

## Checklist de seguridad

### Si modificas un módulo gold-tier (storage / keyvault / aks)

- [ ] He verificado que el cambio cumple los controles Must-priority del `controls.md` correspondiente
- [ ] He ejecutado `checkov -d terraform/modules/{modulo}` localmente y revisado los resultados
- [ ] Si introduzco una misconfiguración intencionada (demo), está documentada con comentario en el código

### Si introduces un FAIL conocido y justificado

- [ ] He registrado la excepción en `docs/compliance/exceptions-registry.json`
- [ ] La excepción tiene `reason` clara, `approved_by` y `expires_at` (máx. 1 año)
- [ ] He verificado que el ID de la excepción coincide exactamente con la regla Checkov o el ID MCSB

### Si modificas el pipeline o el script de análisis

- [ ] He comprobado que el step `Enforce security gate` sigue activo
- [ ] No he añadido `continue-on-error: true` al step del gate
- [ ] `MODULE_CONTROLS_MAP` sigue mapeando correctamente todos los módulos gold-tier

---

## Notas para los revisores

<!-- Cualquier contexto adicional, dependencias, o riesgos a tener en cuenta -->
