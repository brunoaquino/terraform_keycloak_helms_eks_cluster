# Outputs do Keycloak
output "keycloak_namespace" {
  description = "Namespace onde o Keycloak foi instalado"
  value       = module.keycloak.keycloak_namespace
}

output "keycloak_endpoint" {
  description = "Endpoint do Keycloak"
  value       = "Para acessar o Keycloak, use: ${module.keycloak.keycloak_url}"
}

output "keycloak_credentials" {
  description = "Instruções para obter as credenciais do Keycloak"
  value       = <<-EOT
    1. Usuário administrador: ${module.keycloak.keycloak_admin_user}
    2. Se nenhuma senha foi definida, obtenha a senha gerada automaticamente:
       kubectl -n ${module.keycloak.keycloak_namespace} get secret keycloak -o jsonpath="{.data.admin-password}" | base64 -d
  EOT
}

# Informações gerais
output "info_message" {
  description = "Informações gerais sobre a instalação"
  value       = <<-EOT
    Keycloak foi instalado com sucesso!
    
    Keycloak:
    - Namespace: ${module.keycloak.keycloak_namespace}
    - Console: ${module.keycloak.keycloak_url}
    - Banco de Dados: PostgreSQL Externo (${var.keycloak_external_db_host})
    
    Observações:
    - Use as instruções acima para obter as credenciais do administrador
    - Recomenda-se alterar a senha após o primeiro login
    - Configure seus reinos (realms) e clientes no Keycloak para gerenciar autenticação
  EOT
}
