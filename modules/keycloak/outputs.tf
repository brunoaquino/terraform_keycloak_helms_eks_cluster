output "keycloak_namespace" {
  description = "Namespace onde o Keycloak foi instalado"
  value       = var.namespace
}

output "keycloak_url" {
  description = "URL do Keycloak"
  value       = var.create_ingress ? "https://keycloak.${var.base_domain}" : null
}

output "keycloak_admin_user" {
  description = "Nome de usuário do administrador do Keycloak"
  value       = var.admin_username
} 
