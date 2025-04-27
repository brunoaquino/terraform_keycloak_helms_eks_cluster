variable "aws_region" {
  description = "Região da AWS onde os recursos serão criados"
  type        = string
}

variable "eks_cluster_name" {
  description = "Nome do cluster EKS"
  type        = string
}

variable "eks_cluster_endpoint" {
  description = "Endpoint do cluster EKS"
  type        = string
}

variable "eks_cluster_ca_cert" {
  description = "Certificado CA do cluster EKS"
  type        = string
}

variable "base_domain" {
  description = "Nome de domínio base para o qual o External-DNS terá permissões"
  type        = string
}

# Referência ao Cert-Manager já instalado no cluster
variable "cert_manager_letsencrypt_server" {
  description = "Servidor do Let's Encrypt (staging ou prod)"
  type        = string
  default     = "staging"

  validation {
    condition     = contains(["staging", "prod"], var.cert_manager_letsencrypt_server)
    error_message = "O valor de cert_manager_letsencrypt_server deve ser 'staging' ou 'prod'."
  }
}

# Variáveis para o módulo Keycloak
variable "keycloak_namespace" {
  description = "Namespace do Kubernetes onde o Keycloak será instalado"
  type        = string
  default     = "keycloak"
}

variable "keycloak_create_namespace" {
  description = "Indica se deve criar o namespace para o Keycloak"
  type        = bool
  default     = true
}

variable "keycloak_chart_version" {
  description = "Versão do Helm chart do Keycloak"
  type        = string
  default     = "24.6.1"
}

variable "keycloak_service_type" {
  description = "Tipo de serviço para o Keycloak (LoadBalancer, ClusterIP, NodePort)"
  type        = string
  default     = "ClusterIP"
}

variable "keycloak_enable_https" {
  description = "Habilita HTTPS para o Keycloak"
  type        = bool
  default     = true
}

variable "keycloak_create_ingress" {
  description = "Indica se deve criar um Ingress para o Keycloak"
  type        = bool
  default     = true
}

variable "keycloak_admin_username" {
  description = "Nome de usuário do administrador do Keycloak"
  type        = string
  default     = "admin"
}

variable "keycloak_admin_password" {
  description = "Senha do administrador do Keycloak. Se não fornecida, será gerada automaticamente."
  type        = string
  default     = null
  sensitive   = true
}

# Variáveis para o PostgreSQL externo
variable "keycloak_external_db_enabled" {
  description = "Indica se deve usar um banco de dados PostgreSQL externo"
  type        = bool
  default     = true
}

variable "keycloak_external_db_host" {
  description = "Host do banco de dados PostgreSQL externo"
  type        = string
  default     = ""
}

variable "keycloak_external_db_port" {
  description = "Porta do banco de dados PostgreSQL externo"
  type        = number
  default     = 5432
}

variable "keycloak_external_db_database" {
  description = "Nome do banco de dados PostgreSQL externo"
  type        = string
  default     = "keycloak"
}

variable "keycloak_external_db_username" {
  description = "Nome de usuário para o banco de dados PostgreSQL externo"
  type        = string
  default     = "keycloak"
}

variable "keycloak_external_db_password" {
  description = "Senha para o banco de dados PostgreSQL externo"
  type        = string
  default     = ""
  sensitive   = true
}
