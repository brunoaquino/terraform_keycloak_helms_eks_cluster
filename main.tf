provider "aws" {
  region = var.aws_region
}

provider "kubernetes" {
  host                   = var.eks_cluster_endpoint
  cluster_ca_certificate = base64decode(var.eks_cluster_ca_cert)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    args        = ["eks", "get-token", "--cluster-name", var.eks_cluster_name]
    command     = "aws"
  }
}

provider "helm" {
  kubernetes {
    host                   = var.eks_cluster_endpoint
    cluster_ca_certificate = base64decode(var.eks_cluster_ca_cert)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      args        = ["eks", "get-token", "--cluster-name", var.eks_cluster_name]
      command     = "aws"
    }
  }
}

# Módulo Keycloak
module "keycloak" {
  source = "./modules/keycloak"

  aws_region           = var.aws_region
  eks_cluster_name     = var.eks_cluster_name
  eks_cluster_endpoint = var.eks_cluster_endpoint
  eks_cluster_ca_cert  = var.eks_cluster_ca_cert
  base_domain          = var.base_domain

  # Configurações específicas do Keycloak
  namespace                = var.keycloak_namespace
  create_namespace         = var.keycloak_create_namespace
  chart_version            = var.keycloak_chart_version
  service_type             = var.keycloak_service_type
  enable_https             = var.keycloak_enable_https
  create_ingress           = var.keycloak_create_ingress
  admin_username           = var.keycloak_admin_username
  admin_password           = var.keycloak_admin_password
  cert_manager_environment = var.cert_manager_letsencrypt_server

  # Configurações do PostgreSQL externo
  external_db_enabled  = var.keycloak_external_db_enabled
  external_db_host     = var.keycloak_external_db_host
  external_db_port     = var.keycloak_external_db_port
  external_db_database = var.keycloak_external_db_database
  external_db_username = var.keycloak_external_db_username
  external_db_password = var.keycloak_external_db_password
}
