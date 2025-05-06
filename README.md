# Keycloak no EKS - Arquitetura de Referência

Este projeto Terraform configura o Keycloak em um cluster Amazon EKS, fornecendo autenticação/autorização centralizada para suas aplicações.

## Pré-requisitos

- AWS CLI configurado com acesso adequado
- Terraform >= 1.0.0
- kubectl >= 1.20
- Cluster EKS existente
- Helm >= 3.0.0
- Domínio configurado com Route53 ou outro provedor DNS
- NGINX Ingress Controller já instalado no cluster
- cert-manager com ClusterIssuer letsencrypt-prod já configurado
- External-DNS já configurado

## Dependências de Versões

- Keycloak Chart: 24.6.1 (Bitnami)
- Keycloak: 26.2.1
- PostgreSQL: 16.x (compatível com Amazon RDS)
- cert-manager: v1.10.0 ou superior (já instalado)
- NGINX Ingress Controller: v1.5.0 ou superior (já instalado)
- External-DNS: v0.12.0 ou superior (já instalado)
- AWS EKS: 1.27 ou superior
- Terraform: >= 1.0.0
- Kubernetes: >= 1.20

## Requisitos de Infraestrutura

### Banco de Dados PostgreSQL

- Versão: PostgreSQL 16.x
- Instância recomendada na AWS: db.t3.medium (mínimo)
- Armazenamento mínimo: 20GB
- Configuração Multi-AZ recomendada para produção
- Parâmetros recomendados:
  - max_connections: 200
  - shared_buffers: 256MB
  - effective_cache_size: 768MB

### EKS Cluster

- Versão: 1.27 ou superior
- Tamanho mínimo dos nodes: t3.medium
- Número mínimo de nodes: 2
- Autoscaling recomendado para ambientes de produção

## Configuração do Ambiente

### 1. Configurar acesso ao cluster EKS

```bash
# Obter credenciais para o cluster EKS
aws eks update-kubeconfig --region us-east-1 --name seu-cluster-eks

# Verificar conexão com o cluster
kubectl cluster-info

# Verificar os componentes já instalados
kubectl get pods -n ingress-nginx
kubectl get pods -n cert-manager
kubectl get clusterissuer letsencrypt-prod
kubectl get pods -n kube-system -l app.kubernetes.io/name=external-dns
```

## Configuração do Terraform

### 1. Configurar Variáveis

Edite o arquivo `terraform.tfvars` com suas informações:

```hcl
aws_region           = "us-east-1"
eks_cluster_name     = "seu-cluster-eks"
eks_cluster_endpoint = "https://seu-endpoint-eks.region.eks.amazonaws.com"
eks_cluster_ca_cert  = "seu-certificado-ca-base64"

# Obtenha o endpoint e certificado CA com esses comandos:
# aws eks describe-cluster --name seu-cluster-eks --query "cluster.endpoint" --output text
# aws eks describe-cluster --name seu-cluster-eks --query "cluster.certificateAuthority.data" --output text

base_domain = "seu-dominio.com"
cert_manager_letsencrypt_server = "prod"

# Keycloak
keycloak_namespace      = "keycloak"
keycloak_chart_version  = "24.6.1"
keycloak_admin_password = "sua-senha-segura" # Mude para uma senha forte
keycloak_hostname       = "keycloak.seu-dominio.com"
keycloak_enable_tls     = true

# Recursos do Keycloak
keycloak_resources_requests_cpu    = "500m"  # Ajuste conforme necessidade
keycloak_resources_requests_memory = "1Gi"   # Ajuste conforme necessidade
keycloak_resources_limits_cpu      = "1000m" # Ajuste conforme necessidade
keycloak_resources_limits_memory   = "2Gi"   # Ajuste conforme necessidade

# PostgreSQL Externo (AWS RDS ou outro)
keycloak_external_db_enabled  = true
keycloak_external_db_host     = "seu-postgresql.region.rds.amazonaws.com"
keycloak_external_db_port     = 5432
keycloak_external_db_database = "keycloak"
keycloak_external_db_username = "keycloak"
keycloak_external_db_password = "senha-segura-do-banco"
```

### 2. Inicializar e Aplicar o Terraform

```bash
terraform init
terraform apply
```

## Acesso ao Keycloak

### Interface Web do Keycloak

Após a instalação, acesse o Keycloak através da URL:

```
https://keycloak.seu-dominio.com
```

### Credenciais de Administrador

As credenciais iniciais para o administrador do Keycloak são:

- **Usuário**: admin
- **Senha**: Definida na variável `keycloak_admin_password` no arquivo terraform.tfvars

## Configuração do Keycloak

### 1. Criação de um Realm

Um Realm no Keycloak é um conceito que define um domínio protegido pelo Keycloak. Ele contém clientes, usuários, funções, grupos, etc.

1. Faça login na interface administrativa do Keycloak
2. Clique em "Create Realm"
3. Forneça um nome para o realm (ex: "app-realm")
4. Clique em "Create"

### 2. Criação de Clientes para Frontend (NextJS) e Backend (NestJS)

#### 2.1. Cliente para Frontend (NextJS)

1. No seu realm, clique em "Clients" no menu lateral
2. Clique em "Create client"
3. Configure o cliente para o NextJS:
   - Client ID: `frontend-app`
   - Client type: `Standard flow`
   - Habilite "Client authentication" (Off para aplicações SPA)
   - Valid redirect URIs: `https://seu-frontend.com/*`
   - Web origins: `https://seu-frontend.com` (para CORS)
4. Salve o cliente

Configure as opções avançadas conforme necessário:

- Na aba "Settings":
  - Access type: `public`
  - Standard flow enabled: `ON`
  - Direct access grants enabled: `ON` (para login com username/password)
  - Implicit flow enabled: `OFF` (deprecated)
  - Service accounts enabled: `OFF` (para aplicações cliente)

#### 2.2. Cliente para Backend (NestJS)

1. No seu realm, clique em "Clients" no menu lateral
2. Clique em "Create client"
3. Configure o cliente para o NestJS:
   - Client ID: `backend-api`
   - Client type: `Bearer-only` ou `Service accounts (if client calls other services)`
   - Habilite "Client authentication" (On para APIs protegidas)
4. Salve o cliente

Configure as opções avançadas:

- Na aba "Settings":

  - Access type: `confidential` (para verificação de tokens)
  - Standard flow enabled: `OFF`
  - Direct access grants enabled: `OFF`
  - Service accounts enabled: `ON` (para cliente-credenciais se o backend precisar chamar outras APIs)

- Na aba "Credentials" (após salvar), copie o "Client Secret" que será usado pelo seu backend

### 3. Criação de Usuários

1. No seu realm, clique em "Users" no menu lateral
2. Clique em "Add user"
3. Preencha os campos obrigatórios (username, email, etc.)
4. Na aba "Credentials", defina uma senha para o usuário

### 4. Criação de Roles (Papéis)

1. No seu realm, clique em "Realm roles" (para papéis globais) ou no cliente específico para papéis de cliente
2. Clique em "Create role"
3. Defina um nome e descrição para o papel (ex: "user", "admin", etc.)
4. Salve o papel

## Integração com NextJS (Frontend)

### Instalação dos pacotes necessários

```bash
npm install next-auth keycloak-js
# ou
yarn add next-auth keycloak-js
```

### Configuração do NextAuth

Crie um arquivo `pages/api/auth/[...nextauth].js`:

```javascript
import NextAuth from "next-auth";
import KeycloakProvider from "next-auth/providers/keycloak";

export default NextAuth({
  providers: [
    KeycloakProvider({
      clientId: process.env.KEYCLOAK_CLIENT_ID,
      clientSecret: process.env.KEYCLOAK_CLIENT_SECRET,
      issuer: process.env.KEYCLOAK_ISSUER,
    }),
  ],
  callbacks: {
    async jwt({ token, account }) {
      // Persistir o access_token no token JWT
      if (account) {
        token.accessToken = account.access_token;
        token.refreshToken = account.refresh_token;
        token.idToken = account.id_token;
        token.expiresAt = account.expires_at;
      }
      return token;
    },
    async session({ session, token }) {
      // Enviar tokens para o cliente
      session.accessToken = token.accessToken;
      session.error = token.error;

      return session;
    },
  },
});
```

### Configuração das variáveis de ambiente (.env)

```
KEYCLOAK_CLIENT_ID=frontend-app
KEYCLOAK_CLIENT_SECRET=seu-client-secret
KEYCLOAK_ISSUER=https://keycloak.seu-dominio.com/realms/app-realm
NEXTAUTH_URL=https://seu-frontend.com
NEXTAUTH_SECRET=sua-chave-secreta-gerada-aleatoriamente
```

### Uso no componente

```jsx
import { useSession, signIn, signOut } from "next-auth/react";

export default function Component() {
  const { data: session } = useSession();

  if (session) {
    return (
      <>
        <p>Signed in as {session.user.email}</p>
        <button onClick={() => signOut()}>Sign out</button>
      </>
    );
  }

  return (
    <>
      <p>Not signed in</p>
      <button onClick={() => signIn("keycloak")}>Sign in</button>
    </>
  );
}
```

### Proteção de rotas

```jsx
// Em _app.js
import { SessionProvider } from "next-auth/react";

function MyApp({ Component, pageProps: { session, ...pageProps } }) {
  return (
    <SessionProvider session={session}>
      <Component {...pageProps} />
    </SessionProvider>
  );
}

export default MyApp;
```

## Monitoramento e Manutenção

### Logs do Keycloak

Para verificar os logs do Keycloak:

```bash
kubectl logs -f -n keycloak deploy/keycloak
```

### Backup do Banco de Dados

Recomenda-se configurar backups regulares do banco de dados PostgreSQL. Para o Amazon RDS, você pode ativar snapshots automáticos.

### Atualização do Keycloak

Para atualizar o Keycloak para uma nova versão, atualize a variável `keycloak_chart_version` no arquivo terraform.tfvars e execute:

```bash
terraform apply
```

## Segurança

- Recomenda-se alterar a senha de administrador após o primeiro login
- Configure TLS para todas as comunicações
- Utilize grupos e papéis para gerenciar permissões
- Considere a integração com um provedor de identidade existente se necessário (LDAP, SAML, etc.)
- Implemente monitoramento de segurança e auditorias regulares
- Mantenha o Keycloak e PostgreSQL atualizados com as últimas versões de segurança

## Resolução de Problemas

### Problemas comuns:

1. **Não é possível acessar o Keycloak**: Verifique o Ingress, certificados TLS e resolução DNS
2. **Erros de banco de dados**: Verifique as credenciais e conectividade com o PostgreSQL
3. **Problemas de desempenho**: Ajuste os recursos do Keycloak e PostgreSQL conforme necessário
4. **Erros de autenticação**: Verifique a configuração dos clientes e redirects
