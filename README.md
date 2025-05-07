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

## Boas Práticas para Nomes de Grupos e Roles no Keycloak

### Princípios Gerais

- **Simplicidade e Clareza**: Os nomes devem ser autoexplicativos e facilmente compreensíveis por todos na organização.
- **Consistência**: Adote um padrão de nomenclatura e mantenha-o em todo o sistema.
- **Hierarquia**: Utilize estruturas hierárquicas quando apropriado para organizar melhor suas permissões.

### Boas Práticas para Nomes de Grupos

A utilização de grupos simplifica o processo de atribuição de permissões aos usuários. Em vez de gerenciar as permissões individualmente, organize os usuários em grupos e atribua as permissões adequadas a esses grupos.

#### Padrões de Nomenclatura para Grupos

1. **Baseado em Departamentos/Funções**:

   - `Departamento_TI`
   - `Departamento_RH`
   - `Departamento_Financeiro`
   - `Equipe_Desenvolvimento`

2. **Baseado em Níveis de Acesso**:

   - `Acesso_Administrativo`
   - `Acesso_Gerencial`
   - `Acesso_Operacional`

3. **Prefixos Claros**:

   - Use prefixos como `G_` para indicar grupos
   - Exemplo: `G_Financeiro_Leitura`, `G_Financeiro_Completo`

4. **Grupos Aninhados/Hierárquicos**:
   - `TI/Desenvolvimento/Frontend`
   - `TI/Desenvolvimento/Backend`
   - `TI/Infraestrutura/Redes`

### Boas Práticas para Nomes de Roles

Roles identificam um tipo ou categoria de usuário. Admin, user, manager e employee são exemplos típicos que podem existir em uma organização.

#### Padrões de Nomenclatura para Roles

1. **Baseado em Ações**:

   - `criar_usuario`
   - `editar_usuario`
   - `visualizar_usuario`
   - `excluir_usuario`

2. **Baseado em Recursos + Ações**:

   - `usuario_criar`
   - `usuario_editar`
   - `usuario_visualizar`
   - `usuario_excluir`
   - `relatorio_gerar`
   - `relatorio_visualizar`

3. **Prefixos para Diferenciação**:

   - Use prefixos como `R_` para roles
   - Exemplo: `R_Admin`, `R_Gerente`, `R_Usuario`

4. **Tipos de Roles**:
   - **Roles Simples**: Para permissões diretas (ex: `visualizar_relatorio`)
   - **Roles Compostas**: Para agrupar outras roles (ex: `gerente_relatorios` inclui `visualizar_relatorio`, `gerar_relatorio`)

### Organização Funcional

1. **Roles de Realm vs. Roles de Client**:

   - **Roles de Realm**: Use para permissões globais (ex: `admin_sistema`)
   - **Roles de Client**: Use para permissões específicas da aplicação (ex: `app_cadastrar`)

2. **Mapeamento entre Grupos e Roles**:

   - Atribua roles aos grupos para facilitar a gestão
   - Um usuário herda todas as roles do grupo a que pertence

3. **Hierarquia Organizacional**:
   - Crie grupos que reflitam a estrutura da empresa
   - Agrupe roles relacionadas para facilitar a atribuição

### Recomendações Práticas

1. **Padronização de Nomenclatura**:

   - Use separadores consistentes: underscores (\_) ou hífens (-)
   - Escolha entre CamelCase (`usuarioAdmin`) ou snake_case (`usuario_admin`)
   - Mantenha todos os nomes em minúsculas ou use um padrão de capitalização consistente

2. **Documentação**:

   - Mantenha um documento com a descrição de todas as roles e grupos
   - Descreva o propósito de cada role e grupo no campo de descrição do Keycloak

3. **Revisão Periódica**:

   - Avalie regularmente seus grupos e roles para remover duplicações
   - Verifique permissões não utilizadas e consolide quando necessário

4. **Evite Nomes Ambíguos**:
   - `pode_editar` é vago → `usuario_editar` é específico
   - `admin` é amplo → `admin_sistema` ou `admin_usuarios` é específico

Seguindo estas práticas, você conseguirá manter um sistema de permissões no Keycloak que é organizado, escalável e fácil de gerenciar, mesmo à medida que sua organização e requisitos de segurança crescem.

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

## Configurações Iniciais e Boas Práticas para Clients no Keycloak

### 1. Client para Aplicação React (Frontend)

#### Configuração do Client

1. No seu realm, clique em "Clients" no menu lateral
2. Clique em "Create client"
3. Configure o cliente para o React:
   - Client ID: `react-app`
   - Client type: `Standard flow`
   - Habilite "Client authentication": `OFF` (para aplicações SPA)
   - Valid redirect URIs:
     ```
     http://localhost:3000/*
     https://seu-app-react.com/*
     ```
   - Web origins:
     ```
     http://localhost:3000
     https://seu-app-react.com
     ```

#### Configurações Avançadas

Na aba "Settings":

- Access type: `public`
- Standard flow enabled: `ON`
- Direct access grants enabled: `ON`
- Implicit flow enabled: `OFF` (deprecated)
- Service accounts enabled: `OFF`
- OIDC CIBA Grant Enabled: `OFF`
- OAuth 2.0 Device Authorization Grant Enabled: `OFF`

#### Configuração do React

1. Instale as dependências necessárias:

```bash
npm install @react-keycloak/web keycloak-js
# ou
yarn add @react-keycloak/web keycloak-js
```

2. Configure o Keycloak no seu aplicativo React:

```typescript
// src/keycloak.ts
import Keycloak from "keycloak-js";

const keycloakConfig = {
  url: "https://keycloak.seu-dominio.com",
  realm: "seu-realm",
  clientId: "react-app",
};

const keycloak = new Keycloak(keycloakConfig);

export default keycloak;
```

3. Configure o provedor no seu aplicativo:

```typescript
// src/App.tsx
import { ReactKeycloakProvider } from "@react-keycloak/web";
import keycloak from "./keycloak";

function App() {
  return (
    <ReactKeycloakProvider authClient={keycloak}>
      <Router>{/* Suas rotas aqui */}</Router>
    </ReactKeycloakProvider>
  );
}
```

4. Use o hook para autenticação:

```typescript
// src/components/Login.tsx
import { useKeycloak } from "@react-keycloak/web";

function Login() {
  const { keycloak } = useKeycloak();

  return (
    <div>
      {!keycloak.authenticated && (
        <button onClick={() => keycloak.login()}>Login</button>
      )}
      {keycloak.authenticated && (
        <button onClick={() => keycloak.logout()}>Logout</button>
      )}
    </div>
  );
}
```

### 2. Client para Validação de Token (Backend)

#### Configuração do Client

1. No seu realm, clique em "Clients" no menu lateral
2. Clique em "Create client"
3. Configure o cliente para validação de token:
   - Client ID: `token-validator`
   - Client type: `Bearer-only`
   - Habilite "Client authentication": `ON`
   - Valid redirect URIs: `*` (não é necessário para Bearer-only)

#### Configurações Avançadas

Na aba "Settings":

- Access type: `confidential`
- Standard flow enabled: `OFF`
- Direct access grants enabled: `OFF`
- Implicit flow enabled: `OFF`
- Service accounts enabled: `ON`
- OIDC CIBA Grant Enabled: `OFF`
- OAuth 2.0 Device Authorization Grant Enabled: `OFF`

#### Configuração do Backend (NestJS)

1. Instale as dependências necessárias:

```bash
npm install @nestjs/passport passport passport-keycloak-bearer
# ou
yarn add @nestjs/passport passport passport-keycloak-bearer
```

2. Configure a estratégia de autenticação:

```typescript
// src/auth/keycloak.strategy.ts
import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { Strategy } from "passport-keycloak-bearer";

@Injectable()
export class KeycloakStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      realm: "seu-realm",
      "auth-server-url": "https://keycloak.seu-dominio.com",
      "ssl-required": "external",
      resource: "token-validator",
      "confidential-port": 0,
      "bearer-only": true,
    });
  }

  async validate(token: string) {
    // Aqui você pode adicionar lógica adicional de validação
    return token;
  }
}
```

3. Configure o módulo de autenticação:

```typescript
// src/auth/auth.module.ts
import { Module } from "@nestjs/common";
import { PassportModule } from "@nestjs/passport";
import { KeycloakStrategy } from "./keycloak.strategy";

@Module({
  imports: [PassportModule],
  providers: [KeycloakStrategy],
  exports: [PassportModule],
})
export class AuthModule {}
```

4. Use o guard para proteger suas rotas:

```typescript
// src/controllers/protected.controller.ts
import { Controller, Get, UseGuards } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";

@Controller("protected")
export class ProtectedController {
  @UseGuards(AuthGuard("keycloak"))
  @Get()
  getProtectedResource() {
    return { message: "Recurso protegido" };
  }
}
```

### Boas Práticas para Clients

1. **Segurança**:

   - Use HTTPS em produção
   - Configure CORS adequadamente
   - Mantenha os client secrets seguros
   - Use o tipo de client apropriado para cada caso de uso

2. **Configuração de Roles**:

   - Crie roles específicas para cada client
   - Use roles compostas para agrupar permissões
   - Documente o propósito de cada role

3. **Monitoramento**:

   - Ative o logging de eventos do client
   - Monitore tentativas de login falhas
   - Configure alertas para atividades suspeitas

4. **Manutenção**:

   - Revise periodicamente as configurações dos clients
   - Remova clients não utilizados
   - Mantenha as URLs de redirecionamento atualizadas

5. **Performance**:
   - Configure timeouts adequados
   - Use cache quando apropriado
   - Monitore o uso de recursos
