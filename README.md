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
- cert-manager: v1.10.0 ou superior (já instalado)
- NGINX Ingress Controller: v1.5.0 ou superior (já instalado)
- External-DNS: v0.12.0 ou superior (já instalado)

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

export default function App({ Component, pageProps }) {
  return (
    <SessionProvider session={pageProps.session}>
      <Component {...pageProps} />
    </SessionProvider>
  );
}

// Em páginas protegidas
import { getSession } from "next-auth/react";

export async function getServerSideProps(context) {
  const session = await getSession(context);

  if (!session) {
    return {
      redirect: {
        destination: "/api/auth/signin",
        permanent: false,
      },
    };
  }

  return {
    props: { session },
  };
}
```

## Integração com NestJS (Backend)

### Instalação dos pacotes necessários

```bash
npm install @nestjs/passport passport-jwt jwks-rsa
# ou
yarn add @nestjs/passport passport-jwt jwks-rsa
```

### Configuração do módulo de autenticação

```typescript
// auth.module.ts
import { Module } from "@nestjs/common";
import { PassportModule } from "@nestjs/passport";
import { JwtStrategy } from "./jwt.strategy";

@Module({
  imports: [PassportModule.register({ defaultStrategy: "jwt" })],
  providers: [JwtStrategy],
  exports: [PassportModule],
})
export class AuthModule {}
```

### Implementação da estratégia JWT

```typescript
// jwt.strategy.ts
import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import * as jwksRsa from "jwks-rsa";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      audience: "backend-api", // Client ID do backend no Keycloak
      issuer: process.env.KEYCLOAK_ISSUER,
      algorithms: ["RS256"],
      secretOrKeyProvider: jwksRsa.passportJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `${process.env.KEYCLOAK_ISSUER}/protocol/openid-connect/certs`,
      }),
    });
  }

  async validate(payload: any) {
    // Retorne o usuário a partir do payload
    return {
      id: payload.sub,
      username: payload.preferred_username,
      email: payload.email,
      roles: payload.realm_access?.roles || [],
    };
  }
}
```

### Configuração das variáveis de ambiente (.env)

```
KEYCLOAK_ISSUER=https://keycloak.seu-dominio.com/realms/app-realm
```

### Uso dos Guards de autenticação

```typescript
// Em controllers que precisam de autenticação
import { Controller, Get, UseGuards } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";
import { JwtAuthGuard } from "../auth/jwt-auth.guard";

@Controller("api/protected")
export class ProtectedController {
  @UseGuards(JwtAuthGuard)
  @Get()
  getProtectedData() {
    return { message: "This is protected data" };
  }
}
```

### Criação de um Guard personalizado para verificar roles

```typescript
// roles.guard.ts
import { Injectable, CanActivate, ExecutionContext } from "@nestjs/common";
import { Reflector } from "@nestjs/core";

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>("roles", [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest();
    return requiredRoles.some((role) => user.roles?.includes(role));
  }
}

// Decorador para definir roles
// roles.decorator.ts
import { SetMetadata } from "@nestjs/common";

export const Roles = (...roles: string[]) => SetMetadata("roles", roles);

// Uso em controllers
@Controller("api/admin")
export class AdminController {
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles("admin")
  @Get()
  getAdminData() {
    return { message: "Admin data" };
  }
}
```

## Boas Práticas de Segurança

### 1. Gerenciamento de Tokens

- Configure tempos de expiração adequados para os tokens (30min-1h para access tokens)
- Implemente renovação automática de tokens usando refresh tokens
- Armazene tokens de forma segura (HttpOnly cookies, sessionStorage)

### 2. Proteção contra CSRF

Ative a proteção CSRF no Keycloak:

1. No painel do Keycloak, acesse o realm
2. Vá para Realm Settings > Security Defenses
3. Configure o CSRF

### 3. Configuração de CORS

Configure CORS corretamente tanto no Keycloak quanto na sua aplicação:

No Keycloak:

1. No painel do Keycloak, acesse o realm
2. Vá para Realm Settings > Security Defenses > CORS
3. Adicione as origens permitidas

### 4. Uso de HTTPS

Sempre use HTTPS em todos os endpoints. O Keycloak foi configurado com TLS para garantir comunicações seguras.

### 5. Escopo de Tokens

Defina escopos adequados para as aplicações, seguindo o princípio do privilégio mínimo.

## Solução de Problemas Comuns

### 1. Problemas de DNS e Propagação

Se ocorrerem erros de DNS (como NXDOMAIN), verifique:

- A configuração do External-DNS no cluster
- A zona hospedada correta no Route53
- Propagação do DNS (pode levar até 48h, mas geralmente é muito mais rápido)

### 2. Problemas com o Ingress

Se o Keycloak estiver rodando mas não acessível externamente:

- Verifique as anotações do Ingress para garantir que estão corretas
- Confirme que o certificado SSL está válido
- Verifique os logs do Nginx Ingress Controller

### 3. Problemas de Autenticação

Se houver problemas ao autenticar aplicações com Keycloak:

- Confirme que as configurações de redirecionamento estão corretas
- Verifique se os secrets de cliente estão configurados corretamente
- Analise os logs do Keycloak para mensagens de erro detalhadas
