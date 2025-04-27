# Keycloak - Documentação de Integração

Este documento fornece instruções detalhadas sobre como configurar e utilizar o Keycloak instalado no cluster Kubernetes para autenticação e autorização de aplicações.

## Visão Geral

O Keycloak é uma solução de gerenciamento de identidade e acesso (IAM) de código aberto que fornece Single Sign-On (SSO), autenticação e autorização para aplicações modernas e serviços.

Nesta instalação, o Keycloak está configurado com:

- TLS habilitado para comunicações seguras
- Ingress configurado para acesso externo via `keycloak.mixnarede.com.br`
- Configurações otimizadas para uso em ambiente de produção

## Acessando o Keycloak

### URL de Acesso

O Keycloak está disponível através da URL: `https://keycloak.mixnarede.com.br`

### Credenciais de Administrador

- **Usuário**: admin
- **Senha**: A senha definida durante a instalação via terraform.tfvars

## Configuração Inicial

### 1. Criando um Realm

Um Realm no Keycloak é um conceito que define um domínio protegido contendo usuários, aplicações, funções, grupos e outros detalhes.

1. Faça login na interface administrativa
2. Clique em "Create Realm"
3. Forneça um nome (ex: "app-realm")
4. Clique em "Create"

### 2. Configuração de Clientes

#### 2.1. Cliente para Frontend (NextJS)

1. No seu realm, clique em "Clients" no menu lateral
2. Clique em "Create client"
3. Configure o cliente:
   - Client ID: `frontend-app`
   - Client type: `Standard flow`
   - Client authentication: `OFF` (para aplicações SPA)
   - Habilite "Authorization"
   - Valid redirect URIs: `https://seu-frontend.com/*`
   - Web origins: `https://seu-frontend.com` (para CORS)
4. Salve o cliente

#### 2.2. Cliente para Backend (NestJS)

1. No seu realm, clique em "Clients" no menu lateral
2. Clique em "Create client"
3. Configure o cliente:
   - Client ID: `backend-api`
   - Client type: `Bearer-only` ou `Service accounts`
   - Client authentication: `ON` (para APIs protegidas)
   - Service accounts roles: `ON` (se o backend precisar acessar outras APIs)
4. Salve o cliente
5. Na aba "Credentials", copie o Client Secret gerado

### 3. Criação de Usuários

1. No seu realm, clique em "Users" no menu lateral
2. Clique em "Add user"
3. Preencha os campos necessários:
   - Username: nome de usuário
   - Email: endereço de email
   - First name/Last name: nome e sobrenome
4. Ative o usuário na aba "Details"
5. Na aba "Credentials", defina uma senha (desmarque "Temporary" se não quiser forçar troca de senha)

### 4. Definindo Roles (Papéis)

1. No menu lateral, clique em "Realm roles"
2. Clique em "Create role"
3. Defina roles como "user", "admin", etc.
4. Atribua roles aos usuários na aba "Role mapping" de cada usuário

## Integração com NextJS (Frontend)

### Configuração com NextAuth.js

1. Instale as dependências necessárias:

```bash
npm install next-auth keycloak-js
# ou
yarn add next-auth keycloak-js
```

2. Crie um arquivo para configuração do NextAuth:

```js
// pages/api/auth/[...nextauth].js
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
      // Persistir tokens no JWT
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
      return session;
    },
  },
  // Configurações de sessão
  session: {
    strategy: "jwt",
  },
});
```

3. Configure as variáveis de ambiente no arquivo `.env.local`:

```
KEYCLOAK_CLIENT_ID=frontend-app
KEYCLOAK_CLIENT_SECRET=seu-client-secret
KEYCLOAK_ISSUER=https://keycloak.mixnarede.com.br/realms/app-realm
NEXTAUTH_URL=https://seu-frontend.com
NEXTAUTH_SECRET=senha-longa-e-aleatoria
```

4. Configure o Provider em `_app.js`:

```jsx
import { SessionProvider } from "next-auth/react";

export default function App({ Component, pageProps }) {
  return (
    <SessionProvider session={pageProps.session}>
      <Component {...pageProps} />
    </SessionProvider>
  );
}
```

5. Implementação de login/logout em componentes:

```jsx
import { useSession, signIn, signOut } from "next-auth/react";

export default function NavBar() {
  const { data: session, status } = useSession();
  const loading = status === "loading";

  if (loading) return <div>Carregando...</div>;

  if (session) {
    return (
      <>
        <span>Olá, {session.user.name}!</span>
        <button onClick={() => signOut()}>Sair</button>
      </>
    );
  }

  return <button onClick={() => signIn("keycloak")}>Entrar</button>;
}
```

6. Protegendo rotas:

```jsx
// Em uma página protegida
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

export default function ProtectedPage({ session }) {
  return <div>Esta é uma página protegida</div>;
}
```

### Chamadas de API Autenticadas

Para fazer chamadas autenticadas para o backend:

```jsx
import { useSession } from "next-auth/react";

export default function Profile() {
  const { data: session } = useSession();
  const [userData, setUserData] = useState(null);

  useEffect(() => {
    if (session) {
      fetch("https://seu-backend.com/api/perfil", {
        headers: {
          Authorization: `Bearer ${session.accessToken}`,
        },
      })
        .then((res) => res.json())
        .then((data) => setUserData(data));
    }
  }, [session]);

  if (!session) return <p>Não autenticado</p>;

  return (
    <div>
      <h1>Perfil do Usuário</h1>
      {userData && <pre>{JSON.stringify(userData, null, 2)}</pre>}
    </div>
  );
}
```

## Integração com NestJS (Backend)

### Configuração da Autenticação JWT

1. Instale as dependências necessárias:

```bash
npm install @nestjs/passport passport passport-jwt jwks-rsa
# ou
yarn add @nestjs/passport passport passport-jwt jwks-rsa
```

2. Crie um módulo de autenticação:

```typescript
// auth/auth.module.ts
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

3. Implemente a estratégia JWT:

```typescript
// auth/jwt.strategy.ts
import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import * as jwksRsa from "jwks-rsa";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      audience: configService.get("KEYCLOAK_CLIENT_ID"),
      issuer: configService.get("KEYCLOAK_ISSUER"),
      algorithms: ["RS256"],
      secretOrKeyProvider: jwksRsa.passportJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: `${configService.get(
          "KEYCLOAK_ISSUER"
        )}/protocol/openid-connect/certs`,
      }),
    });
  }

  async validate(payload: any) {
    return {
      id: payload.sub,
      username: payload.preferred_username,
      email: payload.email,
      roles: payload.realm_access?.roles || [],
    };
  }
}
```

4. Crie um guard de autenticação JWT:

```typescript
// auth/jwt-auth.guard.ts
import { Injectable } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";

@Injectable()
export class JwtAuthGuard extends AuthGuard("jwt") {}
```

5. Crie um guard para verificar roles:

```typescript
// auth/roles.guard.ts
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
```

6. Crie um decorator para definir roles:

```typescript
// auth/roles.decorator.ts
import { SetMetadata } from "@nestjs/common";

export const Roles = (...roles: string[]) => SetMetadata("roles", roles);
```

7. Configure as variáveis de ambiente:

```
KEYCLOAK_ISSUER=https://keycloak.mixnarede.com.br/realms/app-realm
KEYCLOAK_CLIENT_ID=backend-api
```

8. Importe o módulo de autenticação no módulo principal:

```typescript
// app.module.ts
import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { AuthModule } from "./auth/auth.module";

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    AuthModule,
    // outros módulos...
  ],
})
export class AppModule {}
```

9. Use os guards em seus controllers:

```typescript
// users/users.controller.ts
import { Controller, Get, UseGuards } from "@nestjs/common";
import { JwtAuthGuard } from "../auth/jwt-auth.guard";
import { RolesGuard } from "../auth/roles.guard";
import { Roles } from "../auth/roles.decorator";
import { UsersService } from "./users.service";

@Controller("users")
export class UsersController {
  constructor(private usersService: UsersService) {}

  @UseGuards(JwtAuthGuard)
  @Get("profile")
  getProfile(@Req() req) {
    return req.user;
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles("admin")
  @Get()
  findAll() {
    return this.usersService.findAll();
  }
}
```

## Boas Práticas de Segurança

### 1. Gerenciamento de Sessões

- Configure tempos de expiração adequados:
  - Access tokens: 5-15 minutos (curto)
  - Refresh tokens: 8-24 horas (mais longo)
- Use refresh tokens para renovar automaticamente a sessão
- Implemente logout em todos os dispositivos quando necessário

### 2. Proteção Contra Ataques

- Ative a proteção CSRF no Keycloak
- Configure rate limiting para endpoints sensíveis
- Use HTTPS em todas as comunicações
- Implemente validação de entrada em todas as APIs

### 3. Gerenciamento de Permissões

- Siga o princípio do privilégio mínimo
- Organize usuários em grupos para facilitar o gerenciamento
- Utilize escopos específicos para limitar o acesso a recursos

### 4. Monitoramento e Auditoria

- Habilite o registro de eventos no Keycloak
- Configure alertas para tentativas de login suspeitas
- Implemente monitoramento proativo

## Solução de Problemas

### 1. Problemas de Redirecionamento

Se ocorrerem erros após o login com mensagens sobre redirecionamento inválido:

- Verifique se os URIs de redirecionamento estão configurados corretamente no cliente do Keycloak
- Confirme que as URLs estão exatamente iguais, incluindo protocolo e caracteres especiais

### 2. Erros de Token

Para problemas de validação de token:

- Verifique se o cliente está configurado corretamente (public vs confidential)
- Confirme que o issuer URL está correto, incluindo o nome do realm
- Verifique a assinatura do token usando bibliotecas como jwt.io

### 3. Problemas de CORS

Se houver erros de CORS:

- Verifique as configurações de Web Origins no cliente do Keycloak
- Configure corretamente os cabeçalhos CORS no seu backend
- Verifique se o protocolo (http/https) está correto nas configurações

### 4. Atualizações e Manutenção

Para atualizar o Keycloak:

- Faça backup das configurações e dados
- Siga um processo de atualização gradual
- Teste em ambiente de desenvolvimento primeiro
- Use a migração de banco de dados oficial do Keycloak

## Referências

- [Documentação Oficial do Keycloak](https://www.keycloak.org/documentation)
- [Integração NextAuth.js com Keycloak](https://next-auth.js.org/providers/keycloak)
- [Guia NestJS de Autenticação](https://docs.nestjs.com/security/authentication)
- [Repositório do Helm Chart do Keycloak](https://github.com/bitnami/charts/tree/main/bitnami/keycloak)
