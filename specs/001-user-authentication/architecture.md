# Architecture: User Authentication System

**Feature**: 001-user-authentication
**Date**: 2025-10-21
**Status**: Design Phase

## Overview

The authentication system provides secure user registration, login, session management, and password reset functionality using JWT-based authentication with bcrypt password hashing. The architecture follows a layered approach with clear separation between presentation (React components), API layer (Next.js routes), business logic (lib utilities), and data access (Prisma ORM).

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         Client Layer                            │
│  ┌────────────────┐  ┌────────────────┐  ┌──────────────────┐  │
│  │  Login Form    │  │ Register Form  │  │ Reset Password   │  │
│  │  Component     │  │  Component     │  │  Form Component  │  │
│  └────────┬───────┘  └────────┬───────┘  └────────┬─────────┘  │
│           │                   │                    │             │
│           └───────────────────┼────────────────────┘             │
│                               │                                  │
└───────────────────────────────┼──────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Middleware Layer                           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Next.js Middleware (middleware.ts)                      │   │
│  │  - Validates JWT tokens                                  │   │
│  │  - Protects routes in (dashboard) group                  │   │
│  │  - Redirects unauthenticated users to /login             │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                         API Layer                               │
│  ┌────────────┐ ┌───────────┐ ┌────────────┐ ┌──────────────┐  │
│  │  Register  │ │   Login   │ │   Logout   │ │ Reset Pass   │  │
│  │  Route     │ │   Route   │ │   Route    │ │ Route        │  │
│  └─────┬──────┘ └─────┬─────┘ └─────┬──────┘ └──────┬───────┘  │
│        │              │              │               │          │
│        └──────────────┼──────────────┼───────────────┘          │
│                       │              │                          │
└───────────────────────┼──────────────┼──────────────────────────┘
                        │              │
                        ▼              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Business Logic Layer                        │
│  ┌─────────────────┐  ┌──────────────────┐  ┌────────────────┐ │
│  │ Password Utils  │  │  Token Utils     │  │ Rate Limiter   │ │
│  │ - hash()        │  │  - generate()    │  │ - checkLimit() │ │
│  │ - verify()      │  │  - validate()    │  │ - increment()  │ │
│  │ - validate()    │  │  - refresh()     │  │                │ │
│  └────────┬────────┘  └────────┬─────────┘  └────────┬───────┘ │
│           │                    │                      │         │
└───────────┼────────────────────┼──────────────────────┼─────────┘
            │                    │                      │
            └────────────────────┼──────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Data Access Layer                          │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Prisma ORM                                              │   │
│  │  - User model                                            │   │
│  │  - Session model (via tokens)                            │   │
│  │  - PasswordResetToken model                              │   │
│  └────────────────────────┬─────────────────────────────────┘   │
└───────────────────────────┼─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Database Layer                            │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  SQLite Database                                         │   │
│  │  Tables: users, password_reset_tokens                    │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Component Architecture

### 1. Client Layer (React Components)

**Location**: `components/features/auth/`, `app/(auth)/`

**Responsibilities**:
- Render authentication forms (login, register, reset password)
- Client-side form validation (React Hook Form + Zod)
- Handle user interactions
- Display error messages
- Redirect on successful authentication

**Key Components**:
- `LoginForm`: Email/password login with validation
- `RegisterForm`: New user registration with password strength indicator
- `ResetPasswordForm`: Password reset request and confirmation

**Data Flow**:
1. User submits form
2. Client-side validation (Zod schema)
3. API request to backend
4. Handle response (success → redirect, error → display message)

### 2. Middleware Layer

**Location**: `app/middleware.ts`

**Responsibilities**:
- Intercept requests to protected routes
- Validate JWT access tokens
- Extract user context from tokens
- Redirect unauthenticated users to login
- Attach user info to request headers

**Execution Flow**:
```typescript
Request → Middleware → Check Token → Valid? → Continue : Redirect to /login
```

**Protected Routes Pattern**:
```typescript
export const config = {
  matcher: ['/dashboard/:path*', '/profile/:path*'],
};
```

### 3. API Layer (Next.js Route Handlers)

**Location**: `app/api/auth/`

**Endpoints**:

#### POST /api/auth/register
- **Purpose**: Create new user account
- **Input**: `{ email, password }`
- **Validation**: Zod schema (email format, password strength)
- **Process**:
  1. Validate input
  2. Check email uniqueness
  3. Hash password (bcrypt, 12 rounds)
  4. Create user in database
  5. Generate access + refresh tokens
  6. Return tokens
- **Output**: `{ accessToken, refreshToken, user: { id, email } }`
- **Errors**: 400 (validation), 409 (duplicate email)

#### POST /api/auth/login
- **Purpose**: Authenticate existing user
- **Input**: `{ email, password }`
- **Process**:
  1. Rate limiting check
  2. Find user by email
  3. Verify password (bcrypt.compare)
  4. Generate tokens
  5. Update last login timestamp
  6. Return tokens
- **Output**: `{ accessToken, refreshToken, user: { id, email } }`
- **Errors**: 401 (invalid credentials), 429 (rate limit)

#### POST /api/auth/logout
- **Purpose**: Invalidate user session
- **Input**: `{ refreshToken }`
- **Process**:
  1. Validate refresh token
  2. Add token to blacklist (if implemented)
  3. Clear client-side tokens
- **Output**: `{ success: true }`
- **Errors**: 401 (invalid token)

#### POST /api/auth/refresh
- **Purpose**: Issue new access token
- **Input**: `{ refreshToken }`
- **Process**:
  1. Validate refresh token
  2. Extract user ID
  3. Generate new access token
  4. Return new access token
- **Output**: `{ accessToken }`
- **Errors**: 401 (invalid/expired token)

#### POST /api/auth/reset-password
- **Purpose**: Request password reset or reset password
- **Input**:
  - Request: `{ email }`
  - Reset: `{ token, newPassword }`
- **Process** (Request):
  1. Find user by email
  2. Generate reset token (UUID)
  3. Store token with expiration (1 hour)
  4. Send email with reset link
  5. Return success (even if email not found - prevent enumeration)
- **Process** (Reset):
  1. Validate reset token
  2. Check expiration
  3. Hash new password
  4. Update user password
  5. Invalidate reset token
  6. Return success
- **Output**: `{ success: true }`
- **Errors**: 400 (invalid token/expired), 404 (user not found)

### 4. Business Logic Layer

**Location**: `lib/auth/`

#### Password Utilities (`lib/auth/password.ts`)
```typescript
export async function hashPassword(password: string): Promise<string>
export async function verifyPassword(password: string, hash: string): Promise<boolean>
export function validatePasswordStrength(password: string): { valid: boolean; errors: string[] }
```

**Password Requirements**:
- Minimum 8 characters
- At least one letter
- At least one number
- Optional: special character (not enforced)

#### Token Utilities (`lib/auth/tokens.ts`)
```typescript
export function generateAccessToken(userId: string): string
export function generateRefreshToken(userId: string): string
export function validateToken(token: string): { valid: boolean; payload?: JWTPayload }
export function decodeToken(token: string): JWTPayload | null
```

**Token Structure**:
```typescript
interface JWTPayload {
  userId: string;
  email: string;
  iat: number;  // Issued at
  exp: number;  // Expiration
}
```

**Token Configuration**:
- Access Token: 1 hour expiration, signed with JWT_SECRET
- Refresh Token: 7 days expiration, signed with JWT_REFRESH_SECRET
- Algorithm: HS256 (HMAC SHA-256)

#### Session Utilities (`lib/auth/session.ts`)
```typescript
export function setAuthCookies(accessToken: string, refreshToken: string): void
export function clearAuthCookies(): void
export function getAuthTokens(): { accessToken?: string; refreshToken?: string }
```

**Cookie Configuration**:
- httpOnly: true (prevent XSS)
- secure: true (HTTPS only in production)
- sameSite: 'lax' (CSRF protection)
- path: '/'

#### Rate Limiter (`lib/auth/rate-limit.ts`)
```typescript
export async function checkRateLimit(identifier: string, action: string): Promise<boolean>
export async function incrementRateLimit(identifier: string, action: string): Promise<void>
```

**Rate Limiting Strategy**:
- Identifier: IP address or email
- Action types: 'login', 'register', 'reset-password'
- Login: 5 attempts per 15 minutes, exponential backoff
- Register: 3 attempts per hour per IP
- Reset Password: 3 attempts per hour per email

**Implementation**: In-memory store (Map) for MVP, can be replaced with Redis for production

#### Audit Logger (`lib/auth/audit-logger.ts`)
```typescript
export interface AuthAuditLog {
  timestamp: Date;
  event: 'login' | 'login_failed' | 'register' | 'logout' | 'password_reset_request' | 'password_reset_confirm';
  userId?: string;
  email?: string;
  ipAddress: string;
  userAgent: string;
  success: boolean;
  failureReason?: string;
}

export async function logAuthEvent(log: AuthAuditLog): Promise<void>
export async function getAuditLogs(filters: AuditLogFilters): Promise<AuthAuditLog[]>
```

**Audit Logging Strategy** (FR-017 requirement):
- Event Types: login, login_failed, register, logout, password_reset_request, password_reset_confirm
- Storage: Database table (audit_logs) for persistence
- Retention: 90 days minimum
- Fields: timestamp, event type, user ID, email, IP address, user agent, success flag, failure reason
- Alerting: Monitor for suspicious patterns (10+ failed logins, mass registration, etc.)

**Security Purpose**:
- Detect brute force attacks
- Investigate security incidents
- Compliance requirements (GDPR, SOC2)
- User activity monitoring

### 5. Data Access Layer

**Location**: `prisma/schema.prisma`, `lib/db/prisma.ts`

**Prisma Client Singleton**:
```typescript
// lib/db/prisma.ts
import { PrismaClient } from '@prisma/client';

const globalForPrisma = global as unknown as { prisma: PrismaClient };

export const prisma = globalForPrisma.prisma || new PrismaClient();

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma;
```

**Data Models** (see data-model.md for full schema):
- User
- PasswordResetToken

### 6. Validation Layer

**Location**: `lib/validations/auth.ts`

**Zod Schemas**:
```typescript
export const RegisterSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).regex(/[a-zA-Z]/).regex(/[0-9]/),
});

export const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

export const ResetPasswordRequestSchema = z.object({
  email: z.string().email(),
});

export const ResetPasswordConfirmSchema = z.object({
  token: z.string().uuid(),
  newPassword: z.string().min(8).regex(/[a-zA-Z]/).regex(/[0-9]/),
});
```

## Security Architecture

### 1. Password Security
- **Hashing Algorithm**: bcrypt with 12 salt rounds
- **Storage**: Only hashed passwords stored, never plaintext
- **Validation**: Server-side only (never trust client)
- **Timing Attack Prevention**: Use constant-time comparison (bcrypt.compare)

### 2. Token Security
- **JWT Secret**: Stored in environment variables
- **Separate Secrets**: Different secrets for access/refresh tokens
- **Token Rotation**: Refresh tokens can be rotated on use
- **Expiration**: Short-lived access tokens, longer refresh tokens
- **Storage**: httpOnly cookies (not accessible via JavaScript)

### 3. Session Security
- **Cookie Attributes**: httpOnly, secure, sameSite
- **CSRF Protection**: Next.js built-in CSRF protection + sameSite cookies
- **Session Timeout**: 24 hours of inactivity
- **Concurrent Sessions**: Allow multiple devices (store multiple refresh tokens)

### 4. Rate Limiting
- **Brute Force Protection**: Limit login attempts
- **Registration Spam**: Limit account creation per IP
- **Password Reset Abuse**: Limit reset requests per email
- **Exponential Backoff**: Increasing delays after failed attempts

### 5. Input Validation
- **Client-Side**: Zod validation for user feedback
- **Server-Side**: Zod validation at API boundary (never trust client)
- **Sanitization**: Trim inputs, normalize email (lowercase)
- **SQL Injection Prevention**: Prisma ORM (parameterized queries)

### 6. Error Handling
- **Generic Errors**: Don't reveal which field is incorrect
  - ❌ "Email not found"
  - ✅ "Invalid email or password"
- **User Enumeration Prevention**: Same response for existing/non-existing users
- **Detailed Logging**: Server-side logs for debugging (never log passwords)

### 7. OWASP Top 10 Compliance
1. **Broken Access Control**: ✅ Middleware validates all protected routes
2. **Cryptographic Failures**: ✅ bcrypt hashing, HTTPS enforced
3. **Injection**: ✅ Prisma ORM prevents SQL injection
4. **Insecure Design**: ✅ Rate limiting, secure token design
5. **Security Misconfiguration**: ✅ Security headers, no debug in production
6. **Vulnerable Components**: ✅ Dependency audit (npm audit)
7. **Authentication Failures**: ✅ Strong passwords, secure sessions
8. **Software & Data Integrity**: ✅ Input validation, no eval()
9. **Logging Failures**: ✅ Audit logging for auth events
10. **SSRF**: ✅ N/A (no external URL fetching in auth)

## Data Flow Diagrams

### Registration Flow
```
User → Register Form → Client Validation → API /auth/register
  ↓
Validate Input (Zod)
  ↓
Check Email Uniqueness (Prisma)
  ↓
Hash Password (bcrypt)
  ↓
Create User (Prisma)
  ↓
Generate Tokens (JWT)
  ↓
Set Cookies
  ↓
Return Success → Redirect to Dashboard
```

### Login Flow
```
User → Login Form → Client Validation → API /auth/login
  ↓
Rate Limit Check
  ↓
Validate Input (Zod)
  ↓
Find User by Email (Prisma)
  ↓
Verify Password (bcrypt)
  ↓
Generate Tokens (JWT)
  ↓
Update Last Login (Prisma)
  ↓
Set Cookies
  ↓
Return Success → Redirect to Dashboard
```

### Protected Route Access Flow
```
User → Access /dashboard → Middleware
  ↓
Extract Token from Cookie
  ↓
Validate Token (JWT)
  ↓
Token Valid? → Yes → Continue to Page
             → No → Redirect to /login
```

### Token Refresh Flow
```
Access Token Expired → API Request Fails
  ↓
Client Detects 401
  ↓
Call /auth/refresh with Refresh Token
  ↓
Validate Refresh Token
  ↓
Generate New Access Token
  ↓
Set New Cookie
  ↓
Retry Original Request
```

### Password Reset Flow
```
User → Reset Form → Enter Email → API /auth/reset-password
  ↓
Find User (or return success anyway)
  ↓
Generate Reset Token (UUID)
  ↓
Store Token with Expiration (1 hour)
  ↓
Send Email with Link
  ↓
User Clicks Link → Reset Form → Enter New Password
  ↓
Validate Token + Expiration
  ↓
Hash New Password
  ↓
Update User Password
  ↓
Invalidate Token
  ↓
Return Success → Redirect to Login
```

## Technology Decisions

### Why bcrypt over Argon2?
- **Maturity**: bcrypt is battle-tested (20+ years)
- **Ecosystem**: Better Node.js support (7.8k stars)
- **Sufficient Security**: 12 rounds provides adequate protection
- **Constitution Compliance**: Meets open-source criteria
- **Trade-off**: Argon2 is newer/stronger but less mature in Node.js

### Why JWT over Session Cookies?
- **Stateless**: No server-side session storage required
- **Scalability**: Easier to scale horizontally
- **Mobile-Friendly**: Works well with mobile apps
- **Flexibility**: Can include custom claims
- **Trade-off**: Can't invalidate tokens without blacklist

### Why Dual Token Strategy?
- **Security**: Short-lived access tokens limit exposure
- **UX**: Long-lived refresh tokens avoid frequent logins
- **Best Practice**: Industry standard (OAuth 2.0 pattern)
- **Balance**: Optimal security-usability trade-off

### Why SQLite over PostgreSQL?
- **Simplicity**: No external dependencies for local development
- **Constitution Alignment**: Simple architecture for simple app
- **Testing**: Easy to reset between tests
- **Migration Path**: Can migrate to PostgreSQL later
- **Trade-off**: Limited concurrency, single-user focus

### Why In-Memory Rate Limiting (MVP)?
- **Simplicity**: No external dependencies
- **Sufficient**: Works for single-instance deployment
- **Fast**: No network latency
- **Upgradable**: Can swap to Redis later
- **Trade-off**: Doesn't work across multiple instances

## Performance Considerations

### Response Time Targets
- **Login**: <200ms (p95)
- **Register**: <300ms (p95, includes hashing)
- **Token Validation**: <100ms (p99)
- **Password Reset Request**: <200ms (p95)

### Optimization Strategies
1. **Password Hashing**: Use bcrypt's async API (non-blocking)
2. **Database Queries**: Index email field for fast lookups
3. **Token Validation**: Cache public key for JWT verification
4. **Rate Limiting**: In-memory store for fast checks
5. **Client-Side**: Validate before API call to reduce load

### Scalability Considerations
- **Horizontal Scaling**: JWT tokens are stateless
- **Rate Limiting**: Replace in-memory store with Redis for multi-instance
- **Session Storage**: Consider Redis for token blacklist
- **Database**: Migrate to PostgreSQL for production load
- **Caching**: Add Redis for frequently accessed user data

## Testing Strategy

### Unit Tests (95%+ coverage)
- Password utilities (hashing, validation)
- Token utilities (generation, validation)
- Validation schemas (Zod)
- Rate limiting logic

### Integration Tests (90%+ coverage)
- Registration endpoint (success, duplicate email, validation errors)
- Login endpoint (success, wrong password, rate limiting)
- Logout endpoint
- Refresh endpoint
- Password reset endpoint

### E2E Tests (Critical flows)
- Complete registration → login → access protected route → logout
- Failed login → error message
- Password reset request → email → reset → login
- Token expiration → redirect to login

### Security Tests (100% coverage on auth flows)
- Brute force attack simulation
- SQL injection attempts
- XSS attempts in email/password fields
- CSRF token validation
- Token tampering detection

## Error Scenarios

| Scenario | HTTP Status | Response | User Experience |
|----------|-------------|----------|-----------------|
| Invalid email format | 400 | Validation error | Inline error message |
| Weak password | 400 | Validation error | Password requirements shown |
| Duplicate email | 409 | Conflict error | "Email already registered" |
| Invalid credentials | 401 | Auth error | "Invalid email or password" |
| Rate limit exceeded | 429 | Too many requests | "Too many attempts, try again in X minutes" |
| Expired token | 401 | Auth error | Redirect to login |
| Invalid reset token | 400 | Validation error | "Invalid or expired reset link" |
| Server error | 500 | Internal error | "Something went wrong, please try again" |

## Deployment Considerations

### Environment Variables
```bash
DATABASE_URL="file:./dev.db"
JWT_SECRET="[secure random string]"
JWT_REFRESH_SECRET="[different secure random string]"
SMTP_HOST="smtp.example.com"
SMTP_PORT="587"
SMTP_USER="[email]"
SMTP_PASS="[password]"
NODE_ENV="production"
```

### Security Headers (Next.js middleware)
```typescript
headers: {
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
}
```

### Database Migrations
```bash
# Development
npx prisma migrate dev --name init-auth

# Production
npx prisma migrate deploy
```

## Future Enhancements (Out of Scope for MVP)

1. **Two-Factor Authentication (2FA)**: TOTP-based 2FA
2. **OAuth Integration**: Google, GitHub, Facebook login
3. **Email Verification**: Verify email on registration
4. **Account Deletion**: GDPR compliance
5. **Login History**: Track devices and locations
6. **Magic Links**: Passwordless authentication
7. **Biometric Authentication**: WebAuthn support
8. **Admin Panel**: User management dashboard
9. **Advanced Rate Limiting**: Per-user, per-endpoint limits
10. **Token Blacklist**: Redis-based token revocation

## Appendix

### Glossary
- **JWT**: JSON Web Token - compact, self-contained token for authentication
- **bcrypt**: Password hashing function based on Blowfish cipher
- **CSRF**: Cross-Site Request Forgery - attack forcing authenticated users to execute unwanted actions
- **XSS**: Cross-Site Scripting - injection attack inserting malicious scripts
- **OWASP**: Open Web Application Security Project - security standards organization
- **Rate Limiting**: Restricting the number of requests a user can make in a time period
- **Salt Rounds**: Number of iterations bcrypt uses (higher = slower but more secure)

### References
- [Next.js Authentication Best Practices](https://nextjs.org/docs/app/building-your-application/authentication)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [bcrypt Documentation](https://github.com/kelektiv/node.bcrypt.js)
- [Prisma Documentation](https://www.prisma.io/docs)
