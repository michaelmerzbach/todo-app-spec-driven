# Data Model: User Authentication System

**Feature**: 001-user-authentication
**Date**: 2025-10-21
**Database**: SQLite (via Prisma ORM)

## Overview

The authentication system uses two primary entities: **User** (representing user accounts) and **PasswordResetToken** (representing password reset requests). This document defines the complete database schema, relationships, validation rules, and indexes.

## Entity-Relationship Diagram

```
┌─────────────────────────────────────────┐
│              User                       │
├─────────────────────────────────────────┤
│ id: String (UUID) [PK]                  │
│ email: String [UNIQUE]                  │
│ password: String (hashed)               │
│ lastLoginAt: DateTime?                  │
│ createdAt: DateTime                     │
│ updatedAt: DateTime                     │
└───────┬───────────────┬─────────────────┘
        │               │
        │ 1:N           │ 1:N
        │               │
        ▼               ▼
┌─────────────────┐  ┌──────────────────────┐
│PasswordReset    │  │    AuthAuditLog      │
│     Token       │  │                      │
├─────────────────┤  ├──────────────────────┤
│ id: String [PK] │  │ id: String [PK]      │
│ token: String   │  │ event: String        │
│ userId: String  │  │ userId: String?      │
│ expiresAt: Date │  │ email: String?       │
│ used: Boolean   │  │ ipAddress: String    │
│ createdAt: Date │  │ userAgent: String    │
└─────────────────┘  │ success: Boolean     │
                     │ failureReason: Str?  │
                     │ timestamp: DateTime  │
                     └──────────────────────┘
```

## Prisma Schema

```prisma
// prisma/schema.prisma

generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "sqlite"
  url      = env("DATABASE_URL")
}

model User {
  id          String   @id @default(uuid())
  email       String   @unique
  password    String   // bcrypt hashed password
  lastLoginAt DateTime? @map("last_login_at")
  createdAt   DateTime @default(now()) @map("created_at")
  updatedAt   DateTime @updatedAt @map("updated_at")

  passwordResetTokens PasswordResetToken[]

  @@index([email])
  @@map("users")
}

model PasswordResetToken {
  id        String   @id @default(uuid())
  token     String   @unique @default(uuid())
  userId    String   @map("user_id")
  expiresAt DateTime @map("expires_at")
  used      Boolean  @default(false)
  createdAt DateTime @default(now()) @map("created_at")

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@index([token])
  @@index([userId])
  @@index([expiresAt])
  @@map("password_reset_tokens")
}
```

## Entity Definitions

### User

**Description**: Represents a registered user account with authentication credentials.

**Fields**:

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | String (UUID) | Primary Key, Auto-generated | Unique user identifier |
| `email` | String | Unique, Required, Indexed | User's email address (normalized to lowercase) |
| `password` | String | Required | bcrypt hashed password (never plaintext) |
| `lastLoginAt` | DateTime | Nullable | Timestamp of most recent successful login |
| `createdAt` | DateTime | Auto-generated, Default: now() | Account creation timestamp |
| `updatedAt` | DateTime | Auto-updated | Last modification timestamp |

**Relationships**:
- One-to-Many with `PasswordResetToken`: A user can have multiple reset tokens (only one active at a time)

**Validation Rules**:
- `email`: Must be valid email format (validated by Zod before DB insert)
- `email`: Converted to lowercase before storage (normalization)
- `password`: Must be bcrypt hash (validated by application logic)
- `password`: Never stored in plaintext
- `lastLoginAt`: Updated on each successful login

**Indexes**:
- Primary Index: `id` (automatic)
- Unique Index: `email` (for fast lookups and uniqueness constraint)

**Business Rules**:
1. Email must be unique across all users
2. Password must be hashed with bcrypt (12 salt rounds minimum)
3. Email is case-insensitive for comparison (stored lowercase)
4. User can only be created with valid email and strong password
5. Deleting a user cascades to delete all their password reset tokens

**Example Data**:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "password": "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5NU7K9h2QX9yK",
  "lastLoginAt": "2025-10-21T14:30:00Z",
  "createdAt": "2025-10-20T10:00:00Z",
  "updatedAt": "2025-10-21T14:30:00Z"
}
```

---

### PasswordResetToken

**Description**: Represents a time-limited token for password reset requests.

**Fields**:

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `id` | String (UUID) | Primary Key, Auto-generated | Unique token record identifier |
| `token` | String (UUID) | Unique, Auto-generated, Indexed | The actual reset token sent to user |
| `userId` | String (UUID) | Foreign Key → User.id, Required, Indexed | Reference to user requesting reset |
| `expiresAt` | DateTime | Required, Indexed | Token expiration timestamp (1 hour from creation) |
| `used` | Boolean | Default: false | Whether token has been used |
| `createdAt` | DateTime | Auto-generated, Default: now() | Token creation timestamp |

**Relationships**:
- Many-to-One with `User`: Each token belongs to one user
- Cascade Delete: Deleting user deletes all their tokens

**Validation Rules**:
- `token`: Must be unique UUID v4
- `expiresAt`: Must be 1 hour after `createdAt` (enforced by application)
- `used`: Can only transition from false → true (never back to false)
- `userId`: Must reference existing user

**Indexes**:
- Primary Index: `id` (automatic)
- Unique Index: `token` (for fast validation lookups)
- Index: `userId` (for querying user's tokens)
- Index: `expiresAt` (for efficient expiration cleanup)

**Business Rules**:
1. Token is valid for exactly 1 hour from creation
2. Token can only be used once (`used: true` after first use)
3. Expired tokens (`expiresAt < now()`) are invalid even if not used
4. User can have multiple tokens, but only the most recent unused/unexpired one is valid
5. Old tokens should be cleaned up periodically (cron job)

**Token Lifecycle States**:
```
Created → Valid (not expired, not used)
       ↓
       → Expired (expiresAt < now())
       ↓
       → Used (used: true)
       ↓
       → Invalid (expired OR used)
```

**Example Data**:
```json
{
  "id": "660e8400-e29b-41d4-a716-446655440001",
  "token": "770e8400-e29b-41d4-a716-446655440002",
  "userId": "550e8400-e29b-41d4-a716-446655440000",
  "expiresAt": "2025-10-21T15:30:00Z",
  "used": false,
  "createdAt": "2025-10-21T14:30:00Z"
}
```

## Database Migrations

### Initial Migration

```sql
-- CreateTable: users
CREATE TABLE "users" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "email" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "last_login_at" DATETIME,
    "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" DATETIME NOT NULL
);

-- CreateIndex: unique email
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex: email lookup
CREATE INDEX "users_email_idx" ON "users"("email");

-- CreateTable: password_reset_tokens
CREATE TABLE "password_reset_tokens" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "token" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "expires_at" DATETIME NOT NULL,
    "used" INTEGER NOT NULL DEFAULT 0,
    "created_at" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "password_reset_tokens_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateIndex: unique token
CREATE UNIQUE INDEX "password_reset_tokens_token_key" ON "password_reset_tokens"("token");

-- CreateIndex: token lookup
CREATE INDEX "password_reset_tokens_token_idx" ON "password_reset_tokens"("token");

-- CreateIndex: user tokens lookup
CREATE INDEX "password_reset_tokens_user_id_idx" ON "password_reset_tokens"("user_id");

-- CreateIndex: expiration cleanup
CREATE INDEX "password_reset_tokens_expires_at_idx" ON "password_reset_tokens"("expires_at");
```

## Data Access Patterns

### Common Queries

#### 1. Find User by Email (Login)
```typescript
const user = await prisma.user.findUnique({
  where: { email: email.toLowerCase() },
});
```

**Performance**: O(1) - Unique index on email
**Use Case**: User login, email uniqueness check

#### 2. Create User (Registration)
```typescript
const user = await prisma.user.create({
  data: {
    email: email.toLowerCase(),
    password: hashedPassword,
  },
});
```

**Use Case**: User registration

#### 3. Update Last Login
```typescript
await prisma.user.update({
  where: { id: userId },
  data: { lastLoginAt: new Date() },
});
```

**Use Case**: Track user activity on successful login

#### 4. Create Password Reset Token
```typescript
const resetToken = await prisma.passwordResetToken.create({
  data: {
    userId: user.id,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
  },
});
```

**Use Case**: User requests password reset

#### 5. Validate Reset Token
```typescript
const resetToken = await prisma.passwordResetToken.findUnique({
  where: { token: providedToken },
  include: { user: true },
});

const isValid = resetToken &&
                !resetToken.used &&
                resetToken.expiresAt > new Date();
```

**Performance**: O(1) - Unique index on token
**Use Case**: Validate reset token before password change

#### 6. Mark Token as Used
```typescript
await prisma.passwordResetToken.update({
  where: { id: resetToken.id },
  data: { used: true },
});
```

**Use Case**: Prevent token reuse after password reset

#### 7. Clean Up Expired Tokens (Cron Job)
```typescript
await prisma.passwordResetToken.deleteMany({
  where: {
    OR: [
      { expiresAt: { lt: new Date() } },
      { used: true },
    ],
  },
});
```

**Use Case**: Periodic cleanup to prevent database bloat

## Data Validation

### Application-Level Validation (Zod)

```typescript
// lib/validations/auth.ts
import { z } from 'zod';

export const UserSchema = z.object({
  email: z.string().email().toLowerCase(),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[a-zA-Z]/, 'Password must contain at least one letter')
    .regex(/[0-9]/, 'Password must contain at least one number'),
});

export const PasswordResetTokenSchema = z.object({
  token: z.string().uuid(),
  expiresAt: z.date().refine(
    (date) => date > new Date(),
    'Token must not be expired'
  ),
  used: z.boolean().refine(
    (used) => used === false,
    'Token has already been used'
  ),
});
```

### Database-Level Constraints

- **Uniqueness**: Email and reset token uniqueness enforced by database
- **Foreign Keys**: Cascade deletes maintain referential integrity
- **Required Fields**: NOT NULL constraints on required fields
- **Default Values**: Auto-populated for `createdAt`, `updatedAt`, `used`

## Security Considerations

### 1. Password Storage
- **Never** store plaintext passwords
- **Always** use bcrypt with ≥12 salt rounds
- **Never** log or expose hashed passwords in errors

### 2. Email Normalization
- Convert to lowercase before storage/comparison
- Prevents duplicate accounts (User@Example.com vs user@example.com)

### 3. Reset Token Security
- Use cryptographically secure UUID v4
- Tokens are single-use (marked as used)
- Short expiration time (1 hour)
- Token sent via secure channel (email)

### 4. Cascade Deletes
- Deleting user removes all their reset tokens
- Prevents orphaned data

### 5. Index Security
- Indexes on email and token speed up lookups
- Prevents timing attacks (constant-time lookups)

## Performance Optimization

### Indexes Strategy
1. **email** (unique): Fast user lookup on login
2. **token** (unique): Fast reset token validation
3. **userId**: Efficient user → tokens queries
4. **expiresAt**: Efficient expired token cleanup

### Query Optimization
- Use `findUnique` instead of `findFirst` when possible (faster)
- Include only necessary fields in queries (reduce payload)
- Use transactions for multi-step operations (consistency)

### Example Optimized Transaction
```typescript
await prisma.$transaction(async (tx) => {
  // Validate token
  const resetToken = await tx.passwordResetToken.findUnique({
    where: { token },
  });

  if (!resetToken || resetToken.used || resetToken.expiresAt < new Date()) {
    throw new Error('Invalid token');
  }

  // Update password and mark token as used
  await tx.user.update({
    where: { id: resetToken.userId },
    data: { password: newHashedPassword },
  });

  await tx.passwordResetToken.update({
    where: { id: resetToken.id },
    data: { used: true },
  });
});
```

## Data Retention

### Active Data
- **Users**: Retained indefinitely (or until account deletion)
- **Active Reset Tokens**: Retained for 1 hour

### Cleanup Strategy
- **Expired Tokens**: Delete tokens where `expiresAt < now()` (daily cron)
- **Used Tokens**: Delete tokens where `used = true` after 7 days (weekly cron)

### Future Considerations (Out of Scope)
- User account deletion (GDPR compliance)
- Data export functionality
- Audit logging for sensitive operations

## Sample Data (for Testing)

```typescript
// Test user
{
  email: "test@example.com",
  password: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5NU7K9h2QX9yK", // "Password123"
}

// Test reset token (valid)
{
  token: "550e8400-e29b-41d4-a716-446655440099",
  userId: "550e8400-e29b-41d4-a716-446655440000",
  expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  used: false,
}

// Test reset token (expired)
{
  token: "550e8400-e29b-41d4-a716-446655440088",
  userId: "550e8400-e29b-41d4-a716-446655440000",
  expiresAt: new Date(Date.now() - 60 * 60 * 1000),
  used: false,
}

// Test reset token (used)
{
  token: "550e8400-e29b-41d4-a716-446655440077",
  userId: "550e8400-e29b-41d4-a716-446655440000",
  expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  used: true,
}
```

## TypeScript Types (Generated by Prisma)

```typescript
export type User = {
  id: string;
  email: string;
  password: string;
  lastLoginAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
};

export type PasswordResetToken = {
  id: string;
  token: string;
  userId: string;
  expiresAt: Date;
  used: boolean;
  createdAt: Date;
};

// Prisma includes
export type UserWithTokens = User & {
  passwordResetTokens: PasswordResetToken[];
};

export type PasswordResetTokenWithUser = PasswordResetToken & {
  user: User;
};
```

## References

- [Prisma Schema Reference](https://www.prisma.io/docs/reference/api-reference/prisma-schema-reference)
- [SQLite Data Types](https://www.sqlite.org/datatype3.html)
- [bcrypt Best Practices](https://github.com/kelektiv/node.bcrypt.js#security-issues-and-concerns)
- [UUID v4 Specification](https://tools.ietf.org/html/rfc4122)
