# API Contracts: User Authentication

**Feature**: 001-user-authentication
**Date**: 2025-10-21
**Version**: 1.0.0
**Base URL**: `/api/auth`

## Overview

This document defines the RESTful API contracts for the user authentication system. All endpoints follow standard HTTP conventions, use JSON for request/response bodies, and implement proper error handling with descriptive status codes.

## Authentication

Most authentication endpoints are **public** (no authentication required). Protected endpoints that require authentication will be clearly marked.

### Token Flow
1. User registers or logs in → Receives `accessToken` + `refreshToken`
2. Access token stored in httpOnly cookie (expires in 1 hour)
3. Refresh token stored in httpOnly cookie (expires in 7 days)
4. Client includes cookies automatically on subsequent requests
5. When access token expires, use refresh endpoint to get new access token

## Common Headers

### Request Headers
```
Content-Type: application/json
```

### Response Headers
```
Content-Type: application/json
Set-Cookie: accessToken=<jwt>; HttpOnly; Secure; SameSite=Lax; Path=/
Set-Cookie: refreshToken=<jwt>; HttpOnly; Secure; SameSite=Lax; Path=/
```

## Error Response Format

All error responses follow this structure:

```typescript
{
  "error": {
    "code": string,        // Error code (e.g., "VALIDATION_ERROR")
    "message": string,     // Human-readable error message
    "details"?: unknown    // Optional additional details (e.g., field errors)
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Invalid request data |
| `AUTHENTICATION_ERROR` | 401 | Invalid credentials or token |
| `UNAUTHORIZED` | 401 | Authentication required |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `CONFLICT` | 409 | Resource already exists |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |

---

## Endpoints

### 1. Register User

**POST** `/api/auth/register`

Create a new user account with email and password.

#### Request Body

```typescript
{
  "email": string,     // Valid email address
  "password": string   // Min 8 chars, letters + numbers
}
```

**Example**:
```json
{
  "email": "newuser@example.com",
  "password": "SecurePass123"
}
```

#### Success Response

**Status**: `201 Created`

```typescript
{
  "data": {
    "user": {
      "id": string,
      "email": string,
      "createdAt": string  // ISO 8601 datetime
    },
    "accessToken": string,
    "refreshToken": string
  }
}
```

**Example**:
```json
{
  "data": {
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "newuser@example.com",
      "createdAt": "2025-10-21T14:30:00.000Z"
    },
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

#### Error Responses

**Status**: `400 Bad Request` - Invalid input
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": {
      "email": ["Invalid email format"],
      "password": ["Password must be at least 8 characters"]
    }
  }
}
```

**Status**: `409 Conflict` - Email already registered
```json
{
  "error": {
    "code": "CONFLICT",
    "message": "Email already registered"
  }
}
```

**Status**: `429 Too Many Requests` - Rate limit exceeded
```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many registration attempts. Please try again in 60 minutes."
  }
}
```

#### Validation Rules
- Email must be valid format (RFC 5322)
- Email is case-insensitive (converted to lowercase)
- Password minimum 8 characters
- Password must contain at least one letter
- Password must contain at least one number

---

### 2. Login User

**POST** `/api/auth/login`

Authenticate existing user with email and password.

#### Request Body

```typescript
{
  "email": string,
  "password": string
}
```

**Example**:
```json
{
  "email": "user@example.com",
  "password": "SecurePass123"
}
```

#### Success Response

**Status**: `200 OK`

```typescript
{
  "data": {
    "user": {
      "id": string,
      "email": string,
      "lastLoginAt": string  // ISO 8601 datetime
    },
    "accessToken": string,
    "refreshToken": string
  }
}
```

**Example**:
```json
{
  "data": {
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "user@example.com",
      "lastLoginAt": "2025-10-21T14:30:00.000Z"
    },
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
}
```

#### Error Responses

**Status**: `401 Unauthorized` - Invalid credentials
```json
{
  "error": {
    "code": "AUTHENTICATION_ERROR",
    "message": "Invalid email or password"
  }
}
```

**Note**: Same error message for wrong email OR wrong password (prevents user enumeration)

**Status**: `429 Too Many Requests` - Rate limit exceeded
```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many login attempts. Please try again in 15 minutes.",
    "details": {
      "retryAfter": 900  // Seconds until retry allowed
    }
  }
}
```

#### Rate Limiting
- Maximum 5 failed attempts per 15 minutes per email
- Exponential backoff: 1st = 0s, 2nd = 5s, 3rd = 15s, 4th = 60s, 5th = 300s
- Counter resets on successful login

---

### 3. Logout User

**POST** `/api/auth/logout`

Terminate user session and invalidate tokens.

#### Request Body

```typescript
{
  "refreshToken"?: string  // Optional if using cookies
}
```

**Example**:
```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Success Response

**Status**: `200 OK`

```typescript
{
  "data": {
    "success": true,
    "message": string
  }
}
```

**Example**:
```json
{
  "data": {
    "success": true,
    "message": "Logged out successfully"
  }
}
```

**Cookies**: Both `accessToken` and `refreshToken` cookies are cleared

#### Error Responses

**Status**: `401 Unauthorized` - Invalid token
```json
{
  "error": {
    "code": "AUTHENTICATION_ERROR",
    "message": "Invalid or expired token"
  }
}
```

**Note**: Logout succeeds even if token is already invalid (idempotent operation)

---

### 4. Refresh Access Token

**POST** `/api/auth/refresh`

Issue new access token using valid refresh token.

#### Request Body

```typescript
{
  "refreshToken"?: string  // Optional if using cookies
}
```

**Example**:
```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Success Response

**Status**: `200 OK`

```typescript
{
  "data": {
    "accessToken": string,
    "expiresIn": number  // Seconds until expiration
  }
}
```

**Example**:
```json
{
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresIn": 3600
  }
}
```

#### Error Responses

**Status**: `401 Unauthorized` - Invalid or expired refresh token
```json
{
  "error": {
    "code": "AUTHENTICATION_ERROR",
    "message": "Invalid or expired refresh token"
  }
}
```

**Status**: `401 Unauthorized` - Missing refresh token
```json
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Refresh token required"
  }
}
```

---

### 5. Request Password Reset

**POST** `/api/auth/reset-password/request`

Request password reset link via email.

#### Request Body

```typescript
{
  "email": string
}
```

**Example**:
```json
{
  "email": "user@example.com"
}
```

#### Success Response

**Status**: `200 OK`

```typescript
{
  "data": {
    "success": true,
    "message": string
  }
}
```

**Example**:
```json
{
  "data": {
    "success": true,
    "message": "If the email exists, a reset link has been sent"
  }
}
```

**Note**: Same response for existing/non-existing email (prevents user enumeration)

**Email Sent**: If email exists, user receives email with reset link:
```
Subject: Reset Your Password

Click the link below to reset your password:
https://example.com/reset-password?token=770e8400-e29b-41d4-a716-446655440002

This link expires in 1 hour.
```

#### Error Responses

**Status**: `400 Bad Request` - Invalid email format
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid email format"
  }
}
```

**Status**: `429 Too Many Requests` - Rate limit exceeded
```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many reset requests. Please try again in 60 minutes."
  }
}
```

#### Rate Limiting
- Maximum 3 requests per hour per email
- Prevents email bombing attacks

---

### 6. Confirm Password Reset

**POST** `/api/auth/reset-password/confirm`

Reset password using valid reset token.

#### Request Body

```typescript
{
  "token": string,      // UUID from email link
  "newPassword": string // Min 8 chars, letters + numbers
}
```

**Example**:
```json
{
  "token": "770e8400-e29b-41d4-a716-446655440002",
  "newPassword": "NewSecurePass456"
}
```

#### Success Response

**Status**: `200 OK`

```typescript
{
  "data": {
    "success": true,
    "message": string
  }
}
```

**Example**:
```json
{
  "data": {
    "success": true,
    "message": "Password reset successfully"
  }
}
```

**Side Effects**:
- Password is updated
- Reset token is marked as used
- All existing sessions are invalidated (user must login again)

#### Error Responses

**Status**: `400 Bad Request` - Invalid token format
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid token format"
  }
}
```

**Status**: `400 Bad Request` - Invalid password
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid password",
    "details": {
      "password": ["Password must be at least 8 characters", "Password must contain at least one letter"]
    }
  }
}
```

**Status**: `400 Bad Request` - Expired or used token
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid or expired reset token"
  }
}
```

---

### 7. Validate Token (Protected)

**GET** `/api/auth/validate`

Validate current access token and return user info.

**Authentication**: Required (access token in cookie or Authorization header)

#### Request Headers
```
Cookie: accessToken=<jwt>
// OR
Authorization: Bearer <jwt>
```

#### Success Response

**Status**: `200 OK`

```typescript
{
  "data": {
    "valid": true,
    "user": {
      "id": string,
      "email": string
    },
    "expiresAt": string  // ISO 8601 datetime
  }
}
```

**Example**:
```json
{
  "data": {
    "valid": true,
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "user@example.com"
    },
    "expiresAt": "2025-10-21T15:30:00.000Z"
  }
}
```

#### Error Responses

**Status**: `401 Unauthorized` - Missing token
```json
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Authentication required"
  }
}
```

**Status**: `401 Unauthorized` - Invalid or expired token
```json
{
  "error": {
    "code": "AUTHENTICATION_ERROR",
    "message": "Invalid or expired token"
  }
}
```

---

## Data Types

### User (Response)
```typescript
interface User {
  id: string;              // UUID v4
  email: string;           // Lowercase email
  createdAt?: string;      // ISO 8601 datetime
  lastLoginAt?: string;    // ISO 8601 datetime
}
```

### Tokens
```typescript
interface Tokens {
  accessToken: string;     // JWT (1 hour expiration)
  refreshToken: string;    // JWT (7 days expiration)
}
```

### JWT Payload
```typescript
interface JWTPayload {
  userId: string;
  email: string;
  iat: number;  // Issued at (Unix timestamp)
  exp: number;  // Expires at (Unix timestamp)
}
```

## Security Considerations

### 1. Password Security
- Passwords are never returned in responses
- Passwords are hashed with bcrypt (12 salt rounds)
- Password validation enforced on client and server

### 2. Token Security
- Tokens stored in httpOnly cookies (not accessible via JavaScript)
- Secure flag set in production (HTTPS only)
- SameSite=Lax for CSRF protection
- Short-lived access tokens (1 hour)
- Longer refresh tokens for UX (7 days)

### 3. Error Messages
- Generic error messages to prevent user enumeration
- "Invalid email or password" (not "Email not found")
- "If email exists..." (for password reset)

### 4. Rate Limiting
- Login: 5 attempts per 15 minutes
- Registration: 3 attempts per hour per IP
- Password reset: 3 attempts per hour per email

### 5. HTTPS Enforcement
- All endpoints require HTTPS in production
- Cookies have Secure flag in production

### 6. CORS
- CORS configured to allow only authorized origins
- Credentials (cookies) allowed for same-origin requests

## Example Flows

### Registration + Login Flow
```
1. POST /api/auth/register
   → 201 Created
   → Cookies set: accessToken, refreshToken
   → Redirect to /dashboard

2. User navigates to /dashboard
   → Middleware validates accessToken
   → Access granted

3. 1 hour later, accessToken expires
   → Request to protected resource fails (401)
   → Client calls POST /api/auth/refresh
   → 200 OK with new accessToken
   → Retry original request
```

### Password Reset Flow
```
1. POST /api/auth/reset-password/request
   Body: { email: "user@example.com" }
   → 200 OK
   → Email sent with reset link

2. User clicks link: https://app.com/reset-password?token=<uuid>

3. POST /api/auth/reset-password/confirm
   Body: { token: "<uuid>", newPassword: "NewPass123" }
   → 200 OK
   → Password updated
   → Redirect to /login

4. POST /api/auth/login
   Body: { email: "user@example.com", password: "NewPass123" }
   → 200 OK
   → Access granted
```

### Logout Flow
```
1. POST /api/auth/logout
   → 200 OK
   → Cookies cleared
   → Redirect to /login

2. Attempt to access /dashboard
   → Middleware checks accessToken
   → No token found
   → Redirect to /login
```

## Testing

### cURL Examples

#### Register
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPass123"}' \
  -c cookies.txt
```

#### Login
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPass123"}' \
  -c cookies.txt
```

#### Validate (with cookies)
```bash
curl -X GET http://localhost:3000/api/auth/validate \
  -b cookies.txt
```

#### Refresh
```bash
curl -X POST http://localhost:3000/api/auth/refresh \
  -b cookies.txt
```

#### Logout
```bash
curl -X POST http://localhost:3000/api/auth/logout \
  -b cookies.txt
```

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-10-21 | Initial API contract definition |

## References

- [REST API Design Best Practices](https://restfulapi.net/)
- [HTTP Status Codes](https://httpstatuses.com/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
