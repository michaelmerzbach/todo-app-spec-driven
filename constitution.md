# Todo App - Project Constitution

**Version**: 1.0  
**Created**: October 19, 2025  
**Status**: Active

---

## 1. Project Overview

### 1.1 Purpose
A simple, secure personal task management application that demonstrates spec-driven development with AI agent orchestration.

### 1.2 Business Domain
- Personal task management for individual users
- CRUD operations for todo items
- User authentication and authorization
- Task organization and status tracking

### 1.3 Target Users
- Individual users managing personal tasks
- Primary use case: Daily task tracking and completion
- Secondary use case: Learning demonstration of spec-driven development workflow

---

## 2. Open Source Philosophy

### 2.1 General Principle
We prefer open source solutions over commercial/proprietary tooling to maximize flexibility, transparency, and community-driven innovation while minimizing vendor lock-in and licensing costs.

### 2.2 Open Source Evaluation Criteria

When evaluating open source tools, frameworks, or libraries, they must meet these quality standards:

#### Maturity & Adoption
- **GitHub Stars**: ≥ 1,000 stars (or proportional for niche tools)
- **Production Usage**: Evidence of production use by reputable organizations
- **Downloads/Usage**: Significant npm downloads (≥ 100k weekly) or equivalent metrics
- **Stack Overflow Activity**: Active community helping users solve problems

#### Active Development
- **Recent Commits**: Activity within last 3 months
- **Release Cadence**: Regular releases (at least quarterly for stable projects)
- **Responsive Maintainers**: Issues/PRs reviewed and addressed within reasonable time
- **Roadmap**: Clear vision and roadmap for future development

#### Quality & Stability
- **Documentation**: Comprehensive, up-to-date documentation with examples
- **Test Coverage**: Evidence of automated testing (visible CI/CD badges)
- **Semantic Versioning**: Follows semver for predictable upgrades
- **Breaking Changes**: Clear migration guides for major versions

#### Security & Compliance
- **Security Policy**: Has SECURITY.md or documented vulnerability reporting process
- **Known Vulnerabilities**: No unpatched critical/high severity CVEs
- **Dependency Health**: Dependencies are actively maintained
- **License Compatibility**: OSI-approved license (MIT, Apache 2.0, BSD, etc.)

#### Community Health
- **Contributors**: Multiple active contributors (not single maintainer)
- **Governance**: Clear governance model or backing organization
- **Code of Conduct**: Has CODE_OF_CONDUCT.md or equivalent
- **Issues Response**: Reasonable response time to issues (< 2 weeks for critical)

### 2.3 When to Consider Commercial Tools

Commercial tools may be justified when:
- Open source alternatives don't meet critical requirements
- Commercial tool provides significant time/cost savings
- Compliance/support requirements mandate commercial solution
- Free tier meets all project needs (e.g., Vercel, Netlify, Supabase free tiers)

**Decision Process**: Document rationale in Architecture Decision Record (ADR) when choosing commercial over open source.

### 2.4 Evaluation Checklist Template

```markdown
## Tool Evaluation: [Tool Name]

### Basic Info
- **Type**: Framework/Library/Service
- **License**: [License]
- **Repository**: [URL]
- **Documentation**: [URL]

### Evaluation
- [ ] GitHub Stars: [count] (≥1k)
- [ ] Recent Activity: Last commit [date] (≤3 months)
- [ ] Release Cadence: [frequency] (≥quarterly)
- [ ] Downloads: [count]/week (≥100k for npm)
- [ ] Test Coverage: [%] or CI badges present
- [ ] Security Policy: Present
- [ ] Known CVEs: [count] high/critical (must be 0)
- [ ] Documentation Quality: [Good/Adequate/Poor]
- [ ] Active Contributors: [count] (≥3)
- [ ] Issues Response: [avg time]

### Decision
- [x] APPROVED - Meets all criteria
- [ ] APPROVED WITH MONITORING - Minor concerns, will monitor
- [ ] REJECTED - Does not meet criteria
- [ ] COMMERCIAL ALTERNATIVE - [Name] chosen because [reason]

### Rationale
[Brief explanation of decision]
```

---

## 3. Technical Architecture

### 3.1 Stack Evolution Policy

The technology stack defined in this constitution represents our **initial architecture decisions** as of project inception. The stack is **not immutable** and should evolve as the project matures and requirements change.

#### When Stack Changes Are Permitted
- New requirements emerge that current stack cannot fulfill efficiently
- Better alternatives become available (based on evaluation criteria)
- Performance, security, or scalability concerns arise
- Community shifts toward superior solutions
- Current tools become deprecated or unmaintained

#### Stack Change Process
1. **Identify Need**: Document why current solution is inadequate
2. **Evaluate Alternatives**: Use Open Source Evaluation Criteria (Section 2.2)
3. **Create ADR**: Document decision in Architecture Decision Record
4. **Update Constitution**: Reflect stack changes in this document
5. **Migration Plan**: If replacing existing tool, create migration strategy
6. **Team Review**: Get approval from technical stakeholders

#### Architecture Decision Records (ADRs)
All significant architectural and stack decisions must be documented in ADRs:

**Location**: `/docs/adr/`

**Naming Convention**: `YYYY-MM-DD-[number]-[title].md`

**Template**:
```markdown
# [Number]. [Title]

Date: YYYY-MM-DD

## Status
[Proposed | Accepted | Deprecated | Superseded by [ADR-XXX]]

## Context
What is the issue we're facing? What factors are driving this decision?

## Decision
What is the change we're proposing or doing?

## Consequences
What becomes easier or more difficult because of this change?

### Positive
- Benefit 1
- Benefit 2

### Negative
- Trade-off 1
- Trade-off 2

### Neutral
- Side effect 1

## Alternatives Considered
What other options did we evaluate?

### Alternative 1: [Name]
- **Pros**: ...
- **Cons**: ...
- **Why rejected**: ...

## References
- Related specs, documentation, benchmarks
```

**Example ADR**:
```markdown
# 001. Use Prisma ORM for Database Access

Date: 2025-10-19

## Status
Accepted

## Context
We need a type-safe way to interact with our SQLite database. Options include raw SQL, query builders (Knex), and ORMs (Prisma, TypeORM, Drizzle).

## Decision
We will use Prisma ORM for all database operations.

## Consequences

### Positive
- Full TypeScript type safety from database to application
- Automatic migrations with Prisma Migrate
- Excellent developer experience with Prisma Studio
- Strong community support (46k+ GitHub stars)
- Active development (weekly releases)

### Negative
- Learning curve for team members unfamiliar with Prisma
- Slight performance overhead vs raw SQL (acceptable for our use case)
- Vendor-specific query syntax

### Neutral
- Locks us into Prisma's data modeling approach
- Will need migration effort if switching ORMs later

## Alternatives Considered

### Alternative 1: TypeORM
- **Pros**: Mature, decorator-based syntax
- **Cons**: Less active development, TypeScript support weaker
- **Why rejected**: Prisma has better DX and more active community

### Alternative 2: Drizzle ORM
- **Pros**: Newer, claims better performance, SQL-like syntax
- **Cons**: Less mature (fewer stars), smaller community
- **Why rejected**: Too new, want proven solution for this project

### Alternative 3: Raw SQL with Knex
- **Pros**: Maximum control, best performance
- **Cons**: No type safety, manual migrations, more boilerplate
- **Why rejected**: Type safety is critical for our team

## References
- Prisma Docs: https://www.prisma.io/docs
- Evaluation Checklist: Passed all criteria (see /docs/evaluations/prisma.md)
```

### 3.2 Technology Stack

**Note**: This stack represents our initial architecture. See Section 3.1 for evolution policy. All stack changes must have corresponding ADRs.

#### Frontend
- **Framework**: Next.js 14 (App Router)
- **Language**: TypeScript (strict mode enabled)
- **UI Library**: React 18+
- **Styling**: Tailwind CSS 3+
- **State Management**: React hooks + Context API (for simple state)
- **Form Handling**: React Hook Form + Zod validation

#### Backend
- **API**: Next.js API Routes
- **Language**: TypeScript (strict mode enabled)
- **Authentication**: NextAuth.js or custom JWT implementation
- **Validation**: Zod schemas

#### Database
- **Database**: SQLite (local development)
- **ORM**: Prisma
- **Migrations**: Prisma Migrate
- **Rationale**: Simple, file-based, no external dependencies for testing

#### Testing
- **Unit Testing**: Jest
- **Component Testing**: React Testing Library
- **Integration Testing**: Jest + Supertest (for API routes)
- **E2E Testing**: Playwright (for critical flows)
- **Test Runner**: Jest (built into Next.js)

#### Development Tools
- **Linting**: ESLint (Next.js config + custom rules)
- **Formatting**: Prettier
- **Type Checking**: TypeScript compiler
- **Git Hooks**: Husky (optional, for pre-commit checks)

### 3.3 Architecture Principles

#### Component Architecture
- **Atomic Design**: Break UI into atoms → molecules → organisms → templates → pages
- **Single Responsibility**: Each component does one thing well
- **Composition over Inheritance**: Favor component composition
- **Props over Context**: Use Context sparingly, prefer explicit props

#### API Design
- **RESTful Conventions**: Use standard HTTP methods (GET, POST, PUT, DELETE)
- **Consistent Naming**: `/api/[resource]/[id]` pattern
- **Error Handling**: Standardized error responses with proper HTTP status codes
- **Validation**: Validate all inputs at API boundary

#### Data Flow
- **Unidirectional**: Data flows down, events flow up
- **Server State**: Use TanStack Query (React Query) for server state caching
- **Client State**: Use React hooks for local UI state
- **Form State**: React Hook Form manages form state

#### File Structure
```
/app
  /(auth)
    /login
    /register
  /(dashboard)
    /todos
  /api
    /auth
    /todos
/components
  /ui           # Reusable UI components (buttons, inputs, etc.)
  /features     # Feature-specific components
  /layouts      # Layout components
/lib
  /db           # Database client and utilities
  /auth         # Authentication utilities
  /validations  # Zod schemas
/prisma
  schema.prisma
  /migrations
/tests
  /unit
  /integration
  /e2e
```

---

## 4. Code Quality Standards

### 4.1 TypeScript Standards

#### Type Safety
- **Strict Mode**: `"strict": true` in tsconfig.json
- **No Implicit Any**: Avoid `any` type; use `unknown` if type is truly unknown
- **Explicit Return Types**: All functions must declare return types
- **Type Imports**: Use `import type` for type-only imports

#### Example
```typescript
// ✅ GOOD
function calculateTotal(items: TodoItem[]): number {
  return items.reduce((sum, item) => sum + (item.priority || 0), 0);
}

// ❌ BAD
function calculateTotal(items) {
  return items.reduce((sum, item) => sum + (item.priority || 0), 0);
}
```

### 4.2 Documentation Standards

#### JSDoc Comments
- **All exported functions**: Must have JSDoc comments
- **Complex logic**: Document why, not what
- **Public APIs**: Include examples in JSDoc

#### Example
```typescript
/**
 * Creates a new todo item in the database
 * 
 * @param data - The todo item data to create
 * @param userId - The ID of the user creating the todo
 * @returns The created todo item with generated ID
 * @throws {ValidationError} If the input data is invalid
 * @throws {AuthorizationError} If the user is not authorized
 * 
 * @example
 * const todo = await createTodo({
 *   title: "Buy groceries",
 *   description: "Milk, eggs, bread",
 *   status: "pending"
 * }, userId);
 */
export async function createTodo(
  data: CreateTodoInput,
  userId: string
): Promise<Todo> {
  // Implementation
}
```

### 4.3 Code Style

#### Naming Conventions
- **Files**: kebab-case (`user-profile.tsx`, `create-todo.ts`)
- **Components**: PascalCase (`UserProfile`, `TodoList`)
- **Functions/Variables**: camelCase (`getUserById`, `todoItems`)
- **Constants**: UPPER_SNAKE_CASE (`MAX_TODO_LENGTH`, `API_BASE_URL`)
- **Types/Interfaces**: PascalCase (`TodoItem`, `UserProfile`)
- **Enums**: PascalCase with UPPER_CASE values
  ```typescript
  enum TodoStatus {
    PENDING = "PENDING",
    COMPLETED = "COMPLETED",
  }
  ```

#### Component Structure
```typescript
// 1. Imports (external, then internal, then types)
import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { TodoList } from '@/components/features/TodoList';
import type { Todo } from '@/types';

// 2. Types/Interfaces
interface TodoPageProps {
  userId: string;
}

// 3. Component
export function TodoPage({ userId }: TodoPageProps) {
  // 3a. Hooks
  const router = useRouter();
  const [todos, setTodos] = useState<Todo[]>([]);
  
  // 3b. Event handlers
  const handleCreate = (todo: Todo) => {
    setTodos(prev => [...prev, todo]);
  };
  
  // 3c. Render
  return (
    <div>
      <TodoList todos={todos} onCreate={handleCreate} />
    </div>
  );
}
```

### 4.4 Linting & Formatting

#### ESLint Rules (enforced)
- No unused variables
- No console.log in production code (use proper logging)
- Prefer const over let
- Require explicit function return types
- No any type without @ts-expect-error comment

#### Prettier Config
```json
{
  "semi": true,
  "trailingComma": "es5",
  "singleQuote": true,
  "printWidth": 100,
  "tabWidth": 2,
  "arrowParens": "avoid"
}
```

---

## 5. Testing Standards

### 5.1 Test Coverage Requirements
- **Minimum Coverage**: 80% across all metrics (lines, branches, functions, statements)
- **Critical Paths**: 100% coverage (authentication, data mutations)
- **Utilities**: 95%+ coverage
- **Components**: 80%+ coverage
- **API Routes**: 90%+ coverage

### 5.2 Test-Driven Development (TDD)

#### When to Use TDD
- **Business Logic**: Always write tests first
- **Utilities**: Always write tests first
- **API Routes**: Write tests first for happy path and error cases
- **Components**: Write tests first for interactive components

#### TDD Workflow
```
1. Write failing test (Red)
2. Write minimal code to pass test (Green)
3. Refactor while keeping tests green (Refactor)
4. Repeat
```

### 5.3 Test Organization

#### Unit Tests
- **Location**: Co-located with source files (`user.ts` → `user.test.ts`)
- **Scope**: Test single functions/classes in isolation
- **Mocking**: Mock external dependencies

#### Integration Tests
- **Location**: `/tests/integration`
- **Scope**: Test API routes end-to-end
- **Database**: Use test database or in-memory SQLite

#### Component Tests
- **Location**: Co-located with components (`TodoList.tsx` → `TodoList.test.tsx`)
- **Scope**: Test component behavior and rendering
- **Approach**: User-centric tests (test behavior, not implementation)

#### E2E Tests
- **Location**: `/tests/e2e`
- **Scope**: Test critical user flows
- **Tool**: Playwright
- **Coverage**: Login → Create Todo → Complete Todo → Logout

### 5.4 Test Naming Convention

```typescript
describe('UserService', () => {
  describe('createUser', () => {
    it('should create a user with valid data', () => {});
    it('should throw ValidationError when email is invalid', () => {});
    it('should throw ConflictError when email already exists', () => {});
  });
});
```

### 5.5 Test Quality Standards
- **Arrange-Act-Assert**: Structure all tests with clear AAA pattern
- **One Assertion per Test**: Prefer single logical assertion
- **Descriptive Names**: Test names should describe expected behavior
- **No Logic in Tests**: Tests should be straightforward, no complex logic
- **Fast Execution**: Unit tests should complete in < 100ms each

---

## 6. Security Standards

### 6.1 Authentication & Authorization

#### Authentication Requirements
- **Method**: JWT-based authentication or NextAuth.js
- **Password Storage**: bcrypt hashing with salt rounds ≥ 12
- **Session Management**: Secure, httpOnly cookies for tokens
- **Token Expiration**: Access tokens expire in 15 minutes, refresh tokens in 7 days
- **Password Requirements**:
  - Minimum 12 characters
  - Must contain: uppercase, lowercase, number, special character

#### Authorization Requirements
- **Principle of Least Privilege**: Users can only access their own data
- **Resource-Level Authorization**: Check authorization on every data access
- **Middleware Pattern**: Use Next.js middleware for route protection

### 6.2 Input Validation

#### Validation Requirements
- **Validate at Boundary**: All API inputs must be validated before processing
- **Use Zod Schemas**: Define schemas for all request/response shapes
- **Sanitize Inputs**: Remove/escape dangerous characters
- **Reject Invalid Data**: Return 400 Bad Request with clear error messages

#### Example
```typescript
import { z } from 'zod';

export const CreateTodoSchema = z.object({
  title: z.string().min(1).max(200),
  description: z.string().max(2000).optional(),
  dueDate: z.string().datetime().optional(),
  status: z.enum(['pending', 'completed']).default('pending'),
});

export type CreateTodoInput = z.infer<typeof CreateTodoSchema>;
```

### 6.3 Data Protection

#### Database Security
- **SQL Injection Prevention**: Use Prisma ORM (parameterized queries)
- **Sensitive Data**: Never log passwords, tokens, or PII
- **Data Access**: All queries must include user context for authorization

#### API Security
- **CSRF Protection**: Use Next.js built-in CSRF protection
- **Rate Limiting**: Implement rate limiting on authentication endpoints
- **HTTPS Only**: Enforce HTTPS in production (Next.js handles this)
- **Secure Headers**: Set security headers (X-Frame-Options, CSP, etc.)

### 6.4 Error Handling

#### Security-Safe Errors
- **No Sensitive Data**: Error messages must not leak system information
- **Generic Messages**: User-facing errors should be generic
  ```typescript
  // ✅ GOOD
  return { error: "Invalid email or password" };
  
  // ❌ BAD (reveals which field is wrong)
  return { error: "Email not found in database" };
  ```
- **Detailed Logging**: Log detailed errors server-side for debugging
- **Error Codes**: Use error codes for client-side error handling

### 6.5 OWASP Top 10 Compliance

Must address all OWASP Top 10 vulnerabilities:
1. **Broken Access Control**: ✅ Resource-level authorization checks
2. **Cryptographic Failures**: ✅ bcrypt for passwords, HTTPS enforced
3. **Injection**: ✅ Prisma ORM prevents SQL injection
4. **Insecure Design**: ✅ Threat modeling required in design phase
5. **Security Misconfiguration**: ✅ Security headers, no debug in production
6. **Vulnerable Components**: ✅ Regular dependency updates
7. **Authentication Failures**: ✅ Strong password policy, secure sessions
8. **Software & Data Integrity**: ✅ No eval(), sanitized inputs
9. **Logging Failures**: ✅ Comprehensive audit logging
10. **SSRF**: ✅ Validate all external URLs

---

## 7. Performance Standards

### 7.1 Frontend Performance

#### Core Web Vitals (targets)
- **Largest Contentful Paint (LCP)**: < 2.0s
- **First Input Delay (FID)**: < 100ms
- **Cumulative Layout Shift (CLS)**: < 0.1

#### Lighthouse Score Targets
- **Performance**: > 90
- **Accessibility**: > 90
- **Best Practices**: > 90
- **SEO**: > 90

#### Optimization Requirements
- **Image Optimization**: Use Next.js Image component for all images
- **Code Splitting**: Dynamic imports for large components
- **Bundle Size**: Keep initial bundle < 200KB (gzipped)
- **Font Loading**: Use next/font for optimized font loading
- **CSS**: Use Tailwind's JIT compiler

### 7.2 Backend Performance

#### API Response Times (p95)
- **Simple Queries**: < 100ms
- **Complex Queries**: < 300ms
- **Authentication**: < 200ms
- **List Endpoints**: < 300ms (with pagination)

#### Database Performance
- **Indexes**: Index all foreign keys and frequently queried fields
- **N+1 Prevention**: Use Prisma's `include` for eager loading
- **Pagination**: Implement cursor-based pagination for lists
- **Query Optimization**: Use `EXPLAIN` to optimize slow queries

#### Caching Strategy
- **Static Pages**: Pre-render with Next.js SSG where possible
- **Dynamic Data**: Use SWR or React Query for client-side caching
- **API Routes**: Cache read-only endpoints with appropriate headers

### 7.3 Scalability Considerations

While this is a simple app, design for scale:
- **Stateless APIs**: No server-side session state (use JWT)
- **Database Pooling**: Prisma handles connection pooling
- **Async Operations**: Use async/await for all I/O operations
- **Pagination**: Never return unbounded lists

---

## 8. Accessibility Standards

### 8.1 WCAG 2.1 Level AA Compliance

#### Perceivable
- **Text Alternatives**: All images have alt text
- **Captions**: Not applicable (no multimedia content planned)
- **Adaptable**: Content structure is semantic (proper headings)
- **Distinguishable**: Color contrast ratio ≥ 4.5:1

#### Operable
- **Keyboard Accessible**: All functionality available via keyboard
- **Enough Time**: No time limits on interactions
- **Seizures**: No flashing content
- **Navigable**: Skip links, focus indicators, logical tab order

#### Understandable
- **Readable**: Clear language, labeled form fields
- **Predictable**: Consistent navigation and behavior
- **Input Assistance**: Clear error messages, validation feedback

#### Robust
- **Compatible**: Valid HTML, ARIA attributes where needed

### 8.2 Implementation Requirements

#### Semantic HTML
```tsx
// ✅ GOOD
<button onClick={handleClick}>Add Todo</button>
<main>
  <h1>My Todos</h1>
  <ul>
    <li>...</li>
  </ul>
</main>

// ❌ BAD
<div onClick={handleClick}>Add Todo</div>
<div>
  <div>My Todos</div>
  <div>
    <div>...</div>
  </div>
</div>
```

#### ARIA Labels
- Use when semantic HTML is insufficient
- Prefer semantic HTML over ARIA when possible
- Test with screen readers (VoiceOver, NVDA)

#### Keyboard Navigation
- All interactive elements must be focusable
- Visible focus indicators (outline or custom styling)
- Logical tab order
- Escape key closes modals/dropdowns

#### Color Contrast
- Text: 4.5:1 minimum
- Large text (18pt+): 3:1 minimum
- Icons: 3:1 minimum
- Use tools: WebAIM Contrast Checker

---

## 9. Development Workflow

### 9.1 Branch Strategy

#### Main Branch
- **Protected**: Requires PR approval before merge
- **Always Deployable**: All code in main must be production-ready
- **CI Checks**: All tests must pass before merge

#### Feature Branches
- **Naming**: `feature/[feature-id]-[short-description]`
- **Example**: `feature/001-user-authentication`
- **Lifetime**: Delete after merge
- **Commits**: Use conventional commits

### 9.2 Commit Message Convention

Follow Conventional Commits:
```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples**:
```
feat(auth): implement user registration endpoint
fix(todos): correct due date validation logic
docs(readme): add setup instructions
test(todos): add integration tests for CRUD operations
```

### 9.3 Pull Request Process

#### PR Creation
1. Create feature branch from main
2. Implement feature following spec/plan/tasks
3. Ensure all tests pass
4. Push branch to GitHub
5. Create PR with description linking to spec

#### PR Description Template
```markdown
## Feature: [Feature Name]

### Spec Reference
- Spec: `specs/[id]/spec.md`
- Plan: `specs/[id]/plan.md`
- Tasks: `specs/[id]/tasks.md`

### Implementation Summary
- Brief description of what was implemented
- Key technical decisions made

### Test Coverage
- Unit tests: [coverage %]
- Integration tests: [coverage %]
- E2E tests: [if applicable]

### Checklist
- [ ] All tasks completed
- [ ] Tests pass locally
- [ ] Code follows constitution standards
- [ ] Documentation updated
- [ ] Security review completed (if needed)
- [ ] Performance tested (if applicable)
```

#### PR Review Process
1. **Automated Checks**: Linting, tests, type checking
2. **Design Review Checkpoint**: Reviewer checks adherence to plan
3. **Code Review Checkpoint**: Reviewer checks code quality
4. **Testing Checkpoint**: Reviewer tests locally
5. **Approval**: Reviewer approves PR
6. **Merge**: Merge to main, delete feature branch

### 9.4 Agent Roles in Workflow

#### Architect Agent
- **Responsibilities**: System design, technical planning, task breakdown
- **Skills**: Architecture patterns, database design, API design
- **Outputs**: plan.md, architecture.md, tasks.md

#### Developer Agent
- **Responsibilities**: Code implementation, unit tests
- **Skills**: TypeScript, React, Next.js, Prisma
- **Outputs**: Source code, tests

#### Security Champion Agent
- **Responsibilities**: Security reviews, threat modeling
- **Skills**: OWASP Top 10, authentication patterns, secure coding
- **Outputs**: security-review.md, security-notes.md

#### QA Agent
- **Responsibilities**: Test case generation, quality assurance
- **Skills**: Jest, React Testing Library, Playwright
- **Outputs**: Enhanced test suites, test-report.md

#### Performance Engineer Agent
- **Responsibilities**: Performance analysis, optimization
- **Skills**: Profiling, database optimization, caching
- **Outputs**: performance-report.md, optimization recommendations

#### Accessibility Champion Agent
- **Responsibilities**: Accessibility compliance
- **Skills**: WCAG standards, ARIA, screen reader testing
- **Outputs**: accessibility-report.md

---

## 10. Data Model Standards

### 10.1 Database Design Principles

#### Normalization
- **3rd Normal Form**: Eliminate redundant data
- **Exceptions**: Denormalize for performance if justified and documented

#### Naming Conventions
- **Tables**: Singular, lowercase with underscores (`user`, `todo_item`)
- **Columns**: Lowercase with underscores (`created_at`, `is_completed`)
- **Primary Keys**: `id` (UUID or auto-increment integer)
- **Foreign Keys**: `[table]_id` (e.g., `user_id`)

#### Required Fields
- **Timestamps**: All tables must have `created_at` and `updated_at`
- **Soft Deletes**: Use `deleted_at` instead of hard deletes for user data
- **Audit Trail**: Consider `created_by` and `updated_by` for audit logging

### 10.2 Prisma Schema Standards

```prisma
model User {
  id        String   @id @default(uuid())
  email     String   @unique
  password  String
  name      String?
  createdAt DateTime @default(now()) @map("created_at")
  updatedAt DateTime @updatedAt @map("updated_at")
  
  todos     Todo[]
  
  @@map("users")
}

model Todo {
  id          String     @id @default(uuid())
  title       String
  description String?
  status      TodoStatus @default(PENDING)
  dueDate     DateTime?  @map("due_date")
  userId      String     @map("user_id")
  createdAt   DateTime   @default(now()) @map("created_at")
  updatedAt   DateTime   @updatedAt @map("updated_at")
  
  user        User       @relation(fields: [userId], references: [id], onDelete: Cascade)
  
  @@index([userId])
  @@index([status])
  @@index([dueDate])
  @@map("todos")
}

enum TodoStatus {
  PENDING
  COMPLETED
}
```

---

## 11. Error Handling Standards

### 11.1 Error Types

Define custom error classes:
```typescript
export class AppError extends Error {
  constructor(
    public statusCode: number,
    public message: string,
    public isOperational = true
  ) {
    super(message);
    Object.setPrototypeOf(this, AppError.prototype);
  }
}

export class ValidationError extends AppError {
  constructor(message: string) {
    super(400, message);
  }
}

export class AuthenticationError extends AppError {
  constructor(message: string = 'Authentication required') {
    super(401, message);
  }
}

export class AuthorizationError extends AppError {
  constructor(message: string = 'Insufficient permissions') {
    super(403, message);
  }
}

export class NotFoundError extends AppError {
  constructor(resource: string) {
    super(404, `${resource} not found`);
  }
}

export class ConflictError extends AppError {
  constructor(message: string) {
    super(409, message);
  }
}
```

### 11.2 API Error Responses

Standardized error response format:
```typescript
interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
}

// Example usage
return NextResponse.json(
  {
    error: {
      code: 'VALIDATION_ERROR',
      message: 'Invalid input data',
      details: zodError.format(),
    },
  },
  { status: 400 }
);
```

### 11.3 Error Logging

```typescript
// Log all errors server-side
console.error('[ERROR]', {
  timestamp: new Date().toISOString(),
  error: error.message,
  stack: error.stack,
  userId: userId,
  endpoint: request.url,
});

// Never log sensitive data
// ❌ BAD: console.error('Password failed:', password);
// ✅ GOOD: console.error('Password validation failed');
```

---

## 12. API Design Standards

### 12.1 RESTful Conventions

#### Endpoints
```
GET    /api/todos          # List all todos (paginated)
GET    /api/todos/:id      # Get single todo
POST   /api/todos          # Create new todo
PUT    /api/todos/:id      # Update existing todo
DELETE /api/todos/:id      # Delete todo

GET    /api/users/me       # Get current user profile
PUT    /api/users/me       # Update current user profile
```

#### HTTP Status Codes
- **200 OK**: Successful GET, PUT
- **201 Created**: Successful POST
- **204 No Content**: Successful DELETE
- **400 Bad Request**: Validation error
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found
- **409 Conflict**: Duplicate resource
- **500 Internal Server Error**: Server error

### 12.2 Request/Response Format

#### Request Body (POST/PUT)
```typescript
// POST /api/todos
{
  "title": "Buy groceries",
  "description": "Milk, eggs, bread",
  "dueDate": "2025-10-20T10:00:00Z",
  "status": "pending"
}
```

#### Response Body (Success)
```typescript
// 201 Created
{
  "data": {
    "id": "uuid",
    "title": "Buy groceries",
    "description": "Milk, eggs, bread",
    "dueDate": "2025-10-20T10:00:00Z",
    "status": "pending",
    "userId": "user-uuid",
    "createdAt": "2025-10-19T12:00:00Z",
    "updatedAt": "2025-10-19T12:00:00Z"
  }
}
```

#### Response Body (Error)
```typescript
// 400 Bad Request
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Title is required",
    "details": {
      "title": ["Required field"]
    }
  }
}
```

### 12.3 Pagination

Use cursor-based pagination for scalability:
```typescript
// GET /api/todos?limit=20&cursor=abc123

{
  "data": [...],
  "pagination": {
    "nextCursor": "xyz789",
    "hasMore": true
  }
}
```

---

## 13. Documentation Requirements

### 13.1 Code Documentation
- All exported functions/classes: JSDoc comments
- Complex algorithms: Inline comments explaining logic
- Magic numbers: Named constants with comments

### 13.2 API Documentation
- OpenAPI/Swagger spec for all endpoints
- Generated from Zod schemas where possible
- Example requests/responses

### 13.3 User Documentation
- README.md with setup instructions
- Feature documentation in `/docs` folder
- Screenshots for UI features

### 13.4 Architecture Documentation
- Architecture Decision Records (ADRs) for major decisions
- Diagrams for complex flows (Mermaid in markdown)
- Database schema documentation

---

## 14. Constitution Updates

### 14.1 Update Process
1. Identify need for constitution change
2. Discuss in retrospective or create GitHub issue
3. Update constitution.md
4. Create PR with rationale
5. Review and approve
6. Apply to future features (not retroactively)

### 14.2 Version History
- **1.0** (October 19, 2025): Initial constitution for Todo App

---

## 15. Metrics and Success Criteria

### 15.1 Code Quality Metrics
- **Test Coverage**: ≥ 80%
- **TypeScript Errors**: 0
- **ESLint Errors**: 0
- **Prettier Violations**: 0

### 15.2 Performance Metrics
- **Lighthouse Score**: ≥ 90 all categories
- **API Response Time (p95)**: < 300ms
- **Bundle Size**: < 200KB (gzipped)

### 15.3 Security Metrics
- **Known Vulnerabilities**: 0 high/critical
- **OWASP Compliance**: 100%
- **Security Tests**: 100% coverage on auth flows

### 15.4 Accessibility Metrics
- **WCAG Compliance**: Level AA
- **Automated Tests**: Pass axe-core
- **Manual Tests**: Pass screen reader testing

---

**End of Constitution**
