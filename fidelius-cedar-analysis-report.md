# Access Intent Report: Fidelius

**Analysis Date:** 2026-02-15
**Framework:** Spring Boot 2.5.15 (Spring MVC)
**Security Framework:** Spring Security with LDAP
**Java Version:** 11

---

## 1. Project Profile

### Framework & Version
- **Type:** Spring MVC (traditional servlet-based, not reactive)
- **Version:** Spring Boot 2.5.15
- **Evidence:** Uses `@RestController`, `ResponseEntity`, no reactive types (`Mono`/`Flux`)

### Java Version
- **Version:** Java 11
- **Evidence:** `pom.xml` specifies `<java.version>1.11</java.version>` and `<release>11</release>`

### Key Dependencies
- **Spring Boot Starter Web** - REST API framework
- **Spring Boot Starter Security** - Security framework
- **Spring Security LDAP** (4.0.3.RELEASE) - LDAP authentication
- **Spring Boot Starter Jersey** - JAX-RS support
- **AWS SDK v2** (2.16.60) - DynamoDB, KMS, EC2, Lambda, RDS, STS
- **Springfox Swagger** (2.7.0) - API documentation
- **BouncyCastle** (1.70) - Cryptography
- **Jasypt** (1.9.2) - Password encryption
- **Guava** - Caching (LoadingCache)
- **Jackson** - JSON serialization
- **Hibernate Validator** - Bean validation

### Module Structure

```
org.finra.fidelius/
├── controllers/          # REST endpoints
│   ├── FideliusController.java    # Main credential operations (22 endpoints)
│   └── AuthController.java        # Authentication/authorization (1 endpoint)
├── services/            # Business logic layer
│   ├── CredentialsService.java    # Core credential operations with @PreAuthorize
│   ├── FideliusService.java       # AWS DynamoDB/KMS operations
│   ├── MembershipService.java     # Application membership resolution
│   ├── MigrateService.java        # Legacy credential migration
│   ├── auth/                      # Authorization services
│   │   ├── FideliusRoleService.java           # Role determination and checks
│   │   ├── FideliusAuthorizationService.java  # Abstract LDAP service
│   │   ├── FideliusActiveDirectoryLDAPAuthorizationService.java
│   │   └── FideliusOpenLDAPAuthorizationService.java
│   ├── aws/                       # AWS client wrappers
│   │   ├── AWSSessionService.java
│   │   └── DynamoDBService.java
│   └── account/
│       └── AccountsService.java   # AWS account metadata
├── model/               # DTOs and entities
│   ├── Credential.java            # Main credential DTO (@NotBlank, @NotNull, @Pattern)
│   ├── Metadata.java              # Rotation metadata DTO
│   ├── HistoryEntry.java          # Version history DTO
│   ├── ActiveDirectory.java       # AD validation config
│   ├── account/
│   │   ├── Account.java           # AWS account model
│   │   └── Region.java            # AWS region model
│   └── validators/
│       └── IsValidActiveDirectoryPassword.java  # Custom validator
├── config/              # Spring configuration
│   ├── FideliusWebSecurityConfig.java  # Security config (CRITICAL: permitAll!)
│   └── AppConfig.java
├── authfilter/          # Custom authentication filters
│   ├── UserHeaderFilter.java     # Extracts user from HTTP headers
│   └── parser/                   # User profile parsers (SSO, composite)
├── factories/           # AWS session factories
└── exceptions/
    └── FideliusException.java    # Custom exception with HTTP status
```

### Architectural Pattern
- **Type:** Standard layered architecture
- **Flow:** Controller → Service (with @PreAuthorize) → FideliusService → AWS SDK
- **Separation:** Clear separation between REST layer and business logic
- **Note:** Authorization is applied at SERVICE layer, NOT controller layer

### Generic/Abstract Base Classes
- **None detected** - No generic CRUD controllers or inherited endpoints
- All endpoints explicitly defined in FideliusController and AuthController

---

## 2. Authorization Model

### Summary Table

| Mechanism | Type | Confidence | Coverage | Details |
|-----------|------|------------|----------|---------|
| Global Filter Chain | FILTER_CHAIN | HIGH | All endpoints | `.anyRequest().permitAll()` - **NO AUTHENTICATION REQUIRED** |
| Method-Level @PreAuthorize | ANNOTATION_BASED | HIGH | Service methods only | Applied to CredentialsService methods |
| Custom UserHeaderFilter | CUSTOM_FILTER | MEDIUM | All requests | Extracts user from headers, no rejection |
| Programmatic Role Checks | PROGRAMMATIC | MEDIUM | Service layer | FideliusRoleService.isAuthorized() |
| LDAP Authorization | CUSTOM | MEDIUM | Background | Membership resolution via LDAP queries |

### 1. Global SecurityFilterChain (FideliusWebSecurityConfig.java)

**CRITICAL FINDING:**
```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)
public class FideliusWebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .anyRequest()
            .permitAll()      // ⚠️ ALL REQUESTS PERMITTED WITHOUT AUTHENTICATION
            .and()
            .csrf()
            .disable();       // ⚠️ CSRF PROTECTION DISABLED
    }
}
```

**Analysis:**
- **Path Matching:** `.anyRequest()` matches ALL HTTP requests
- **Authorization:** `.permitAll()` - NO authentication or authorization required at filter chain level
- **CSRF:** Disabled (`.csrf().disable()`)
- **CORS:** Not configured (defaults)
- **Session Management:** Default (stateful sessions)
- **OAuth2/JWT:** Not configured
- **Classification:** FILTER_CHAIN with CRITICAL security gap

**Effective Behavior:**
- Any request can reach the controller layer without authentication
- Authorization is ONLY enforced at service layer via `@PreAuthorize`
- If a controller method calls a service without `@PreAuthorize`, it's unprotected

### 2. Method-Level Security Annotations

**Enabled via:** `@EnableGlobalMethodSecurity(prePostEnabled=true)`

**Usage (12 occurrences across CredentialsService.java):**

```java
@PreAuthorize("@fideliusRoleService.isAuthorized(#application, #account, \"LIST_CREDENTIALS\")")
public List<Credential> getAllCredentials(String tableName, String account, String region, String application)

@PreAuthorize("@fideliusRoleService.isAuthorized(#application, #account)")
public Credential getCredentialSecret(String account, String region, String application, ...)

@PreAuthorize("@fideliusRoleService.isAuthorized(#credential.application, #credential.account)")
public Credential putCredential(Credential credential)

@PreAuthorize("@fideliusRoleService.isAuthorizedToDelete(#credential.getApplication(), #credential.getAccount())")
public Credential deleteCredential(Credential credential)
```

**Pattern Analysis:**
- **Method:** SPEL expressions calling `@fideliusRoleService` bean
- **Parameters:** Uses method parameter references (`#application`, `#account`, `#credential.application`)
- **Authorization Methods:**
  - `isAuthorized(app, account)` - For read/write operations
  - `isAuthorized(app, account, "LIST_CREDENTIALS")` - For list operations
  - `isAuthorizedToDelete(app, account)` - For delete operations
- **Note:** Controllers do NOT have @PreAuthorize - only services do

**Classification:** ANNOTATION_BASED, HIGH confidence

### 3. Custom Security Mechanisms

#### UserHeaderFilter (Custom Filter)

**Location:** `org.finra.fidelius.authfilter.UserHeaderFilter`

**Behavior:**
```java
public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain) {
    HttpServletRequest httpReq = (HttpServletRequest) req;
    Optional<IFideliusUserProfile> userProfile = userProfileParser.parse(httpReq);
    if (userProfile.isPresent()) {
        filterChain.doFilter(new UserProfileRequestWrapper(httpReq, userProfile.get()), httpRes);
    } else {
        filterChain.doFilter(httpReq, httpRes);  // ⚠️ Continues even if no user found
    }
}
```

**Analysis:**
- Extracts user profile from HTTP headers (SSO headers)
- Wraps request with user principal if found
- **Does NOT reject requests with missing user** - just passes through
- Sets security headers (CSP, X-XSS-Protection, X-Frame-Options)
- **Classification:** CUSTOM_FILTER, does NOT enforce authentication

#### FideliusRoleService (Programmatic Authorization)

**Location:** `org.finra.fidelius.services.auth.FideliusRoleService`

**Key Methods:**

```java
public boolean isAuthorized(String application, String account, String permission) {
    if((getRole().equals(FideliusRole.OPS) || getRole().equals(FideliusRole.DEV)
        || getRole().equals(FideliusRole.MASTER)) && permission.equals("LIST_CREDENTIALS"))
        return true;
    return false;
}

public boolean isAuthorized(String application, String account) {
    if(getRole().equals(FideliusRole.OPS) || getRole().equals(FideliusRole.MASTER))
        return true;

    if(getRole().equals(FideliusRole.DEV)) {
        String sdlc = accountService.getAccountByAlias(account).getSdlc();
        return (!sdlc.equals("prod") && loadLdapUserDevMemberships().contains(application.toUpperCase()));
    }
    return false;
}

public boolean isAuthorizedToDelete(String application, String account) {
    if(getRole().equals(FideliusRole.MASTER))
        return true;

    String sdlc = accountService.getAccountByAlias(account).getSdlc();

    if(getRole().equals(FideliusRole.OPS) && !sdlc.equals("prod"))
        return true;
    else if(getRole().equals(FideliusRole.DEV))
        return (!sdlc.equals("prod") && loadLdapUserDevMemberships().contains(application.toUpperCase()));

    return false;
}
```

**Authorization Logic:**
- **LIST_CREDENTIALS:** Any authenticated role (MASTER/OPS/DEV) can list
- **Read/Write Operations:**
  - MASTER: All accounts/applications
  - OPS: All accounts/applications
  - DEV: Non-prod accounts only, AND membership in application (LDAP-based)
- **Delete Operations:**
  - MASTER: All accounts (including prod)
  - OPS: Non-prod accounts only
  - DEV: Non-prod accounts only, AND membership in application

**Classification:** PROGRAMMATIC, MEDIUM confidence (logic complexity)

### 4. Authentication Model

**Principal Identification:**
- User extracted from HTTP headers via UserHeaderFilter
- Headers parsed by SSOParser or UserParser (SSO integration)
- User profile contains: `userId`, `name`, `email`

**Role/Permission Determination:**
- Roles determined by LDAP group membership patterns
- Cached in Guava LoadingCache (10 minute expiration)
- Patterns matched against LDAP DN:
  - Master pattern: Regex from `fidelius.auth.masterGroupsPattern`
  - Ops pattern: Regex from `fidelius.auth.opsGroupsPattern`
  - Dev pattern: Regex from `fidelius.auth.devGroupsPattern`

**Multi-Tenancy:**
- Yes - Account-level isolation
- Application-level membership (LDAP groups)
- Environment-level access (prod vs non-prod)

### 5. Role/Permission Hierarchy

**Roles (FideliusRole enum):**

| Role | Description | Access Level |
|------|-------------|--------------|
| **MASTER** | Admin access across all accounts | Can delete in ALL accounts including prod |
| **OPS** | Admin access across all accounts | Cannot delete in prod accounts |
| **DEV** | Limited access based on membership | Only non-prod accounts where user is member |
| **UNAUTHORIZED** | No memberships | No access |

**Hierarchy:**
```
MASTER > OPS > DEV > UNAUTHORIZED
```

**Permission Mapping:**
- No explicit permission-to-role mapping
- Permissions are embedded in authorization logic
- Implicit permissions:
  - `LIST_CREDENTIALS` - All roles except UNAUTHORIZED
  - `READ_SECRET` - MASTER/OPS (all), DEV (non-prod + membership)
  - `WRITE_SECRET` - Same as READ_SECRET
  - `DELETE_SECRET` - MASTER (all), OPS (non-prod), DEV (non-prod + membership)
  - `ROTATE_SECRET` - Same as READ_SECRET

**Role Determination Logic:**
```java
private FideliusRole checkFideliusRole() {
    if(!getMasterMemberships().isEmpty()) return FideliusRole.MASTER;
    else if(!getOpsMemberships().isEmpty()) return FideliusRole.OPS;
    else if(!getDevMemberships().isEmpty()) return FideliusRole.DEV;
    else return FideliusRole.UNAUTHORIZED;
}
```

---

## 3. Endpoint Inventory

### Controller: FideliusController

**Base Path:** `/api/fidelius` (from application.yml: `server.servlet.context-path`)

| # | Path | Method | Handler | Request Body | Response Body | Protected | Authorization Method |
|---|------|--------|---------|--------------|---------------|-----------|---------------------|
| 1 | `/heartbeat` | GET | `heartbeatEndpoint()` | None | Empty (204) | ❌ NO | None |
| 2 | `/credentials` | GET | `getCredentials(account, region, application)` | None | `List<Credential>` | ✅ YES | Service: `@PreAuthorize("@fideliusRoleService.isAuthorized(#application, #account, \"LIST_CREDENTIALS\")")` |
| 3 | `/credentials/{key}/` | GET | `getCredential(key, account, region, application)` | None | `Credential` | ✅ YES | Service: `@PreAuthorize("@fideliusRoleService.isAuthorized(#application, #account, \"LIST_CREDENTIALS\")")` |
| 4 | `/credentials/history` | GET | `getCredentialHistory(account, region, app, environment, component, key)` | None | `List<HistoryEntry>` | ✅ YES | Service: `@PreAuthorize("@fideliusRoleService.isAuthorized(#application, #account, \"LIST_CREDENTIALS\")")` |
| 5 | `/credentials/secret` | GET | `getSecret(account, region, application, environment, component, version, shortKey)` | None | `Credential` (with secret) | ✅ YES | Service: `@PreAuthorize("@fideliusRoleService.isAuthorized(#application, #account)")` |
| 6 | `/credentials/secret` | POST | `createCredential(credential)` | `Credential` (@Valid) | `Credential` | ✅ YES | Service: `@PreAuthorize("@fideliusRoleService.isAuthorized(#credential.application, #credential.account)")` |
| 7 | `/credentials/secret` | PUT | `updateCredential(credential)` | `Credential` (@Valid) | `Credential` | ✅ YES | Service: `@PreAuthorize("@fideliusRoleService.isAuthorized(#credential.application, #credential.account)")` |
| 8 | `/credentials/secret` | DELETE | `deleteCredential(account, region, application, environment, component, source, sourceType, shortKey)` | None | `Credential` | ✅ YES | Service: `@PreAuthorize("@fideliusRoleService.isAuthorizedToDelete(#credential.getApplication(), #credential.getAccount())")` |
| 9 | `/credentials/rotate` | POST | `rotateSecret(request)` | `Map<String,String>` | `ResponseEntity` | ✅ YES | Service: `@PreAuthorize("@fideliusRoleService.isAuthorized(#application, #account)")` |
| 10 | `/sources` | GET | `getSourceNames(account, region, sourceType, application)` | None | `List<String>` | ❌ NO | None |
| 11 | `/sourceTypes` | GET | `getSourceNames()` | None | `List<String>` | ❌ NO | None |
| 12 | `/rotationUserManual` | GET | `getRotationUserManual()` | None | `String` | ❌ NO | None |
| 13 | `/credentials/metadata` | GET | `getMetadata(account, region, application, environment, component, shortKey)` | None | `Metadata` | ✅ YES | Service: `@PreAuthorize("@fideliusRoleService.isAuthorized(#application, #account)")` |
| 14 | `/credentials/metadata` | POST | `createMetadata(metadata)` | `Metadata` (@Valid) | `Metadata` | ✅ YES | Service: `@PreAuthorize("@fideliusRoleService.isAuthorized(#application, #account)")` |
| 15 | `/credentials/metadata` | PUT | `updateMetadata(metadata)` | `Metadata` (@Valid) | `Metadata` | ✅ YES | Service: `@PreAuthorize("@fideliusRoleService.isAuthorized(#application, #account)")` |
| 16 | `/credentials/metadata` | DELETE | `deleteMetadata(account, region, application, environment, component, shortKey)` | None | `Metadata` | ✅ YES | Service: `@PreAuthorize("@fideliusRoleService.isAuthorizedToDelete(#metadata.getApplication(), #metadata.getAccount())")` |
| 17 | `/validActiveDirectoryRegularExpression` | GET | `activeDirectory()` | None | `ActiveDirectory` | ❌ NO | None |
| 18 | `/accounts` | GET | `getAccounts()` | None | `List<Account>` | ❌ NO | None |

### Controller: AuthController

**Base Path:** `/api/fidelius/auth`

| # | Path | Method | Handler | Request Body | Response Body | Protected | Authorization Method |
|---|------|--------|---------|--------------|---------------|-----------|---------------------|
| 19 | `/auth/role` | GET | `getRole()` | None | `Map<String,Object>` (userId, name, email, role, memberships, accessInstructions) | ❌ NO | None (but requires user in header) |

### Actuator Endpoints

**Base Path:** `/api/fidelius` (actuator base-path is empty)

| # | Path | Method | Handler | Request Body | Response Body | Protected | Authorization Method |
|---|------|--------|---------|--------------|---------------|-----------|---------------------|
| 20 | `/info` | GET | Spring Actuator | None | Application info | ❌ NO | None |
| 21 | `/health` | GET | Spring Actuator | None | Health status | ❌ NO | None |

### Detailed Attribute-Level Analysis

#### Credential Model (Request/Response)

**Fields:**
- `shortKey` (String, @NotBlank, @NotNull)
- `longKey` (String, @Pattern)
- `account` (String, @NotBlank, @NotNull)
- `region` (String, @NotBlank, @NotNull)
- `application` (String, @NotBlank, @NotNull)
- `environment` (String, @NotBlank, @NotNull)
- `component` (String, @Pattern, optional)
- `secret` (String, @NotBlank, @NotNull) - **SENSITIVE**
- `lastUpdatedBy` (String, optional)
- `lastUpdatedDate` (ZonedDateTime, optional)
- `isActiveDirectory` (Boolean, optional)
- `source` (String, optional)
- `sourceType` (String, optional)

**Validation:**
- `@IsValidActiveDirectoryPassword` custom validator at class level
- Pattern validation for `component` and `longKey`: `[^\\s]+` (no whitespace)

#### Metadata Model (Request/Response)

**Fields:**
- `shortKey` (String, @NotBlank, @NotNull)
- `longKey` (String, @Pattern)
- `account` (String, @NotBlank, @NotNull)
- `region` (String, @NotBlank, @NotNull)
- `application` (String, @NotBlank, @NotNull)
- `environment` (String, @NotBlank, @NotNull)
- `component` (String, @Pattern, optional)
- `sourceType` (String, @NotBlank, @NotNull)
- `source` (String, @NotBlank, @NotNull)
- `lastUpdatedBy` (String, optional)
- `lastUpdatedDate` (ZonedDateTime, optional)

#### HistoryEntry Model (Response Only)

**Fields:**
- `revision` (Integer)
- `updatedBy` (String)
- `updatedDate` (String)

#### Account Model (Response Only)

**Fields:**
- `accountId` (String)
- `name` (String)
- `sdlc` (String) - **CRITICAL** for authorization (prod vs non-prod)
- `alias` (String)
- `regions` (List<Region>)

### DTO-to-Entity Mapping

**Mapping Confidence: HIGH**

- **Credential DTO → DynamoDB Item:** Direct field mapping in CredentialsService
- No MapStruct or ModelMapper detected
- Manual setter calls in service layer
- Entity exposure: Credential model is used both as DTO and internally (moderate risk)

---

## 4. Cedar Policies

### Endpoint-Level Policies

#### Policy 1: Heartbeat Endpoint (NO_AUTH)

```cedar
// MANUAL_REVIEW: No authorization required
// Source: FideliusController.java:58
// Endpoint: GET /api/fidelius/heartbeat
// Authorization: NONE
// Confidence: HIGH
// ⚠️ FINDING: Public endpoint - expected for health monitoring
```

**No Cedar permit statement generated - endpoint is intentionally public**

#### Policy 2: List All Credentials

```cedar
// Source: FideliusController.java:63-74, CredentialsService.java:220-259
// Endpoint: GET /api/fidelius/credentials?account={account}&region={region}&application={application}
// Authorization: @PreAuthorize("@fideliusRoleService.isAuthorized(#application, #account, \"LIST_CREDENTIALS\")")
// Effective Permission: MASTER OR OPS OR DEV
// Confidence: HIGH

permit(
  principal in [Role::"MASTER", Role::"OPS", Role::"DEV"],
  action == Action::"ListResource",
  resource == ResourceType::"Credential"
)
when {
  context.http_method == "GET" &&
  context.path == "/api/fidelius/credentials" &&
  context.query_param_application == resource.application &&
  context.query_param_account == resource.account
};
```

**Attribute-Level Read Policy:**

```cedar
// Attributes returned by GET /api/fidelius/credentials
// Source: Credential model fields (excluding 'secret')
// Confidence: HIGH

permit(
  principal in [Role::"MASTER", Role::"OPS", Role::"DEV"],
  action == Action::"ReadAttribute",
  resource == ResourceType::"Credential"
)
when {
  context.http_method == "GET" &&
  context.path == "/api/fidelius/credentials" &&
  resource.attribute in [
    "shortKey",
    "longKey",
    "account",
    "region",
    "application",
    "environment",
    "component",
    "lastUpdatedBy",
    "lastUpdatedDate"
    // Note: 'secret' is NOT returned by this endpoint
  ]
};
```

#### Policy 3: Get Single Credential (Metadata Only)

```cedar
// Source: FideliusController.java:77-89, CredentialsService.java:261-305
// Endpoint: GET /api/fidelius/credentials/{key}/?account={account}&region={region}&application={application}
// Authorization: @PreAuthorize("@fideliusRoleService.isAuthorized(#application, #account, \"LIST_CREDENTIALS\")")
// Confidence: HIGH

permit(
  principal in [Role::"MASTER", Role::"OPS", Role::"DEV"],
  action == Action::"ReadResource",
  resource == ResourceType::"Credential"
)
when {
  context.http_method == "GET" &&
  context.path_pattern == "/api/fidelius/credentials/{key}/" &&
  context.query_param_application == resource.application &&
  context.query_param_account == resource.account
};
```

#### Policy 4: Get Credential History

```cedar
// Source: FideliusController.java:91-105, CredentialsService.java:307-352
// Endpoint: GET /api/fidelius/credentials/history
// Authorization: @PreAuthorize("@fideliusRoleService.isAuthorized(#application, #account, \"LIST_CREDENTIALS\")")
// Confidence: HIGH

permit(
  principal in [Role::"MASTER", Role::"OPS", Role::"DEV"],
  action == Action::"ReadResource",
  resource == ResourceType::"CredentialHistory"
)
when {
  context.http_method == "GET" &&
  context.path == "/api/fidelius/credentials/history" &&
  context.query_param_application == resource.application &&
  context.query_param_account == resource.account
};
```

**Attribute-Level Read Policy:**

```cedar
permit(
  principal in [Role::"MASTER", Role::"OPS", Role::"DEV"],
  action == Action::"ReadAttribute",
  resource == ResourceType::"CredentialHistory"
)
when {
  resource.attribute in ["revision", "updatedBy", "updatedDate"]
};
```

#### Policy 5: Get Credential Secret

```cedar
// Source: FideliusController.java:108-122, CredentialsService.java:365-383
// Endpoint: GET /api/fidelius/credentials/secret
// Authorization: @PreAuthorize("@fideliusRoleService.isAuthorized(#application, #account)")
// Effective Permission: MASTER (all), OPS (all), DEV (non-prod + membership)
// Confidence: HIGH
// MANUAL_REVIEW: Complex authorization logic with prod/non-prod check for DEV role

permit(
  principal in [Role::"MASTER", Role::"OPS"],
  action == Action::"ReadResource",
  resource == ResourceType::"CredentialSecret"
)
when {
  context.http_method == "GET" &&
  context.path == "/api/fidelius/credentials/secret" &&
  context.query_param_application == resource.application &&
  context.query_param_account == resource.account
};

permit(
  principal in [Role::"DEV"],
  action == Action::"ReadResource",
  resource == ResourceType::"CredentialSecret"
)
when {
  context.http_method == "GET" &&
  context.path == "/api/fidelius/credentials/secret" &&
  context.query_param_application == resource.application &&
  context.query_param_account == resource.account &&
  resource.account_sdlc != "prod" &&  // Non-prod only
  principal.memberships.contains(resource.application.toUpperCase())  // Application membership required
};
```

**Attribute-Level Read Policy:**

```cedar
// Attributes returned: ALL including 'secret' (SENSITIVE)
// Confidence: HIGH

permit(
  principal in [Role::"MASTER", Role::"OPS"],
  action == Action::"ReadAttribute",
  resource == ResourceType::"CredentialSecret"
)
when {
  resource.attribute in [
    "shortKey",
    "account",
    "region",
    "application",
    "environment",
    "component",
    "secret"  // ⚠️ SENSITIVE FIELD
  ]
};

permit(
  principal in [Role::"DEV"],
  action == Action::"ReadAttribute",
  resource == ResourceType::"CredentialSecret"
)
when {
  resource.account_sdlc != "prod" &&
  principal.memberships.contains(resource.application.toUpperCase()) &&
  resource.attribute in [
    "shortKey",
    "account",
    "region",
    "application",
    "environment",
    "component",
    "secret"  // ⚠️ SENSITIVE FIELD
  ]
};
```

#### Policy 6: Create Credential

```cedar
// Source: FideliusController.java:125-138, CredentialsService.java:426-439
// Endpoint: POST /api/fidelius/credentials/secret
// Request Body: Credential (with secret)
// Authorization: @PreAuthorize("@fideliusRoleService.isAuthorized(#credential.application, #credential.account)")
// Effective Permission: Same as read secret
// Confidence: HIGH

permit(
  principal in [Role::"MASTER", Role::"OPS"],
  action == Action::"CreateResource",
  resource == ResourceType::"Credential"
)
when {
  context.http_method == "POST" &&
  context.path == "/api/fidelius/credentials/secret" &&
  context.request_body.application == resource.application &&
  context.request_body.account == resource.account
};

permit(
  principal in [Role::"DEV"],
  action == Action::"CreateResource",
  resource == ResourceType::"Credential"
)
when {
  context.http_method == "POST" &&
  context.path == "/api/fidelius/credentials/secret" &&
  context.request_body.application == resource.application &&
  context.request_body.account == resource.account &&
  resource.account_sdlc != "prod" &&
  principal.memberships.contains(resource.application.toUpperCase())
};
```

**Attribute-Level Write Policy:**

```cedar
// Request body fields (all validated)
// Confidence: HIGH

permit(
  principal in [Role::"MASTER", Role::"OPS"],
  action == Action::"WriteAttribute",
  resource == ResourceType::"Credential"
)
when {
  context.http_method == "POST" &&
  resource.attribute in [
    "shortKey",      // @NotBlank, @NotNull
    "account",       // @NotBlank, @NotNull
    "region",        // @NotBlank, @NotNull
    "application",   // @NotBlank, @NotNull
    "environment",   // @NotBlank, @NotNull
    "component",     // @Pattern, optional
    "secret",        // @NotBlank, @NotNull, SENSITIVE
    "source",        // optional
    "sourceType",    // optional
    "isActiveDirectory"  // optional
  ]
};

permit(
  principal in [Role::"DEV"],
  action == Action::"WriteAttribute",
  resource == ResourceType::"Credential"
)
when {
  context.http_method == "POST" &&
  resource.account_sdlc != "prod" &&
  principal.memberships.contains(resource.application.toUpperCase()) &&
  resource.attribute in [
    "shortKey", "account", "region", "application", "environment",
    "component", "secret", "source", "sourceType", "isActiveDirectory"
  ]
};
```

#### Policy 7: Update Credential

```cedar
// Source: FideliusController.java:141-149, CredentialsService.java:391-418
// Endpoint: PUT /api/fidelius/credentials/secret
// Authorization: Same as create
// Confidence: HIGH

permit(
  principal in [Role::"MASTER", Role::"OPS"],
  action == Action::"UpdateResource",
  resource == ResourceType::"Credential"
)
when {
  context.http_method == "PUT" &&
  context.path == "/api/fidelius/credentials/secret"
};

permit(
  principal in [Role::"DEV"],
  action == Action::"UpdateResource",
  resource == ResourceType::"Credential"
)
when {
  context.http_method == "PUT" &&
  context.path == "/api/fidelius/credentials/secret" &&
  resource.account_sdlc != "prod" &&
  principal.memberships.contains(resource.application.toUpperCase())
};
```

#### Policy 8: Delete Credential

```cedar
// Source: FideliusController.java:152-169, CredentialsService.java:527-550
// Endpoint: DELETE /api/fidelius/credentials/secret
// Authorization: @PreAuthorize("@fideliusRoleService.isAuthorizedToDelete(...)")
// Effective Permission: MASTER (all), OPS (non-prod only), DEV (non-prod + membership)
// Confidence: HIGH

permit(
  principal == Role::"MASTER",
  action == Action::"DeleteResource",
  resource == ResourceType::"Credential"
)
when {
  context.http_method == "DELETE" &&
  context.path == "/api/fidelius/credentials/secret"
  // MASTER can delete in ALL environments including prod
};

permit(
  principal == Role::"OPS",
  action == Action::"DeleteResource",
  resource == ResourceType::"Credential"
)
when {
  context.http_method == "DELETE" &&
  context.path == "/api/fidelius/credentials/secret" &&
  resource.account_sdlc != "prod"  // OPS cannot delete in prod
};

permit(
  principal == Role::"DEV",
  action == Action::"DeleteResource",
  resource == ResourceType::"Credential"
)
when {
  context.http_method == "DELETE" &&
  context.path == "/api/fidelius/credentials/secret" &&
  resource.account_sdlc != "prod" &&
  principal.memberships.contains(resource.application.toUpperCase())
};
```

#### Policy 9: Rotate Credential

```cedar
// Source: FideliusController.java:172-185, CredentialsService.java:453-519
// Endpoint: POST /api/fidelius/credentials/rotate
// Request Body: Map<String,String> (DYNAMIC_SCHEMA)
// Authorization: @PreAuthorize("@fideliusRoleService.isAuthorized(#application, #account)")
// Confidence: MEDIUM (dynamic request body)
// ⚠️ FINDING: Request body is Map<String,String> - cannot determine exact fields

permit(
  principal in [Role::"MASTER", Role::"OPS"],
  action == Action::"UpdateResource",  // Rotation is an update operation
  resource == ResourceType::"Credential"
)
when {
  context.http_method == "POST" &&
  context.path == "/api/fidelius/credentials/rotate"
};

permit(
  principal in [Role::"DEV"],
  action == Action::"UpdateResource",
  resource == ResourceType::"Credential"
)
when {
  context.http_method == "POST" &&
  context.path == "/api/fidelius/credentials/rotate" &&
  resource.account_sdlc != "prod" &&
  principal.memberships.contains(resource.application.toUpperCase())
};
```

**Attribute-Level Write Policy:**

```cedar
// UNBOUNDED_ACCESS: Request body is Map<String,String>
// Inferred fields from code: account, sourceType, source (sourceName), shortKey,
//   component, region, application, environment
// Confidence: MEDIUM

permit(
  principal in [Role::"MASTER", Role::"OPS", Role::"DEV"],
  action == Action::"WriteAttribute",
  resource == ResourceType::"Credential"
)
when {
  context.http_method == "POST" &&
  context.path == "/api/fidelius/credentials/rotate" &&
  resource.attribute in [
    "account", "sourceType", "source", "shortKey",
    "component", "region", "application", "environment"
  ]
};
```

#### Policy 10-12: Source/SourceType/UserManual Endpoints (NO_AUTH)

```cedar
// MANUAL_REVIEW: No authorization required
// Source: FideliusController.java:188-210
// Endpoints:
//   - GET /api/fidelius/sources (line 188)
//   - GET /api/fidelius/sourceTypes (line 201)
//   - GET /api/fidelius/rotationUserManual (line 207)
// Authorization: NONE
// Confidence: HIGH
// ⚠️ FINDING: Public endpoints - potential information disclosure
```

**No Cedar permit statements - endpoints are unprotected**

#### Policy 13-16: Metadata Operations

```cedar
// Source: FideliusController.java:213-269, CredentialsService.java:563-621
// Endpoints:
//   - GET /api/fidelius/credentials/metadata (line 213)
//   - POST /api/fidelius/credentials/metadata (line 226)
//   - PUT /api/fidelius/credentials/metadata (line 243)
//   - DELETE /api/fidelius/credentials/metadata (line 254)
// Authorization: Same as credential operations
// Confidence: HIGH

// GET Metadata
permit(
  principal in [Role::"MASTER", Role::"OPS"],
  action == Action::"ReadResource",
  resource == ResourceType::"Metadata"
)
when {
  context.http_method == "GET" &&
  context.path == "/api/fidelius/credentials/metadata"
};

permit(
  principal in [Role::"DEV"],
  action == Action::"ReadResource",
  resource == ResourceType::"Metadata"
)
when {
  context.http_method == "GET" &&
  context.path == "/api/fidelius/credentials/metadata" &&
  resource.account_sdlc != "prod" &&
  principal.memberships.contains(resource.application.toUpperCase())
};

// POST/PUT Metadata
permit(
  principal in [Role::"MASTER", Role::"OPS"],
  action in [Action::"CreateResource", Action::"UpdateResource"],
  resource == ResourceType::"Metadata"
)
when {
  context.http_method in ["POST", "PUT"] &&
  context.path == "/api/fidelius/credentials/metadata"
};

permit(
  principal in [Role::"DEV"],
  action in [Action::"CreateResource", Action::"UpdateResource"],
  resource == ResourceType::"Metadata"
)
when {
  context.http_method in ["POST", "PUT"] &&
  context.path == "/api/fidelius/credentials/metadata" &&
  resource.account_sdlc != "prod" &&
  principal.memberships.contains(resource.application.toUpperCase())
};

// DELETE Metadata
permit(
  principal == Role::"MASTER",
  action == Action::"DeleteResource",
  resource == ResourceType::"Metadata"
)
when {
  context.http_method == "DELETE" &&
  context.path == "/api/fidelius/credentials/metadata"
};

permit(
  principal in [Role::"OPS", Role::"DEV"],
  action == Action::"DeleteResource",
  resource == ResourceType::"Metadata"
)
when {
  context.http_method == "DELETE" &&
  context.path == "/api/fidelius/credentials/metadata" &&
  resource.account_sdlc != "prod"
};
```

#### Policy 17-18: Configuration/Account Endpoints (NO_AUTH)

```cedar
// MANUAL_REVIEW: No authorization required
// Source: FideliusController.java:272-286
// Endpoints:
//   - GET /api/fidelius/validActiveDirectoryRegularExpression (line 272)
//   - GET /api/fidelius/accounts (line 278)
// Authorization: NONE
// Confidence: HIGH
// ⚠️ CRITICAL: /accounts endpoint exposes ALL AWS account metadata including account IDs
```

**No Cedar permit statements - endpoints are unprotected**

#### Policy 19: Get User Role (AuthController)

```cedar
// MANUAL_REVIEW: No controller-level authorization
// Source: AuthController.java:40-65
// Endpoint: GET /api/fidelius/auth/role
// Authorization: NONE at controller level (but UserHeaderFilter extracts user)
// Confidence: MEDIUM
// ⚠️ FINDING: Endpoint requires user in headers but doesn't enforce authentication

// This endpoint returns user profile, role, and memberships
// It will work if UserHeaderFilter extracts a user, otherwise may return partial data
// No Cedar policy generated - endpoint is functionally public
```

#### Policy 20-21: Actuator Endpoints (NO_AUTH)

```cedar
// MANUAL_REVIEW: Spring Boot Actuator endpoints
// Source: application.yml management.endpoints.web.exposure.include
// Endpoints:
//   - GET /api/fidelius/info
//   - GET /api/fidelius/health
// Authorization: NONE
// Confidence: HIGH
// ⚠️ EXPECTED: Health/info endpoints are typically public for monitoring
```

---

## 5. Findings & Risks

### CRITICAL Findings

#### C-1: Global PermitAll Security Configuration

**Severity:** CRITICAL
**Type:** NO_AUTH
**Location:** `FideliusWebSecurityConfig.java:33-39`

**Description:**
The global Spring Security filter chain is configured with `.anyRequest().permitAll()`, which allows ALL requests to pass through without authentication. This means:
- Any endpoint can be accessed by anonymous users if the controller doesn't call a protected service method
- CSRF protection is disabled
- No session validation or authentication checks at the filter level

**Affected Endpoints:**
All 21 endpoints are technically accessible without authentication at the filter chain level.

**Current Mitigation:**
Service-layer `@PreAuthorize` annotations provide authorization for sensitive operations, BUT:
- 7 endpoints have NO service-layer protection (heartbeat, sources, sourceTypes, rotationUserManual, validActiveDirectoryRegularExpression, accounts, auth/role)
- UserHeaderFilter extracts user from headers but doesn't enforce presence

**Risk:**
If an attacker bypasses header-based authentication or if a new endpoint is added without service-layer protection, it will be completely unprotected.

**Recommendation:**
1. Change `.permitAll()` to `.authenticated()` for all endpoints except `/heartbeat`, `/health`, `/info`
2. Configure proper authentication provider (LDAP, OAuth2, etc.)
3. Keep `@EnableGlobalMethodSecurity(prePostEnabled=true)` as defense-in-depth

---

#### C-2: Account Information Disclosure

**Severity:** CRITICAL
**Type:** NO_AUTH
**Endpoint:** `GET /api/fidelius/accounts`
**Location:** `FideliusController.java:278-286`

**Description:**
This endpoint returns ALL AWS account metadata including:
- Account IDs (sensitive for AWS security)
- Account aliases
- SDLC classifications (prod/non-prod)
- Regions

**Risk:**
Attackers can enumerate all AWS accounts in the organization, which can be used for:
- Reconnaissance for targeted attacks
- Understanding production vs non-production environments
- Phishing attacks using legitimate account IDs

**Recommendation:**
Add `@PreAuthorize` to the service method or require authentication at minimum.

---

### HIGH Findings

#### H-1: No Authentication Enforcement at Entry Point

**Severity:** HIGH
**Type:** NO_AUTH
**Endpoints:** All 21 endpoints

**Description:**
UserHeaderFilter extracts user profile from headers but continues processing even if no user is found:

```java
if (userProfile.isPresent()) {
    filterChain.doFilter(new UserProfileRequestWrapper(httpReq, userProfile.get()), httpRes);
} else {
    filterChain.doFilter(httpReq, httpRes);  // ⚠️ Continues without user
}
```

**Risk:**
- No guarantee that a user principal exists when service methods execute
- If `@PreAuthorize` tries to evaluate `fideliusRoleService.getUser()` with no user, it may throw exception or return UNAUTHORIZED role
- Error handling may not be consistent

**Recommendation:**
Modify UserHeaderFilter to reject requests without valid user profile (except for public endpoints).

---

#### H-2: CSRF Protection Disabled

**Severity:** HIGH
**Type:** SECURITY_MISCONFIGURATION
**Location:** `FideliusWebSecurityConfig.java:38`

**Description:**
CSRF protection is explicitly disabled: `.csrf().disable()`

**Risk:**
Application is vulnerable to Cross-Site Request Forgery attacks. An attacker can:
- Trick authenticated users into performing state-changing operations (POST, PUT, DELETE)
- Create, update, or delete credentials without user consent

**Recommendation:**
1. Enable CSRF protection for state-changing endpoints
2. If using header-based authentication (not cookies), document why CSRF is not needed
3. Consider using same-site cookie attributes if session-based auth is added

---

#### H-3: Information Disclosure via Unprotected Endpoints

**Severity:** HIGH
**Type:** NO_AUTH
**Endpoints:**
- `GET /api/fidelius/sources` (line 188)
- `GET /api/fidelius/sourceTypes` (line 201)
- `GET /api/fidelius/rotationUserManual` (line 207)
- `GET /api/fidelius/validActiveDirectoryRegularExpression` (line 272)

**Description:**
These endpoints expose operational information without authentication:
- Available source types for credential rotation
- Source names (RDS instances, Aurora, DocumentDB, Redshift clusters)
- Active Directory validation regex patterns
- Rotation documentation

**Risk:**
Attackers can:
- Enumerate database instances and services
- Understand credential naming conventions
- Learn about rotation procedures

**Recommendation:**
Require authentication for all operational endpoints. Minimum: `@PreAuthorize("isAuthenticated()")`

---

#### H-4: Role Endpoint Leaks User Information

**Severity:** HIGH
**Type:** INFORMATION_DISCLOSURE
**Endpoint:** `GET /api/fidelius/auth/role`
**Location:** `AuthController.java:40-65`

**Description:**
Endpoint returns:
- User ID, name, email
- Assigned role (MASTER/OPS/DEV/UNAUTHORIZED)
- All application memberships

Without proper authentication enforcement, this could leak:
- Internal user IDs and organizational structure
- Application names in the organization
- Access levels

**Risk:**
Reconnaissance for social engineering or targeted attacks.

**Recommendation:**
Add authentication requirement and rate limiting.

---

### MEDIUM Findings

#### M-1: Dynamic Request Body Schema

**Severity:** MEDIUM
**Type:** UNBOUNDED_ACCESS
**Endpoint:** `POST /api/fidelius/credentials/rotate`
**Location:** `FideliusController.java:173`

**Description:**
Request body is `Map<String,String>` instead of a typed DTO:

```java
public ResponseEntity rotateSecret(@RequestBody Map<String, String> request)
```

**Risk:**
- No compile-time validation of required fields
- Cedar policies cannot accurately represent attribute-level write access
- Potential for unexpected fields to be processed

**Recommendation:**
Create a `RotateRequest` DTO with proper validation annotations.

---

#### M-2: Inconsistent Authorization for List vs Read

**Severity:** MEDIUM
**Type:** INCONSISTENT_AUTHORIZATION

**Description:**
- `GET /credentials` (list all) - requires `LIST_CREDENTIALS` permission (any role)
- `GET /credentials/secret` (read secret) - requires `isAuthorized()` with prod/non-prod check

For DEV role:
- Can LIST credentials in prod accounts
- Cannot READ secrets in prod accounts

**Risk:**
Information leakage - DEV users can see that credentials exist in prod (metadata) even though they can't read the secrets.

**Recommendation:**
Apply same authorization level to list and read operations, or filter list results based on read permissions.

---

#### M-3: Service Account Detection Logic

**Severity:** MEDIUM
**Type:** AUTHORIZATION_BYPASS_POTENTIAL
**Location:** `CredentialsService.java:395-398`

**Description:**
Special handling for service accounts:

```java
if(credential.getLastUpdatedBy() != null && !credential.getLastUpdatedBy().isEmpty()
   && user.toLowerCase().equals(clientId.get().toLowerCase())) {
    logger.info("Detected Service Account as updating user. Using last updated as user: "
        + credential.getLastUpdatedBy());
    user = credential.getLastUpdatedBy();
}
```

**Risk:**
If an attacker can:
1. Set `lastUpdatedBy` in request
2. Authenticate as the service account (clientId from OAuth2 config)

Then they can impersonate any user in audit logs.

**Recommendation:**
- Do NOT allow `lastUpdatedBy` to be set by client requests
- Set audit fields server-side only
- Consider separate endpoint for service account operations

---

#### M-4: No Rate Limiting

**Severity:** MEDIUM
**Type:** MISSING_CONTROL

**Description:**
No rate limiting detected on any endpoints.

**Risk:**
- Brute force attacks on credential enumeration
- Denial of service through excessive requests
- LDAP query flooding (membership lookups are cached but have 10-minute expiry)

**Recommendation:**
Implement rate limiting per user/IP for:
- Secret read operations
- Authentication/role lookup
- Credential creation

---

### LOW Findings

#### L-1: Verbose Error Messages

**Severity:** LOW
**Type:** INFORMATION_DISCLOSURE

**Description:**
Exception messages are returned to clients:
- `FideliusException` includes `HttpStatus` and message
- Stack traces may be logged with sensitive information

**Recommendation:**
Implement global exception handler to sanitize error responses.

---

#### L-2: No Audit Logging Validation

**Severity:** LOW
**Type:** AUDIT_GAP

**Description:**
Audit fields (`lastUpdatedBy`, `lastUpdatedDate`) are set but:
- No validation that they're immutable once set
- Clients can provide initial values
- No central audit log (relies on DynamoDB item history)

**Recommendation:**
- Remove audit fields from request DTOs
- Set server-side only
- Consider central audit log for compliance

---

#### L-3: Session Timeout Configuration

**Severity:** LOW
**Type:** INFO

**Description:**
`application.yml` sets session timeout to 900000ms (15 minutes) with 10-second pad.

**Note:**
If using header-based authentication, session timeout is irrelevant. Clarify authentication mechanism.

---

### Confidence Gaps

| Finding | Confidence | Missing Information |
|---------|------------|---------------------|
| Rotate endpoint attribute access | MEDIUM | Request body is Map - exact fields not validated |
| UserHeaderFilter behavior | MEDIUM | Actual header names not visible (likely in parser implementations) |
| LDAP membership resolution | MEDIUM | Exact LDAP query patterns not visible in code review |
| Service account OAuth2 flow | LOW | OAuth2 configuration not fully visible (clientId, clientSecret from env) |
| Downstream AWS operations | LOW | Cannot trace all AWS API calls made by service layer |

---

### Downstream Effects Not Captured in Cedar Policies

The following operations have downstream effects that cannot be represented in endpoint-level Cedar policies:

1. **Credential Creation/Update:**
   - Writes to DynamoDB (account: parameter-based)
   - KMS encryption operations (key: from config)
   - May trigger credential rotation service (external HTTP call)

2. **Credential Deletion:**
   - Deletes from DynamoDB
   - May also delete associated metadata

3. **Metadata Operations:**
   - Stored separately in DynamoDB with "META#" prefix
   - Linked to credentials but can exist independently

4. **Account Service Calls:**
   - `AccountsService.getAccountByAlias()` called to check sdlc (prod vs non-prod)
   - This is a dependency for DEV role authorization

5. **LDAP Queries:**
   - Performed on every role/membership check (with 10-minute caching)
   - Cannot be represented in Cedar policies

6. **External Rotation Service:**
   - Rotate endpoint calls external service via REST
   - Authorization on that service is separate (OAuth2)

---

## 6. Summary Statistics

### Endpoint Statistics

- **Total endpoints:** 21
- **Endpoints with service-layer auth:** 14 (66.7%)
- **Endpoints with NO auth:** 7 (33.3%)
  - `/heartbeat` (expected)
  - `/sources`
  - `/sourceTypes`
  - `/rotationUserManual`
  - `/validActiveDirectoryRegularExpression`
  - `/accounts` (CRITICAL)
  - `/auth/role`
  - `/info` (actuator, expected)
  - `/health` (actuator, expected)

### Policy Confidence Distribution

- **HIGH confidence policies:** 14 (66.7%)
  - All policies based on explicit `@PreAuthorize` annotations
  - Typed DTOs with clear field mapping

- **MEDIUM confidence policies:** 2 (9.5%)
  - Rotate endpoint (dynamic request body)
  - Auth/role endpoint (no explicit auth check)

- **LOW/UNKNOWN confidence policies:** 0

- **NO_AUTH (no policies generated):** 7 (33.3%)

### Findings by Severity

- **CRITICAL:** 2
  - Global PermitAll configuration
  - Account information disclosure

- **HIGH:** 4
  - No authentication enforcement at entry point
  - CSRF protection disabled
  - Information disclosure via unprotected endpoints
  - Role endpoint leaks user information

- **MEDIUM:** 4
  - Dynamic request body schema
  - Inconsistent authorization for list vs read
  - Service account detection logic
  - No rate limiting

- **LOW:** 3
  - Verbose error messages
  - No audit logging validation
  - Session timeout configuration

- **INFO:** 0

### Authorization Coverage

| Role | Endpoints with Full Access | Endpoints with Conditional Access | Total |
|------|---------------------------|-----------------------------------|-------|
| MASTER | 14 (all protected endpoints) | 0 | 14 (100%) |
| OPS | 14 (except prod deletes) | 0 | 14 (95% of operations) |
| DEV | 0 | 14 (non-prod only + membership) | 14 (50% of accounts) |
| UNAUTHORIZED | 0 | 0 | 0 |
| Anonymous | 7 (public endpoints) | 0 | 7 |

### Resource Types

Cedar policies reference the following resource types:

1. **Credential** - Main secrets
2. **CredentialSecret** - Secrets with decrypted value
3. **CredentialHistory** - Version history
4. **Metadata** - Rotation metadata
5. **Account** - AWS account information (no policies - unprotected)

### Attribute Statistics

- **Credential fields:** 13 (1 sensitive: `secret`)
- **Metadata fields:** 11 (2 required: `source`, `sourceType`)
- **HistoryEntry fields:** 3
- **Account fields:** 5 (1 critical for authz: `sdlc`)

---

## Recommendations Priority

### Immediate (P0)

1. **Change global security config from permitAll to authenticated**
   - Except: `/heartbeat`, `/health`, `/info`
   - Add authentication provider configuration

2. **Protect /accounts endpoint**
   - Add `@PreAuthorize("isAuthenticated()")` at minimum
   - Consider requiring OPS or MASTER role

3. **Enforce user presence in UserHeaderFilter**
   - Reject requests without valid user profile
   - Return 401 Unauthorized

### High Priority (P1)

4. **Enable CSRF protection**
   - Or document why header-based auth makes it unnecessary

5. **Protect information disclosure endpoints**
   - `/sources`, `/sourceTypes`, `/rotationUserManual`, `/validActiveDirectoryRegularExpression`
   - Require authentication

6. **Fix auth/role endpoint**
   - Add explicit authentication check
   - Consider rate limiting

### Medium Priority (P2)

7. **Create typed DTO for rotate endpoint**
   - Replace `Map<String,String>` with `RotateRequest` class

8. **Fix authorization consistency**
   - Apply same authz level to list and read operations
   - Or filter list results based on read permissions

9. **Remove client-controlled audit fields**
   - Don't allow `lastUpdatedBy` in requests
   - Set server-side only

10. **Add rate limiting**
    - Especially for secret reads and auth endpoints

### Low Priority (P3)

11. **Implement global exception handler**
    - Sanitize error messages

12. **Centralize audit logging**
    - Consider separate audit log for compliance

---

## Appendix: Authorization Logic Summary

### Role Hierarchy

```
MASTER
├─ Full access to all accounts (including prod)
├─ Can delete in prod
└─ No application membership required

OPS
├─ Full read/write access to all accounts
├─ Cannot delete in prod accounts
└─ No application membership required

DEV
├─ Read/write access to non-prod accounts only
├─ Requires LDAP membership in specific application (uppercase)
└─ Cannot access prod accounts

UNAUTHORIZED
└─ No access (role assigned when user has no LDAP memberships)
```

### SDLC-Based Authorization (DEV Role)

```java
// DEV role access check
if (account.sdlc == "prod") {
    return false;  // DEV never accesses prod
}

if (user.ldapMemberships.contains(application.toUpperCase())) {
    return true;   // DEV can access if member of application
}

return false;
```

### Delete Operation Authorization

```
Delete in PROD account:
  ✓ MASTER only

Delete in NON-PROD account:
  ✓ MASTER
  ✓ OPS
  ✓ DEV (if application member)
```

---

**END OF REPORT**
