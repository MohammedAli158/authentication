---
name: springboot-jwt-cookie-auth
description: Replicates the OnePOS Spring Boot authentication service — stateless JWT stored in an HttpOnly cookie, BCrypt passwords, role-based access (SUPERADMIN / ADMIN / STOREADMIN / CASHIER), brand/business-type claims resolved from DB at login, generated-password onboarding emails, and a first-match-wins SecurityFilterChain. Use this skill whenever a Spring Boot 3 project needs login/logout/me endpoints, cookie-based JWT auth, role-gated routes, multi-tenant (brand/store) user context, or "same auth as OnePOS". Trigger even if the user only says "add auth like our POS project".
---

# Spring Boot JWT-in-Cookie Auth (OnePOS pattern)

This document is a complete blueprint. Follow the sections in order and the result behaves identically to the OnePOS auth module.

---

## 1. What this system does (behavioural contract)

| Concern | Behaviour |
|---|---|
| Transport | JWT is issued in an **HttpOnly cookie named `jwt`**. No `Authorization` header is read. |
| Session | `STATELESS`. CSRF disabled (mitigated by `SameSite` + CORS allow-list). |
| Passwords | BCrypt (`new BCryptPasswordEncoder()`). |
| Login identifier | Single field resolved via `findByUsernameOrEmail(input)` — username **or** email. |
| JWT signing | HMAC-SHA via `Keys.hmacShaKeyFor(secret.getBytes())`, jjwt **0.12.x** API. |
| JWT claims | `sub`=username, `email`, `iat`, `exp`, and (only when applicable) `brandId`, `businessType`. **Role is NOT in the token.** |
| Per-request auth | `JwtAuthenticationFilter` validates the token, loads the `User` from DB by username, and builds authorities as `ROLE_<role>`. Role changes take effect immediately. |
| Roles | `SUPERADMIN`, `ADMIN` (company/brand admin), `STOREADMIN`, `CASHIER`. |
| Account creation | SUPERADMIN creates brand admins; ADMIN creates store admins. Password is **randomly generated**, BCrypt-hashed, emailed once, never logged. |
| Email failure | Account is still created; a *warning* string is returned and surfaced in the API response. |
| Notifications | Best-effort (try/catch + log) — never fail the main flow. |
| Logout | Best-effort close of cashier counter session, then clears cookie with `maxAge(0)`. |

### Role → brand resolution (done at login and in `/me`)

```
ADMIN       -> Admin      -> Brand
STOREADMIN  -> StoreAdmin -> Brand
CASHIER     -> Cashier    -> Store -> Brand
SUPERADMIN  -> (none)     -> brandId = null, businessType = null
```

---

## 2. Dependencies (`pom.xml`)

Spring Boot **3.x**, Java **17+** (uses `jakarta.*`).

```xml
<dependencies>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-security</artifactId></dependency>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-validation</artifactId></dependency>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-data-jpa</artifactId></dependency>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-mail</artifactId></dependency>

    <!-- jjwt 0.12.x — required: code uses Jwts.parser().verifyWith(...) and Jwts.builder().subject(...) -->
    <dependency><groupId>io.jsonwebtoken</groupId><artifactId>jjwt-api</artifactId><version>0.12.6</version></dependency>
    <dependency><groupId>io.jsonwebtoken</groupId><artifactId>jjwt-impl</artifactId><version>0.12.6</version><scope>runtime</scope></dependency>
    <dependency><groupId>io.jsonwebtoken</groupId><artifactId>jjwt-jackson</artifactId><version>0.12.6</version><scope>runtime</scope></dependency>

    <dependency><groupId>org.projectlombok</groupId><artifactId>lombok</artifactId><optional>true</optional></dependency>
    <!-- Optional: swagger paths are whitelisted in SecurityConfig -->
    <dependency><groupId>org.springdoc</groupId><artifactId>springdoc-openapi-starter-webmvc-ui</artifactId><version>2.6.0</version></dependency>
</dependencies>
```

---

## 3. Configuration (`application.properties`)

```properties
# >= 32 bytes (256 bits) or Keys.hmacShaKeyFor throws WeakKeyException
jwt.secret=${JWT_SECRET}
# e.g. 96h = 345600000. Keep in sync with cookie maxAge in AuthController (96h).
jwt.expirationMs=345600000

# Local dev:  secure=false, samesite=Lax
# Prod, frontend on a different domain (e.g. Vercel): secure=true, samesite=None
app.cookie.secure=${COOKIE_SECURE:false}
app.cookie.samesite=${COOKIE_SAMESITE:Lax}
```

Frontend requirement: every request must send credentials (`fetch(..., {credentials: 'include'})` / `axios.defaults.withCredentials = true`), and the frontend origin must be in the CORS allow-list.

---

## 4. Package layout

```
com.<root>.authentication
├── api            AuthController
├── application    AuthService, UserContextService
├── domain         User, UserRepository, LoginRequest, LoginResponse, MeResponse,
│                  SignUpRequest, SignUpResponse, StoreAdminRequest
└── security       SecurityConfig, JwtAuthenticationFilter, JwtUtil
com.<root>.user.domain          Role (enum)
com.<root>.common.api           ApiResponse<T>
com.<root>.common.exception     ConflictException, ForbiddenException, ResourceNotFoundException,
                                UnauthorizedException, ValidationException (+ GlobalExceptionHandler)
com.<root>.common.mail          MailService
com.<root>.common.util          RandomPasswordGenerator
```

### Replication tiers — what you actually need

- **Tier 1 (core auth, any project):** `User`, `Role`, `UserRepository`, `JwtUtil`, `JwtAuthenticationFilter`, `SecurityConfig`, `AuthController`, `AuthService` (login/logout/me/signUp), exceptions, `ApiResponse`.
- **Tier 2 (admin onboarding):** `createBrandAdmin`, `createStoreAdmin`, `MailService`, `RandomPasswordGenerator`.
- **Tier 3 (multi-tenant POS):** `Admin`, `StoreAdmin`, `Cashier`, `Brand`, `Store` entities and repositories, `UserContextService`, brand claims in JWT, `CounterService`, `NotificationTriggerService`.

If the new project is not multi-tenant, drop Tier 3 and delete the brand branches in `resolveBrandContext` (Section 8).

---

## 5. Domain layer

### 5.1 `Role`

```java
package com.onepos.user.domain;

public enum Role { SUPERADMIN, ADMIN, STOREADMIN, CASHIER }
```

### 5.2 `User` entity (reconstructed from usage — the original file was not provided)

Used members: `getId, getName/setName, getUsername/setUsername, getEmail/setEmail, getPassword/setPassword, getRole/setRole`.

```java
@Entity
@Table(name = "users")   // "user" is reserved in several DBs
@Getter @Setter @NoArgsConstructor
public class User {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;            // BCrypt hash only

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;
}
```

### 5.3 `UserRepository`

`findByUsernameOrEmail` takes **one** string and matches it against both columns. It returns `Optional<User>`.

```java
public interface UserRepository extends JpaRepository<User, Long> {

    @Query("SELECT u FROM User u WHERE u.username = :value OR u.email = :value")
    Optional<User> findByUsernameOrEmail(@Param("value") String value);
}
```

> Because the lookup is shared, usernames and emails must never collide with each other. The uniqueness checks in `createBrandAdmin` / `createStoreAdmin` (check username, then check email, both through this method) enforce that.

### 5.4 DTOs

```java
@Getter @Setter
public class LoginRequest {
    private String username;                 // either may be supplied
    private String email;
    @NotBlank private String password;
}

@Getter @Setter
public class LoginResponse { private String message; }

@Getter @Setter
public class SignUpRequest {
    @NotBlank private String username;
    @Email @NotBlank private String email;
    @NotBlank @Size(min = 8) private String password;
}

@Getter @Setter
public class SignUpResponse { private String username; private String message; }

@Getter @Builder
public class MeResponse {
    private String username;
    private String email;
    private String role;
    private Long brandId;
    private String businessType;
}

@Getter @Setter
public class StoreAdminRequest {
    private Store store;          // ⚠ see Security Notes #7 — prefer IDs
    private Brand brand;
    @NotBlank private String adminName;
    @Email @NotBlank private String adminEmail;
    @NotBlank private String adminUsername;
}
```

### 5.5 Tier-3 entities required by the services (minimum shape)

```java
// Admin:      user (OneToOne User), brand (ManyToOne Brand), createdBy (ManyToOne User)   @Builder
// StoreAdmin: user, brand, store (ManyToOne Store), createdBy, email                       @Builder
// Cashier:    user, store (ManyToOne Store)  — cashier.getId() is passed to counterService
// Brand:      id, businessType (String)
// Store:      id, storeName, brand (ManyToOne Brand)
//
// Each of AdminRepository / StoreAdminRepository / CashierRepository needs:
//     Optional<X> findByUserId(Long userId);
```

---

## 6. Common layer

### 6.1 Exceptions → HTTP status mapping

Create five unchecked exceptions (each extends `RuntimeException`, constructor takes `String message`) and map them in a `@RestControllerAdvice`. **This handler was not in the provided files — without it every one of these becomes a 500.**

| Exception | HTTP |
|---|---|
| `ValidationException` | 400 |
| `UnauthorizedException` | 401 |
| `ForbiddenException` | 403 |
| `ResourceNotFoundException` | 404 |
| `ConflictException` | 409 |

```java
@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(ValidationException.class)
    ResponseEntity<ApiResponse<Void>> v(ValidationException e) { return build(HttpStatus.BAD_REQUEST, e); }
    @ExceptionHandler(UnauthorizedException.class)
    ResponseEntity<ApiResponse<Void>> u(UnauthorizedException e) { return build(HttpStatus.UNAUTHORIZED, e); }
    @ExceptionHandler(ForbiddenException.class)
    ResponseEntity<ApiResponse<Void>> f(ForbiddenException e) { return build(HttpStatus.FORBIDDEN, e); }
    @ExceptionHandler(ResourceNotFoundException.class)
    ResponseEntity<ApiResponse<Void>> n(ResourceNotFoundException e) { return build(HttpStatus.NOT_FOUND, e); }
    @ExceptionHandler(ConflictException.class)
    ResponseEntity<ApiResponse<Void>> c(ConflictException e) { return build(HttpStatus.CONFLICT, e); }

    private ResponseEntity<ApiResponse<Void>> build(HttpStatus s, RuntimeException e) {
        return ResponseEntity.status(s).body(ApiResponse.error(e.getMessage()));
    }
}
```

### 6.2 `ApiResponse<T>` (reconstructed)

The code calls `ApiResponse.ok(data)` and `ApiResponse.warning(data, warningMessage)`.

```java
@Getter
public class ApiResponse<T> {
    private final boolean success;
    private final T data;
    private final String warning;
    private final String error;

    private ApiResponse(boolean success, T data, String warning, String error) {
        this.success = success; this.data = data; this.warning = warning; this.error = error;
    }
    public static <T> ApiResponse<T> ok(T data)                  { return new ApiResponse<>(true, data, null, null); }
    public static <T> ApiResponse<T> warning(T data, String w)   { return new ApiResponse<>(true, data, w, null); }
    public static <T> ApiResponse<T> error(String message)       { return new ApiResponse<>(false, null, null, message); }
}
```

### 6.3 `RandomPasswordGenerator`

```java
public final class RandomPasswordGenerator {
    private static final String CHARS =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";
    private static final SecureRandom RANDOM = new SecureRandom();   // must be SecureRandom

    private RandomPasswordGenerator() {}

    public static String generate() {
        StringBuilder sb = new StringBuilder(12);
        for (int i = 0; i < 12; i++) sb.append(CHARS.charAt(RANDOM.nextInt(CHARS.length())));
        return sb.toString();
    }
}
```

### 6.4 `MailService` contract

```java
public interface MailService {
    /** @return true if sent, false if delivery failed. MUST NOT throw. */
    boolean sendGeneratedPasswordEmail(String toEmail, String username, String plainPassword);
}
```

Implementation: `JavaMailSender` + `SimpleMailMessage`/`MimeMessage`, wrapped in try/catch returning `false` on failure. Add `spring.mail.*` properties.

---

## 7. Security layer

### 7.1 `JwtUtil`

```java
@Component
public class JwtUtil {
    private final SecretKey secretKey;

    public JwtUtil(@Value("${jwt.secret}") String secret) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public Claims extractClaims(String token) {
        return Jwts.parser().verifyWith(secretKey).build()
                .parseSignedClaims(token).getPayload();
    }
    public String extractUsername(String t)     { return extractClaims(t).getSubject(); }
    public String extractEmail(String t)        { return extractClaims(t).get("email", String.class); }
    public Long   extractBrandId(String t)      { return extractClaims(t).get("brandId", Long.class); }
    public String extractBusinessType(String t) { return extractClaims(t).get("businessType", String.class); }

    public boolean isTokenExpired(String t) {
        return extractClaims(t).getExpiration().before(new Date());
    }
    public boolean validateToken(String t) {
        try { return !isTokenExpired(t); } catch (Exception e) { return false; }
    }
}
```

> `jwtUtil` and `AuthService` each build their own `SecretKey` from the same `jwt.secret` — they must read the identical property.

### 7.2 `JwtAuthenticationFilter`

```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    public JwtAuthenticationFilter(JwtUtil jwtUtil, UserRepository userRepository) {
        this.jwtUtil = jwtUtil; this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String token = extractTokenFromCookie(request);
        if (token == null) { chain.doFilter(request, response); return; }

        if (jwtUtil.validateToken(token)
                && SecurityContextHolder.getContext().getAuthentication() == null) {

            String username = jwtUtil.extractUsername(token);
            Optional<User> userOpt = userRepository.findByUsernameOrEmail(username);

            if (userOpt.isPresent()) {
                User user = userOpt.get();
                var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()));

                var authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        chain.doFilter(request, response);
    }

    private String extractTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (Cookie c : cookies) if ("jwt".equals(c.getName())) return c.getValue();
        return null;
    }
}
```

Key facts: principal is the **username String** (not a `UserDetails`), so `authentication.getName()` returns the username everywhere in the services.

### 7.3 `SecurityConfig`

```java
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    public SecurityConfig(JwtAuthenticationFilter f) { this.jwtAuthenticationFilter = f; }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                // ---- PUBLIC ----
                .requestMatchers("/api/auth/login", "/swagger-ui/**", "/v3/api-docs/**",
                                 "/api/queue/join", "/api/queue/status/**", "/api/queue/vapidPublicKey").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/custom-website/lookup/**").permitAll()

                // Public storefront — MUST precede "/api/ecommerce/storefront/**" (ADMIN)
                .requestMatchers(HttpMethod.GET,
                        "/api/ecommerce/storefront/*/products",
                        "/api/ecommerce/storefront/*/products/*",
                        "/api/ecommerce/storefront/*/locations",
                        "/api/ecommerce/storefront/*/categories",
                        "/api/ecommerce/storefront/*").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/ecommerce/storefront/*/hero-images").permitAll()
                .requestMatchers(HttpMethod.POST,
                        "/api/ecommerce/storefront/*/orders",
                        "/api/ecommerce/storefront/*/orders/cancel").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/ecommerce/storefront/*/orders/status").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/ecommerce/storefront/*/payments/checkout").permitAll()
                .requestMatchers(HttpMethod.GET,  "/api/ecommerce/storefront/*/payments/status").permitAll()

                // ---- SUPERADMIN ----
                .requestMatchers("/api/auth/signup").hasRole("SUPERADMIN")

                // ---- BRAND / CATALOG ----
                .requestMatchers("/brand/**").hasAnyRole("SUPERADMIN", "ADMIN", "STOREADMIN")
                .requestMatchers("/api/categories/bulk-upload/**").hasRole("ADMIN")
                .requestMatchers("/api/categories/**").hasAnyRole("STOREADMIN", "ADMIN")
                .requestMatchers("/api/products/bulk-upload/**").hasRole("ADMIN")
                // barcode BEFORE general products rule so CASHIER is allowed on this route only
                .requestMatchers(HttpMethod.GET, "/api/products/barcode").hasAnyRole("CASHIER", "STOREADMIN", "ADMIN")
                .requestMatchers("/api/products/**").hasAnyRole("STOREADMIN", "ADMIN")

                // ---- E-COMMERCE ADMIN ----
                .requestMatchers("/api/custom-website/**").hasAnyRole("ADMIN")
                .requestMatchers("/api/ecommerce/payment-gateway/**").hasRole("ADMIN")
                .requestMatchers("/api/ecommerce/hero-images", "/api/ecommerce/hero-images/**").hasRole("ADMIN")
                .requestMatchers("/api/ecommerce/dashboard").hasAnyRole("ADMIN")
                .requestMatchers("/api/ecommerce/storefront/**").hasAnyRole("ADMIN")
                .requestMatchers("/api/ecommerce/orders/**").hasAnyRole("ADMIN")
                .requestMatchers("/api/ecommerce/delivery/**").hasAnyRole("ADMIN")

                // ---- DISCOUNTS ----
                .requestMatchers(HttpMethod.POST,   "/api/discounts").hasRole("ADMIN")
                .requestMatchers(HttpMethod.PUT,    "/api/discounts/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/api/discounts/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.GET,    "/api/discounts/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.POST,   "/api/discounts/validate").hasAnyRole("CASHIER", "STOREADMIN", "ADMIN")

                // ---- AUTHENTICATED ----
                .requestMatchers("/api/auth/me").authenticated()

                // ---- ORDERS ----
                .requestMatchers(HttpMethod.POST, "/api/orders/**").hasAnyRole("CASHIER", "ADMIN")
                .requestMatchers(HttpMethod.GET,  "/api/orders/all").hasAnyRole("CASHIER", "STOREADMIN", "ADMIN", "SUPERADMIN")
                .requestMatchers(HttpMethod.GET,  "/api/orders/brand/dashboard").hasRole("ADMIN")
                .requestMatchers("/api/orders/**").hasAnyRole("CASHIER", "STOREADMIN", "ADMIN", "SUPERADMIN")

                // ---- MISC DOMAIN ----
                .requestMatchers("/api/crm/**").hasAnyRole("STOREADMIN", "ADMIN")
                .requestMatchers("/inventory/**").hasAnyRole("STOREADMIN", "ADMIN")
                .requestMatchers(HttpMethod.GET, "/api/layouts/**").hasAnyRole("CASHIER", "STOREADMIN", "ADMIN")
                .requestMatchers("/api/layouts/**").hasAnyRole("STOREADMIN", "ADMIN")
                .requestMatchers("/api/refunds/**").hasAnyRole("CASHIER", "ADMIN")
                .requestMatchers("/api/admin/gateway-credentials/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.POST, "/api/payments/checkout").permitAll()
                .requestMatchers("/api/b2b/**").hasAnyRole("CASHIER", "STOREADMIN", "ADMIN")
                .requestMatchers(HttpMethod.GET, "/api/payments/status").permitAll()
                .requestMatchers("/stock-receipt/**").hasAnyRole("STOREADMIN", "ADMIN")

                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/webhooks/**").permitAll()   // signature verified in handler

                .requestMatchers("/api/queue/store/**").hasAnyRole("CASHIER", "STOREADMIN", "ADMIN")
                .requestMatchers(HttpMethod.PATCH, "/api/queue/**").hasAnyRole("CASHIER", "STOREADMIN", "ADMIN")

                .requestMatchers("/error").permitAll()
                .anyRequest().authenticated());

        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration c = new CorsConfiguration();
        c.setAllowedOrigins(List.of(
                "http://localhost:5173",
                "http://localhost:5174",
                "https://one-pos-frontend.vercel.app",
                "https://one-pos-ecom-templates.vercel.app",
                "https://one-pos.onepathsolutions.com"));
        c.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        c.setAllowedHeaders(List.of("*"));
        c.setAllowCredentials(true);           // required for the cookie to be accepted cross-origin
        c.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
        src.registerCorsConfiguration("/**", c);
        return src;
    }
}
```

**The URL rules above are POS-specific.** For a new project, keep the *skeleton* and swap the domain matchers:

1. Public routes (`/api/auth/login`, swagger, `/error`, OPTIONS).
2. `/api/auth/signup` → `SUPERADMIN`.
3. `/api/auth/me` → `authenticated()`.
4. Your own role-gated route groups.
5. `.anyRequest().authenticated()` last.

**Rule order is law**: Spring Security uses the first match. Specific rules (e.g. `GET /api/products/barcode`, public storefront GETs) must be declared before the broad wildcard that would otherwise capture them.

---

## 8. Application layer

### 8.1 `AuthService`

Constructor-injected dependencies: `UserRepository`, `AdminRepository`, `StoreAdminRepository`, `CashierRepository`, `MailService`, `NotificationTriggerService`, `CounterService`, plus `@Value` `jwt.secret` and `jwt.expirationMs`. `PasswordEncoder` is created inline as `new BCryptPasswordEncoder()`. Cookie flags are field-injected with `@Value("${app.cookie.secure}")` / `@Value("${app.cookie.samesite}")`.

The original duplicates the brand-resolution block in `login()` and `getCurrentUser()`. The version below extracts it into one helper; **error messages and behaviour are identical**.

```java
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final AdminRepository adminRepository;
    private final StoreAdminRepository storeAdminRepository;
    private final CashierRepository cashierRepository;
    private final MailService mailService;
    private final PasswordEncoder passwordEncoder;
    private final SecretKey secretKey;
    private final long jwtExpirationMs;
    private final NotificationTriggerService notificationTriggerService;
    private final CounterService counterService;

    @Value("${app.cookie.secure}")   private boolean cookieSecure;
    @Value("${app.cookie.samesite}") private String cookieSameSite;

    public AuthService(UserRepository userRepository, AdminRepository adminRepository,
                       StoreAdminRepository storeAdminRepository, CashierRepository cashierRepository,
                       MailService mailService, NotificationTriggerService notificationTriggerService,
                       CounterService counterService,
                       @Value("${jwt.secret}") String secret,
                       @Value("${jwt.expirationMs}") long jwtExpirationMs) {
        this.userRepository = userRepository;
        this.adminRepository = adminRepository;
        this.storeAdminRepository = storeAdminRepository;
        this.cashierRepository = cashierRepository;
        this.mailService = mailService;
        this.notificationTriggerService = notificationTriggerService;
        this.counterService = counterService;
        this.passwordEncoder = new BCryptPasswordEncoder();
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes());
        this.jwtExpirationMs = jwtExpirationMs;
    }

    // ---------------------------------------------------------------- SIGN UP (SUPERADMIN only)
    public SignUpResponse signUp(SignUpRequest request) {
        String creatorUsername = SecurityContextHolder.getContext().getAuthentication().getName();

        User creator = userRepository.findByUsernameOrEmail(creatorUsername)
                .orElseThrow(() -> new ResourceNotFoundException("Authenticated user not found"));

        if (creator.getRole() != Role.SUPERADMIN)
            throw new ForbiddenException("Only superadmins can create accounts");

        if (userRepository.findByUsernameOrEmail(request.getUsername()).isPresent())
            throw new ConflictException("Username already exists");

        User newUser = new User();
        newUser.setUsername(request.getUsername());
        newUser.setEmail(request.getEmail());
        newUser.setPassword(passwordEncoder.encode(request.getPassword()));
        newUser.setRole(Role.ADMIN);

        User saved = userRepository.save(newUser);

        SignUpResponse r = new SignUpResponse();
        r.setUsername(saved.getUsername());
        r.setMessage("User registered successfully");
        return r;
    }

    // ---------------------------------------------------------------- LOGIN → returns JWT string
    public String login(LoginRequest request) {
        String input = (request.getUsername() != null && !request.getUsername().isBlank())
                ? request.getUsername() : request.getEmail();

        if (input == null || input.isBlank())
            throw new ValidationException("Username or email is required");

        User user = userRepository.findByUsernameOrEmail(input)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "No account found with username/email: " + input));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword()))
            throw new ForbiddenException("Incorrect password for account: " + user.getUsername());

        BrandContext ctx = resolveBrandContext(user);
        return generateJwtToken(user, ctx.brandId(), ctx.businessType());
    }

    // ---------------------------------------------------------------- CREATE BRAND ADMIN (SUPERADMIN)
    /** @return null on full success, or a warning string if the email failed. */
    public String createBrandAdmin(Brand brand, String adminName, String adminEmail, String adminUsername) {
        User creator = getAuthenticatedUser();
        if (creator.getRole() != Role.SUPERADMIN)
            throw new ForbiddenException("Only superadmins can create admins");

        if (userRepository.findByUsernameOrEmail(adminUsername).isPresent())
            throw new ConflictException("Username already exists");
        if (userRepository.findByUsernameOrEmail(adminEmail).isPresent())
            throw new ConflictException("Email already exists");

        String generatedPassword = RandomPasswordGenerator.generate();

        User user = new User();
        user.setName(adminName);
        user.setUsername(adminUsername);
        user.setEmail(adminEmail);
        user.setPassword(passwordEncoder.encode(generatedPassword));
        user.setRole(Role.ADMIN);
        User savedUser = userRepository.save(user);

        adminRepository.save(Admin.builder().user(savedUser).brand(brand).createdBy(creator).build());

        boolean emailSent = mailService.sendGeneratedPasswordEmail(adminEmail, adminUsername, generatedPassword);

        return emailSent ? null
                : "Account created, but the password email could not be sent to " + adminEmail;
    }

    // ---------------------------------------------------------------- CREATE STORE ADMIN (ADMIN)
    public String createStoreAdmin(Store store, Brand brand, String adminName,
                                   String adminEmail, String adminUsername) {
        User creator = getAuthenticatedUser();
        if (creator.getRole() != Role.ADMIN)
            throw new ForbiddenException("Only admins can create store admins");

        Admin admin = adminRepository.findByUserId(creator.getId())
                .orElseThrow(() -> new ResourceNotFoundException("Admin is not associated with a brand"));

        if (!admin.getBrand().getId().equals(brand.getId())
                || !store.getBrand().getId().equals(brand.getId()))
            throw new ForbiddenException("Store does not belong to the admin's brand");

        if (userRepository.findByUsernameOrEmail(adminUsername).isPresent())
            throw new ConflictException("Username already exists");
        if (userRepository.findByUsernameOrEmail(adminEmail).isPresent())
            throw new ConflictException("Email already exists");

        String generatedPassword = RandomPasswordGenerator.generate();

        User user = new User();
        user.setName(adminName);
        user.setUsername(adminUsername);
        user.setEmail(adminEmail);
        user.setPassword(passwordEncoder.encode(generatedPassword));
        user.setRole(Role.STOREADMIN);
        User savedUser = userRepository.save(user);

        storeAdminRepository.save(StoreAdmin.builder()
                .user(savedUser).brand(brand).store(store).createdBy(creator).email(adminEmail).build());

        boolean emailSent = mailService.sendGeneratedPasswordEmail(adminEmail, adminUsername, generatedPassword);

        // Best-effort notification — must never break account creation
        try {
            notificationTriggerService.triggerStoreAdminCreated(
                    brand.getId(), store.getId(), store.getStoreName(), adminName, savedUser.getId());
        } catch (Exception ex) {
            log.warn("Failed to send STORE_ADMIN_CREATED notification for store={}, user={}: {}",
                    store.getId(), savedUser.getId(), ex.getMessage());
        }

        return emailSent ? null
                : "Account created, but the password email could not be sent to " + adminEmail;
    }

    // ---------------------------------------------------------------- UPDATE STORE ADMIN
    public void updateStoreAdmin(User user, String adminName, String adminEmail,
                                 String adminUsername, String adminPassword) {
        if (adminUsername == null || adminUsername.isBlank())
            throw new ValidationException("Admin username is required");
        if (adminEmail == null || adminEmail.isBlank())
            throw new ValidationException("Admin email is required");

        Optional<User> byUsername = userRepository.findByUsernameOrEmail(adminUsername);
        if (byUsername.isPresent() && !byUsername.get().getId().equals(user.getId()))
            throw new ConflictException("Username already exists");

        Optional<User> byEmail = userRepository.findByUsernameOrEmail(adminEmail);
        if (byEmail.isPresent() && !byEmail.get().getId().equals(user.getId()))
            throw new ConflictException("Email already exists");

        user.setName(adminName);
        user.setEmail(adminEmail);
        user.setUsername(adminUsername);

        if (adminPassword != null && !adminPassword.isBlank()) {
            if (adminPassword.length() < 8)
                throw new ValidationException("Password must be at least 8 characters");
            user.setPassword(passwordEncoder.encode(adminPassword));
        }
        userRepository.save(user);
    }

    // ---------------------------------------------------------------- LOGOUT
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        // Best effort: also free the cashier's counter. Never block the cookie clear.
        try {
            Authentication a = SecurityContextHolder.getContext().getAuthentication();
            if (a != null && a.isAuthenticated() && !"anonymousUser".equals(a.getPrincipal())) {
                userRepository.findByUsernameOrEmail(a.getName()).ifPresent(user ->
                        cashierRepository.findByUserId(user.getId()).ifPresent(cashier ->
                                counterService.closeOpenSessionsForCashier(cashier.getId())));
            }
        } catch (Exception ex) {
            log.warn("Failed to close counter session on logout: {}", ex.getMessage());
        }

        ResponseCookie deleteCookie = ResponseCookie.from("jwt", "")
                .httpOnly(true).secure(cookieSecure).path("/").maxAge(0).sameSite(cookieSameSite).build();
        response.addHeader(HttpHeaders.SET_COOKIE, deleteCookie.toString());
    }

    // ---------------------------------------------------------------- /me
    public MeResponse getCurrentUser() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        if (a == null || !a.isAuthenticated() || "anonymousUser".equals(a.getPrincipal()))
            throw new UnauthorizedException("Not authenticated");

        User user = userRepository.findByUsernameOrEmail(a.getName())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        BrandContext ctx = resolveBrandContext(user);

        return MeResponse.builder()
                .username(user.getUsername())
                .email(user.getEmail())
                .role(user.getRole().name())
                .brandId(ctx.brandId())
                .businessType(ctx.businessType())
                .build();
    }

    // ---------------------------------------------------------------- helpers
    private record BrandContext(Long brandId, String businessType) {}

    private BrandContext resolveBrandContext(User user) {
        Brand brand;

        if (user.getRole() == Role.ADMIN) {
            Admin admin = adminRepository.findByUserId(user.getId())
                    .orElseThrow(() -> new ResourceNotFoundException(
                            "Admin record not found for user: " + user.getUsername()));
            brand = admin.getBrand();
            if (brand == null)
                throw new ResourceNotFoundException("Brand not found for admin: " + user.getUsername());

        } else if (user.getRole() == Role.STOREADMIN) {
            StoreAdmin sa = storeAdminRepository.findByUserId(user.getId())
                    .orElseThrow(() -> new ResourceNotFoundException(
                            "StoreAdmin record not found for user: " + user.getUsername()));
            brand = sa.getBrand();
            if (brand == null)
                throw new ResourceNotFoundException("Brand not found for store admin: " + user.getUsername());

        } else if (user.getRole() == Role.CASHIER) {
            Cashier cashier = cashierRepository.findByUserId(user.getId())
                    .orElseThrow(() -> new ResourceNotFoundException(
                            "Cashier record not found for user: " + user.getUsername()));
            Store store = cashier.getStore();
            if (store == null)
                throw new ResourceNotFoundException("Store not found for cashier: " + user.getUsername());
            brand = store.getBrand();
            if (brand == null)
                throw new ResourceNotFoundException("Brand not found for cashier: " + user.getUsername());

        } else {
            return new BrandContext(null, null);   // SUPERADMIN / others
        }
        return new BrandContext(brand.getId(), brand.getBusinessType());
    }

    private User getAuthenticatedUser() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        if (a == null || !a.isAuthenticated() || "anonymousUser".equals(a.getPrincipal()))
            throw new UnauthorizedException("User is not authenticated");
        return userRepository.findByUsernameOrEmail(a.getName())
                .orElseThrow(() -> new ResourceNotFoundException("Authenticated user not found"));
    }

    private String generateJwtToken(User user, Long brandId, String businessType) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + jwtExpirationMs);

        var builder = Jwts.builder()
                .subject(user.getUsername())
                .claim("email", user.getEmail())
                .issuedAt(now)
                .expiration(expiry)
                .signWith(secretKey);

        if (brandId != null)      builder.claim("brandId", brandId);
        if (businessType != null) builder.claim("businessType", businessType);

        return builder.compact();
    }
}
```

### 8.2 `UserContextService`

Resolves "which brand / which store is this user operating on" and enforces brand isolation for ADMINs. Other services inject this instead of re-implementing the lookups.

```java
@Service
public class UserContextService {

    private final AdminRepository adminRepository;
    private final StoreAdminRepository storeAdminRepository;
    private final CashierRepository cashierRepository;
    private final StoreRepository storeRepository;
    private final UserRepository userRepository;

    // constructor injection of all five ...

    public Optional<Brand> findBrand(User user) {
        if (user.getRole() == Role.ADMIN)
            return adminRepository.findByUserId(user.getId()).map(a -> a.getBrand());
        if (user.getRole() == Role.STOREADMIN)
            return storeAdminRepository.findByUserId(user.getId()).map(sa -> sa.getBrand());
        return Optional.empty();
    }

    public Brand resolveBrand(User user) {
        return findBrand(user).orElseThrow(() -> new RuntimeException("User is not associated with a brand"));
    }

    public Optional<Store> findStore(User user) {
        if (user.getRole() == Role.STOREADMIN)
            return storeAdminRepository.findByUserId(user.getId()).map(sa -> sa.getStore());
        if (user.getRole() == Role.CASHIER)
            return cashierRepository.findByUserId(user.getId()).map(c -> c.getStore());
        if (user.getRole() == Role.ADMIN)   // admin-as-cashier: Cashier row supplies store context
            return cashierRepository.findByUserId(user.getId()).map(c -> c.getStore());
        return Optional.empty();
    }

    public Store resolveStore(User user) {
        return findStore(user).orElseThrow(() -> new RuntimeException("User is not associated with a store"));
    }

    /** ADMIN must pass storeId (validated against own brand). STOREADMIN/CASHIER use own store;
     *  a passed storeId must match it. */
    public Store resolveScopedStore(User user, Long requestedStoreId) {
        if (user.getRole() == Role.ADMIN) {
            if (requestedStoreId == null)
                throw new ValidationException("storeId is required for company admins");
            Brand brand = resolveBrand(user);
            Store store = storeRepository.findById(requestedStoreId)
                    .orElseThrow(() -> new ResourceNotFoundException("Store not found: " + requestedStoreId));
            if (!brand.getId().equals(store.getBrand().getId()))
                throw new ForbiddenException("Store does not belong to your brand");
            return store;
        }
        Store own = resolveStore(user);
        if (requestedStoreId != null && !requestedStoreId.equals(own.getId()))
            throw new ForbiddenException("You are not authorized to access this store");
        return own;
    }

    /** Brand gate: no-op for non-ADMIN roles and null storeId. */
    public void ensureAdminCanAccessStore(Long storeId) {
        if (storeId == null) return;
        ensureAdminCanAccessStore(getAuthenticatedUser(), storeId);
    }

    public void ensureAdminCanAccessStore(User user, Long storeId) {
        if (user.getRole() != Role.ADMIN || storeId == null) return;
        Brand brand = resolveBrand(user);
        Store store = storeRepository.findById(storeId)
                .orElseThrow(() -> new ResourceNotFoundException("Store not found: " + storeId));
        if (!brand.getId().equals(store.getBrand().getId()))
            throw new ForbiddenException("You are not authorized to access this store");
    }

    public User getAuthenticatedUser() {
        if (SecurityContextHolder.getContext().getAuthentication() == null)
            throw new ForbiddenException("User is not authenticated");
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        return userRepository.findByUsernameOrEmail(username)
                .orElseThrow(() -> new ResourceNotFoundException("Authenticated user not found"));
    }
}
```

Usage pattern in any feature service:

```java
User user = userContextService.getAuthenticatedUser();
Store store = userContextService.resolveScopedStore(user, request.getStoreId());   // tenant-safe
// or, when you already have a storeId from a path/body:
userContextService.ensureAdminCanAccessStore(storeId);
```

---

## 9. API layer — `AuthController`

Base path `/api/auth`.

```java
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    @Value("${app.cookie.secure}")   private boolean cookieSecure;
    @Value("${app.cookie.samesite}") private String cookieSameSite;

    public AuthController(AuthService authService) { this.authService = authService; }

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<SignUpResponse>> signUp(@Valid @RequestBody SignUpRequest request) {
        return ResponseEntity.ok(ApiResponse.ok(authService.signUp(request)));
    }

    @PostMapping("/create-store-admin")
    public ResponseEntity<ApiResponse<String>> createStoreAdmin(@Valid @RequestBody StoreAdminRequest request) {
        String warning = authService.createStoreAdmin(
                request.getStore(), request.getBrand(),
                request.getAdminName(), request.getAdminEmail(), request.getAdminUsername());

        if (warning == null)
            return ResponseEntity.ok(ApiResponse.ok("Store admin created successfully"));
        return ResponseEntity.ok(ApiResponse.warning("Store admin created successfully", warning));
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<MeResponse>> getCurrentUser() {
        return ResponseEntity.ok(ApiResponse.ok(authService.getCurrentUser()));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest request,
                                                            HttpServletResponse httpResponse) {
        String token = authService.login(request);

        ResponseCookie cookie = ResponseCookie.from("jwt", token)
                .httpOnly(true)
                .secure(cookieSecure)
                .path("/")
                .maxAge(Duration.ofHours(96))
                .sameSite(cookieSameSite)
                .build();
        httpResponse.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        LoginResponse body = new LoginResponse();
        body.setMessage("Logged In Successfully");
        return ResponseEntity.ok(ApiResponse.ok(body));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(HttpServletRequest request, HttpServletResponse response) {
        authService.logout(request, response);
        return ResponseEntity.ok(ApiResponse.ok(null));
    }
}
```

### Endpoint reference

| Method | Path | Access | Request | Success response |
|---|---|---|---|---|
| POST | `/api/auth/login` | public | `{username? , email?, password}` | `Set-Cookie: jwt=…` + `{message:"Logged In Successfully"}` |
| POST | `/api/auth/logout` | any (cookie optional) | – | cookie cleared |
| GET | `/api/auth/me` | authenticated | – | `{username,email,role,brandId,businessType}` |
| POST | `/api/auth/signup` | SUPERADMIN | `{username,email,password}` | creates an `ADMIN` user |
| POST | `/api/auth/create-store-admin` | ADMIN (checked in service) | `{store,brand,adminName,adminEmail,adminUsername}` | ok or ok+warning |

`/api/auth/create-store-admin` is not listed in `SecurityConfig`; it falls through to `.anyRequest().authenticated()` and the **service** enforces `Role.ADMIN`. Add an explicit `.hasRole("ADMIN")` matcher if you want defence in depth.

---

## 10. Replication checklist

1. Add dependencies (§2) and properties (§3). Generate a ≥32-char secret and keep it in an env var.
2. Create `Role`, `User`, `UserRepository` (§5).
3. Create exceptions + `GlobalExceptionHandler` + `ApiResponse` (§6).
4. Create `JwtUtil`, `JwtAuthenticationFilter`, `SecurityConfig` (§7). Replace the CORS origins and domain URL rules.
5. Create `AuthService` and `AuthController` (§8–9). Remove Tier-2/3 pieces you do not need.
6. Seed a first **SUPERADMIN** manually (BCrypt hash in DB or a `CommandLineRunner`) — there is no endpoint to create the first one.
7. Test:
   - `POST /api/auth/login` → response has `Set-Cookie: jwt=…; HttpOnly`.
   - `GET /api/auth/me` with that cookie → 200; without → 401.
   - Wrong password → 403, unknown user → 404.
   - Role-gated route with wrong role → 403.
   - `POST /api/auth/logout` → cookie cleared (`Max-Age=0`).
8. Frontend: `credentials: 'include'`; on app load call `/api/auth/me` to hydrate the session and read `role`, `brandId`, `businessType`.

### Customisation points

| To change | Edit |
|---|---|
| Token lifetime | `jwt.expirationMs` **and** `Duration.ofHours(96)` in `AuthController.login` (keep them aligned) |
| Allowed frontends | `corsConfigurationSource()` origins |
| Cross-site cookies | `app.cookie.secure=true`, `app.cookie.samesite=None` |
| Add a role | `Role` enum → add its branch to `resolveBrandContext` → add to matchers |
| Add JWT claims | `generateJwtToken` + matching `extractX` in `JwtUtil` |
| Non-tenant app | Delete Admin/StoreAdmin/Cashier/Brand/Store, `resolveBrandContext`, `UserContextService`, brand claims |

---

## 11. Known issues & hardening notes (present in the original — decide whether to carry them over)

1. **User enumeration at login.** Unknown account → 404 "No account found…", wrong password → 403 with the username. Both leak account existence. Safer: return one generic 401 "Invalid credentials" for both.
2. **Wrong password returns 403**, semantically it should be 401.
3. **No brute-force protection.** Add rate limiting / lockout (e.g. Bucket4j or a failed-attempt counter).
4. **Cookie lifetime vs token lifetime** are configured in two places (`jwt.expirationMs` and `Duration.ofHours(96)`). If they drift, the cookie can outlive the token (user appears logged in until the first 401).
5. **No revocation.** Stateless tokens stay valid until expiry. Logout only deletes the cookie client-side. Mitigation: shorter expiry + refresh token, or a token-version column on `User`.
6. **`signUp` creates an `ADMIN` user with no `Admin` row.** That user then fails login with "Admin record not found". It also does not check email uniqueness or set `name`. Prefer routing through `createBrandAdmin`.
7. **`StoreAdminRequest` accepts full `Store` and `Brand` entities from the request body.** The service checks brand consistency against the caller's brand, but binding JPA entities from JSON is fragile. Prefer `storeId` / `brandId` and load them server-side.
8. **Duplicate-check race.** Username/email uniqueness is checked in code, then saved. Keep the DB `UNIQUE` constraints and map `DataIntegrityViolationException` to 409. Add `@Transactional` to `createBrandAdmin` / `createStoreAdmin` so a failed `Admin`/`StoreAdmin` save does not leave an orphan `User`.
9. **CSRF is disabled** while auth is cookie-based. This is safe only with `SameSite=Lax/Strict`, or with `SameSite=None` plus the strict CORS allow-list and no state-changing GETs. Re-evaluate if you ever allow `SameSite=None` broadly.
10. **A DB lookup happens on every authenticated request** (filter loads the `User`). That is what makes role changes immediate; add caching only if it becomes a bottleneck.
11. **Secret handling:** `secret.getBytes()` uses the platform default charset; use `StandardCharsets.UTF_8` for portability. Never commit the secret.
12. **`/me` re-queries the DB** for brand context even though `brandId`/`businessType` are already in the JWT (documented in the original as a temporary migration). The `JwtUtil.extractBrandId` / `extractBusinessType` helpers exist for switching to the claims later.
13. Unused imports/fields in the original `AuthService` (`ResultWithWarning`, the `request` param of `logout`) are harmless and can be dropped.

---

## 12. Files that were NOT provided (reconstructed above from usage)

`User`, `UserRepository`, all DTOs, `Role`, `ApiResponse`, exception classes + handler, `MailService` implementation, `RandomPasswordGenerator`, `Admin`/`StoreAdmin`/`Cashier`/`Brand`/`Store` entities and repositories, `CounterService.closeOpenSessionsForCashier(Long)`, `NotificationTriggerService.triggerStoreAdminCreated(Long brandId, Long storeId, String storeName, String adminName, Long userId)`. When porting, copy the real versions from the OnePOS repo where they exist; the reconstructions here match every call signature used by the provided code.
