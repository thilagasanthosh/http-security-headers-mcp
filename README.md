# http-security-headers-mcp

> MCP server that checks Spring Boot applications for missing or misconfigured HTTP security headers — both in source code and against live endpoints.

## Tools

| Tool | Description |
|------|-------------|
| `checkSecurityConfig` | Scan Spring Security config files and YAMLs for header settings |
| `checkLiveEndpoint` | Fetch a live URL and check which security headers are actually returned |
| `explainHeader` | Get a full explanation + Spring Boot code snippet for any security header |

## Headers Checked

| Header | Severity | What it prevents |
|--------|----------|-----------------|
| `Strict-Transport-Security` | 🔴 HIGH | HTTP downgrade / MITM attacks |
| `Content-Security-Policy` | 🔴 HIGH | XSS, data injection |
| `X-Frame-Options` | 🟠 MEDIUM | Clickjacking |
| `X-Content-Type-Options` | 🟠 MEDIUM | MIME sniffing / drive-by downloads |
| `Referrer-Policy` | 🟡 LOW | Sensitive URL leakage to third parties |
| `Permissions-Policy` | 🟡 LOW | Unwanted access to camera/mic/geolocation |
| `Cache-Control` | 🟡 LOW | Authenticated pages cached after logout |

## Usage with Claude

### HTTP mode (Claude Code)
```bash
mvn spring-boot:run
# Add to claude_desktop_config.json or use via Claude Code
```

### Stdio mode (Claude Desktop)
```bash
mvn spring-boot:run --spring.profiles.active=stdio
```

## Example Conversations

### Check a live endpoint
> "Check the security headers on http://localhost:8080/api/health"

Claude will call `checkLiveEndpoint` and return a report like:
```
✅ X-Content-Type-Options: nosniff
✅ Cache-Control: no-cache, no-store, max-age=0
❌ Content-Security-Policy — MISSING (HIGH)
❌ Strict-Transport-Security — MISSING (HIGH)
❌ X-Frame-Options — MISSING (MEDIUM)
```

### Scan project config
> "Scan my project at /Users/me/myapp/src for security header configuration"

Claude will call `checkSecurityConfig` and identify which headers are configured in your `SecurityFilterChain` beans and `application.yml`.

### Get fix code
> "Explain how to configure Content-Security-Policy in Spring Boot"

Claude will call `explainHeader` and return the exact Java config:
```java
http.headers(h -> h.contentSecurityPolicy(csp ->
    csp.policyDirectives("default-src 'self'; script-src 'self'")));
```

## Complete Spring Security Snippet

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .headers(headers -> headers
            .httpStrictTransportSecurity(hsts -> hsts
                .maxAgeInSeconds(31536000)
                .includeSubDomains(true))
            .contentSecurityPolicy(csp -> csp
                .policyDirectives("default-src 'self'; script-src 'self'"))
            .frameOptions(fo -> fo.deny())
            .contentTypeOptions(Customizer.withDefaults())
            .referrerPolicy(rp -> rp
                .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
            .permissionsPolicy(pp -> pp
                .policy("camera=(), microphone=(), geolocation=()"))
            .cacheControl(Customizer.withDefaults())
        );
    return http.build();
}
```

## Requirements

- Java 21+
- Maven 3.9+
- Spring Boot 3.5.0
- Spring AI 1.0.0 MCP Server

## Build

```bash
mvn clean package
java -jar target/http-security-headers-mcp-0.0.1-SNAPSHOT.jar
```

## Docker

```bash
docker build -t http-security-headers-mcp .
docker run -p 8080:8080 http-security-headers-mcp
```

## Claude Desktop Config

```json
{
  "mcpServers": {
    "http-security-headers": {
      "command": "java",
      "args": [
        "-jar",
        "/path/to/http-security-headers-mcp-0.0.1-SNAPSHOT.jar",
        "--spring.profiles.active=stdio"
      ]
    }
  }
}
```

## Related Projects

- [secret-scanner-mcp](../secret-scanner-mcp) — Detect secrets and credentials in source code
- [owasp-checker-mcp](../owasp-checker-mcp) — OWASP Top 10 AST analysis for Spring Boot
- [jwt-analyser-mcp](../jwt-analyser-mcp) — Decode and audit JWT tokens
- [dependency-vuln-mcp](../dependency-vuln-mcp) — CVE scanning via OSV.dev
- [test-coverage-gap-mcp](../test-coverage-gap-mcp) — Find untested Spring Boot code
