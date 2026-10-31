package com.mcp.httpheaders.tool;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

/**
 * MCP tools for HTTP security header analysis.
 *
 * Three tools:
 *  1. checkSecurityConfig   — scan Spring Security Java config for header settings
 *  2. checkLiveEndpoint     — fetch a URL and report which security headers are present/missing
 *  3. explainHeader         — full explanation + Spring Boot config snippet for a header
 */
@Component
public class HttpHeadersTools {

    private static final Logger log = LoggerFactory.getLogger(HttpHeadersTools.class);

    // All security headers we check
    private static final List<HeaderSpec> REQUIRED_HEADERS = List.of(
        new HeaderSpec("Strict-Transport-Security", "HIGH",
                "Tells browsers to only use HTTPS for your site.",
                "Enables HSTS. Without it, users can be downgraded to HTTP by attackers."),
        new HeaderSpec("Content-Security-Policy", "HIGH",
                "Controls what resources the browser can load — prevents XSS.",
                "Without CSP, XSS attacks can load attacker-controlled scripts."),
        new HeaderSpec("X-Frame-Options", "MEDIUM",
                "Prevents your site from being embedded in an iframe — stops clickjacking.",
                "Without this, attackers can overlay your site in a transparent iframe."),
        new HeaderSpec("X-Content-Type-Options", "MEDIUM",
                "Prevents browsers from MIME-sniffing responses — stops drive-by downloads.",
                "Set to 'nosniff'. Without it, browsers may execute misclassified content."),
        new HeaderSpec("Referrer-Policy", "LOW",
                "Controls how much referrer information is sent with requests.",
                "Leaking referrer URLs can expose sensitive query params to third parties."),
        new HeaderSpec("Permissions-Policy", "LOW",
                "Controls which browser features (camera, mic, geolocation) the page can use.",
                "Prevents embedded third-party scripts from accessing sensitive device features."),
        new HeaderSpec("Cache-Control", "LOW",
                "Prevents sensitive pages from being cached by browsers or proxies.",
                "Without 'no-store', authenticated pages may be served from cache after logout.")
    );

    // ─────────────────────────────────────────────────────────────────────────
    // Tool 1 — Scan Spring Security config files
    // ─────────────────────────────────────────────────────────────────────────

    @Tool(description = """
            Scan a Spring Boot project directory for Spring Security configuration files
            and check whether security headers (CSP, HSTS, X-Frame-Options, etc.) are configured.
            Looks for SecurityFilterChain beans and application.yml header settings.
            Returns which headers are configured, which are missing, and the Spring Boot code to add them.
            """)
    public HeaderConfigReport checkSecurityConfig(
            @ToolParam(description = "Absolute path to the Spring Boot project root or src/ directory")
            String projectPath
    ) {
        log.info("Checking security config in: {}", projectPath);
        Path root = Path.of(projectPath);

        if (!Files.exists(root)) {
            return HeaderConfigReport.error("Path not found: " + projectPath);
        }

        List<String> configFileContents = new ArrayList<>();
        List<String> configFilePaths    = new ArrayList<>();

        try {
            Files.walkFileTree(root, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, java.nio.file.attribute.BasicFileAttributes a) {
                    String name = dir.getFileName() != null ? dir.getFileName().toString() : "";
                    return Set.of("target", "build", ".git").contains(name)
                            ? FileVisitResult.SKIP_SUBTREE : FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, java.nio.file.attribute.BasicFileAttributes a) throws IOException {
                    String name = file.getFileName().toString();
                    boolean isSecurityConfig = name.endsWith(".java") &&
                            (name.toLowerCase().contains("security") || name.toLowerCase().contains("config"));
                    boolean isYaml = name.endsWith(".yml") || name.endsWith(".yaml");

                    if (isSecurityConfig || isYaml) {
                        try {
                            String content = Files.readString(file);
                            if (content.contains("SecurityFilterChain") || content.contains("security:")
                                    || content.contains("headers") || isSecurityConfig) {
                                configFileContents.add(content.toLowerCase());
                                configFilePaths.add(file.toAbsolutePath().toString());
                            }
                        } catch (IOException ignored) {}
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            return HeaderConfigReport.error("Scan failed: " + e.getMessage());
        }

        String combined = String.join("\n", configFileContents);

        List<HeaderCheckResult> results = REQUIRED_HEADERS.stream()
                .map(h -> checkHeaderInConfig(h, combined))
                .collect(Collectors.toList());

        return new HeaderConfigReport(
                projectPath,
                configFilePaths,
                results,
                buildConfigSummary(results),
                SPRING_SECURITY_SNIPPET
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tool 2 — Check live endpoint response headers
    // ─────────────────────────────────────────────────────────────────────────

    @Tool(description = """
            Fetch a live URL and check which HTTP security headers are present or missing in the response.
            Useful for verifying your Spring Boot app is actually sending the headers you configured.
            Works on localhost or any publicly reachable URL.
            """)
    public LiveHeaderReport checkLiveEndpoint(
            @ToolParam(description = "URL to check, e.g. http://localhost:8080/api/health or https://yourapp.com/")
            String url
    ) {
        log.info("Checking live headers at: {}", url);
        try {
            HttpClient client = HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .connectTimeout(Duration.ofSeconds(5))
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();

            HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
            Map<String, String> responseHeaders = new LinkedHashMap<>();
            response.headers().map().forEach((k, v) -> responseHeaders.put(k.toLowerCase(), String.join(", ", v)));

            List<HeaderCheckResult> results = REQUIRED_HEADERS.stream()
                    .map(h -> {
                        boolean found = responseHeaders.containsKey(h.name().toLowerCase());
                        String value  = responseHeaders.get(h.name().toLowerCase());
                        return new HeaderCheckResult(
                                h.name(), h.severity(),
                                found ? "✅ Present" : "❌ Missing",
                                found, value, h.risk(), h.description(), h.springConfig());
                    })
                    .collect(Collectors.toList());

            long missing = results.stream().filter(r -> !r.present()).count();
            String summary = missing == 0
                    ? "✅ All %d security headers present at %s".formatted(REQUIRED_HEADERS.size(), url)
                    : "⚠️ %d of %d security headers missing at %s".formatted(missing, REQUIRED_HEADERS.size(), url);

            return new LiveHeaderReport(url, response.statusCode(), results, summary);

        } catch (Exception e) {
            return new LiveHeaderReport(url, 0, List.of(),
                    "❌ Could not reach " + url + ": " + e.getMessage());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tool 3 — Explain a header
    // ─────────────────────────────────────────────────────────────────────────

    @Tool(description = """
            Get a full explanation of an HTTP security header including:
            - What it does and why it matters
            - The recommended value for Spring Boot applications
            - The exact Spring Security Java config code to enable it
            Headers: Strict-Transport-Security, Content-Security-Policy, X-Frame-Options,
            X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cache-Control
            """)
    public HeaderExplanation explainHeader(
            @ToolParam(description = "Header name, e.g. Content-Security-Policy or X-Frame-Options")
            String headerName
    ) {
        return HEADER_EXPLANATIONS.getOrDefault(
                headerName.trim().toLowerCase().replace(" ", "-"),
                new HeaderExplanation(headerName, "Unknown header",
                        "Check the OWASP Secure Headers Project for guidance.",
                        "N/A", "https://owasp.org/www-project-secure-headers/"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Records
    // ─────────────────────────────────────────────────────────────────────────

    public record HeaderSpec(String name, String severity, String description, String risk) {
        String springConfig() { return HEADER_SPRING_CONFIG.getOrDefault(name, "See Spring Security docs."); }
    }

    public record HeaderCheckResult(String header, String severity, String status,
            boolean present, String value, String risk, String description, String springConfig) {}

    public record HeaderConfigReport(String projectPath, List<String> configFiles,
            List<HeaderCheckResult> results, String summary, String fullSnippet) {
        static HeaderConfigReport error(String msg) {
            return new HeaderConfigReport("", List.of(), List.of(), "❌ " + msg, "");
        }
    }

    public record LiveHeaderReport(String url, int statusCode,
            List<HeaderCheckResult> results, String summary) {}

    public record HeaderExplanation(String header, String description,
            String recommendedValue, String springConfig, String reference) {}

    // ─────────────────────────────────────────────────────────────────────────
    // Static knowledge
    // ─────────────────────────────────────────────────────────────────────────

    private static final Map<String, String> HEADER_SPRING_CONFIG = Map.of(
        "Strict-Transport-Security", "http.headers(h -> h.httpStrictTransportSecurity(hsts -> hsts.maxAgeInSeconds(31536000).includeSubDomains(true)));",
        "Content-Security-Policy",   "http.headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives(\"default-src 'self'\")));",
        "X-Frame-Options",           "http.headers(h -> h.frameOptions(fo -> fo.deny()));",
        "X-Content-Type-Options",    "http.headers(h -> h.contentTypeOptions(Customizer.withDefaults())); // enabled by default",
        "Referrer-Policy",           "http.headers(h -> h.referrerPolicy(rp -> rp.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)));",
        "Permissions-Policy",        "http.headers(h -> h.permissionsPolicy(pp -> pp.policy(\"camera=(), microphone=(), geolocation=()\")));",
        "Cache-Control",             "http.headers(h -> h.cacheControl(Customizer.withDefaults())); // enabled by default in Spring Security"
    );

    private static final Map<String, HeaderExplanation> HEADER_EXPLANATIONS = Map.of(
        "strict-transport-security", new HeaderExplanation(
                "Strict-Transport-Security (HSTS)",
                "Tells browsers to only connect via HTTPS for a set period. Prevents protocol downgrade attacks.",
                "max-age=31536000; includeSubDomains; preload",
                "http.headers(h -> h.httpStrictTransportSecurity(hsts -> hsts\n    .maxAgeInSeconds(31536000)\n    .includeSubDomains(true)\n    .preload(true)));",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"),
        "content-security-policy", new HeaderExplanation(
                "Content-Security-Policy (CSP)",
                "Allowlist of sources the browser can load scripts, styles, images from. Best defense against XSS.",
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:",
                "http.headers(h -> h.contentSecurityPolicy(csp ->\n    csp.policyDirectives(\"default-src 'self'; script-src 'self'\")));",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"),
        "x-frame-options", new HeaderExplanation(
                "X-Frame-Options",
                "Prevents your page from being displayed in an <iframe> on other sites. Stops clickjacking.",
                "DENY (or SAMEORIGIN if you need iframes from your own domain)",
                "http.headers(h -> h.frameOptions(fo -> fo.deny()));",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"),
        "x-content-type-options", new HeaderExplanation(
                "X-Content-Type-Options",
                "Stops browsers from guessing (sniffing) the MIME type of a response. Prevents drive-by downloads.",
                "nosniff",
                "// Enabled by default in Spring Security. To be explicit:\nhttp.headers(h -> h.contentTypeOptions(Customizer.withDefaults()));",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"),
        "referrer-policy", new HeaderExplanation(
                "Referrer-Policy",
                "Controls how much URL information is sent in the Referer header to other sites.",
                "strict-origin-when-cross-origin",
                "http.headers(h -> h.referrerPolicy(rp ->\n    rp.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)));",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"),
        "permissions-policy", new HeaderExplanation(
                "Permissions-Policy",
                "Restricts which browser features (camera, microphone, geolocation) the page and embedded frames can use.",
                "camera=(), microphone=(), geolocation=(), payment=()",
                "http.headers(h -> h.permissionsPolicy(pp ->\n    pp.policy(\"camera=(), microphone=(), geolocation=()\")));",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"),
        "cache-control", new HeaderExplanation(
                "Cache-Control",
                "Prevents browsers and proxies from caching authenticated pages. Critical for logout to work correctly.",
                "no-cache, no-store, max-age=0, must-revalidate",
                "// Enabled by default in Spring Security for authenticated responses.\nhttp.headers(h -> h.cacheControl(Customizer.withDefaults()));",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control")
    );

    private static final String SPRING_SECURITY_SNIPPET = """
            // Complete Spring Security headers configuration
            // Add this to your SecurityFilterChain @Bean:

            @Bean
            public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http
                    .headers(headers -> headers
                        // HSTS — force HTTPS for 1 year
                        .httpStrictTransportSecurity(hsts -> hsts
                            .maxAgeInSeconds(31536000)
                            .includeSubDomains(true))
                        // CSP — adjust sources for your app
                        .contentSecurityPolicy(csp -> csp
                            .policyDirectives("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:"))
                        // Clickjacking protection
                        .frameOptions(fo -> fo.deny())
                        // MIME sniffing prevention (default in Spring Security)
                        .contentTypeOptions(Customizer.withDefaults())
                        // Referrer policy
                        .referrerPolicy(rp -> rp
                            .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                        // Permissions policy
                        .permissionsPolicy(pp -> pp
                            .policy("camera=(), microphone=(), geolocation=()"))
                        // Cache control (default in Spring Security)
                        .cacheControl(Customizer.withDefaults())
                    );
                // ... rest of your config
                return http.build();
            }
            """;

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private HeaderCheckResult checkHeaderInConfig(HeaderSpec h, String combined) {
        boolean found = combined.contains(h.name().toLowerCase().replace("-", ""))
                || combined.contains(h.name().toLowerCase())
                || HEADER_CONFIG_KEYWORDS.getOrDefault(h.name(), List.of())
                        .stream().anyMatch(combined::contains);

        return new HeaderCheckResult(
                h.name(), h.severity(),
                found ? "✅ Likely configured" : "❌ Not found in config",
                found, null, h.risk(), h.description(), h.springConfig());
    }

    private String buildConfigSummary(List<HeaderCheckResult> results) {
        long missing = results.stream().filter(r -> !r.present()).count();
        if (missing == 0) return "✅ All security headers appear to be configured.";
        String missingList = results.stream().filter(r -> !r.present())
                .map(r -> r.header() + " (" + r.severity() + ")")
                .collect(Collectors.joining(", "));
        return "⚠️ %d header(s) not found in config: %s".formatted(missing, missingList);
    }

    private static final Map<String, List<String>> HEADER_CONFIG_KEYWORDS = Map.of(
        "Strict-Transport-Security", List.of("hsts", "httpstricttransport", "maxageinsecon"),
        "Content-Security-Policy",   List.of("contentsecuritypolicy", "csp", "default-src"),
        "X-Frame-Options",           List.of("frameoptions", "frameOptions", "deny", "sameorigin"),
        "Referrer-Policy",           List.of("referrerpolicy", "strictorigin"),
        "Permissions-Policy",        List.of("permissionspolicy", "featurepolicy")
    );
}
