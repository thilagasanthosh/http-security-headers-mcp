package com.mcp.httpheaders;

import com.mcp.httpheaders.tool.HttpHeadersTools;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/**
 * HTTP Security Headers MCP Server
 *
 * Exposes MCP tools to Claude that check Spring Boot security configuration
 * for missing or misconfigured HTTP security headers.
 *
 * Tools:
 *   - checkSecurityConfig   : scan Spring Security config files for header settings
 *   - checkLiveEndpoint     : call a live URL and check actual response headers
 *   - explainHeader         : explain a security header and how to configure it in Spring
 */
@SpringBootApplication
public class HttpSecurityHeadersMcpApplication {

    public static void main(String[] args) {
        SpringApplication.run(HttpSecurityHeadersMcpApplication.class, args);
    }

    @Bean
    public ToolCallbackProvider headersToolProvider(HttpHeadersTools tools) {
        return MethodToolCallbackProvider.builder().toolObjects(tools).build();
    }
}
