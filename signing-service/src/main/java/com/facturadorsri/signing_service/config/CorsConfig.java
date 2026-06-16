package com.facturadorsri.signing_service.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Arrays;
import java.util.List;

/**
 * CORS configuration for the signing service.
 *
 * SECURITY (bd issue mcphub-5ub): The previous version used allowedOrigins=*,
 * which combined with the unauthenticated POST /api/v1/signature/sign endpoint
 * allowed ANY host with network access to the service to sign arbitrary XML
 * with any provided certificate. This version:
 *   - Reads allowed origins from SIGNING_ALLOWED_ORIGINS env var (default empty
 *     list, so no cross-origin requests are accepted out of the box)
 *   - Restricts allowed methods to those the API actually supports
 *   - Restricts allowed headers to Content-Type + Authorization only
 *
 * Production deployments MUST set SIGNING_ALLOWED_ORIGINS to the URL of the
 * Python MCP server (e.g. http://mcp-server:8000).
 */
@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Value("${signing.allowed-origins:}")
    private String allowedOriginsCsv;

    private List<String> getAllowedOrigins() {
        if (allowedOriginsCsv == null || allowedOriginsCsv.isBlank()) {
            return List.of();
        }
        return Arrays.stream(allowedOriginsCsv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        List<String> origins = getAllowedOrigins();
        if (origins.isEmpty()) {
            return;  // No CORS mappings registered — strictest possible
        }
        registry.addMapping("/**")
                .allowedOrigins(origins.toArray(new String[0]))
                .allowedMethods("GET", "POST", "OPTIONS")
                .allowedHeaders("Content-Type", "Authorization", "X-Signing-Key")
                .maxAge(3600);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        List<String> origins = getAllowedOrigins();
        if (origins.isEmpty()) {
            // Use a sentinel that will never match any Origin header.
            configuration.setAllowedOrigins(List.of("null"));
        } else {
            configuration.setAllowedOrigins(origins);
        }
        configuration.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Content-Type", "Authorization", "X-Signing-Key"));
        configuration.setAllowCredentials(false);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
