package com.example.gateway_api.filters;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class JwtAuthenticationGlobalFilter implements GlobalFilter {

    private final WebClient webClient;

    public JwtAuthenticationGlobalFilter(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.baseUrl("http://auth-api:8005/auth").build();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        Logger logger = LoggerFactory.getLogger(JwtAuthenticationGlobalFilter.class);
//        logger.info("Global JWT Filter triggered!");
//        logger.info("Request path: {}", path);
        System.out.println(path);
        System.out.println("Global JWT Filter triggered!");

        // Bypass authentication for public endpoints like /auth/signup or /auth/login
        if (path.equals("/auth/signup") || path.equals("/auth/login")) {
            return chain.filter(exchange);  // Continue the filter chain for these paths
        }

        // Get the Authorization header
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        // If the Authorization header is missing or malformed, return 401 UNAUTHORIZED
        System.out.println(authHeader);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        // Extract token from the Authorization header
        String token = authHeader.substring(7); // Remove "Bearer " prefix
        System.out.println(token);

        // Call the auth service to verify the token
        return webClient.post()
                .uri("/verify") // Endpoint on auth service
                .header(HttpHeaders.AUTHORIZATION, authHeader)
                .retrieve()
                .bodyToMono(VerifiedTokenResponse.class)
                .flatMap(response -> {
                    // If token is valid, add user info as headers and pass to next filter in the chain
                    if (response != null) {
                        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                                .header("X-User-Id", response.getUserId())
                                .header("X-User-Role", response.getUserRole())
                                .build();
                        return chain.filter(exchange.mutate().request(mutatedRequest).build());
                    } else {
                        // If token is invalid, return 401 UNAUTHORIZED
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        System.out.println("Invalid Token");
                        return exchange.getResponse().setComplete();
                    }
                })
                .onErrorResume(e -> {
                    // In case of an error (e.g., network error while calling auth service), return 401
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    System.out.println("Network error");
                    System.out.println(e);
                    return exchange.getResponse().setComplete();
                });
    }

    // Response class to handle the response from auth service
    public static class VerifiedTokenResponse {
        private String userId;
        private String userRole;

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }

        public String getUserRole() {
            return userRole;
        }

        public void setUserRole(String userRole) {
            this.userRole = userRole;
        }
    }
}
