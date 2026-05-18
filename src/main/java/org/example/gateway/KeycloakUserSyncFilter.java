package org.example.gateway;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.gateway.user.RegisterRequest;
import org.example.gateway.user.UserService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
@Slf4j
@RequiredArgsConstructor
public class KeycloakUserSyncFilter implements WebFilter {

    private final UserService userService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        if (path.startsWith("/actuator")) {
            return chain.filter(exchange);
        }

        String token = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (token == null || !token.startsWith("Bearer ")) {
            return chain.filter(exchange);
        }

        RegisterRequest registerRequest = getUserDetails(token);
        if (registerRequest == null || registerRequest.getKeycloakId() == null) {
            return chain.filter(exchange);
        }

        String userId = exchange.getRequest().getHeaders().getFirst("X-User-ID");
        if (userId == null) {
            userId = registerRequest.getKeycloakId();
        }

        String finalUserId = userId;

        return userService.validateUser(finalUserId)
                .onErrorResume(e -> Mono.just(false))
                .flatMap(exists -> {
                    if (!exists) {
                        return userService.registerUser(registerRequest)
                                .onErrorResume(e -> {
                                    log.error("User registration failed: {}", e.getMessage());
                                    return Mono.empty();
                                })
                                .then(Mono.just(true));
                    }
                    return Mono.just(true);
                })
                .then(Mono.defer(() -> {
                    ServerHttpRequest request = exchange.getRequest();

                    HttpHeaders newHeaders = new HttpHeaders();
                    newHeaders.putAll(request.getHeaders());

                    String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

                    if (authHeader != null) {
                        newHeaders.set(HttpHeaders.AUTHORIZATION, authHeader);
                    }

                    newHeaders.set("X-User-ID", finalUserId);

                    ServerHttpRequest decoratedRequest = new ServerHttpRequestDecorator(request) {
                        @Override
                        public HttpHeaders getHeaders() {
                            return newHeaders;
                        }
                    };

                    return chain.filter(exchange.mutate().request(decoratedRequest).build());
                }));
    }

    private RegisterRequest getUserDetails(String token) {
        try {
            String tokenWithoutBearer = token.substring(7).trim();
            SignedJWT signedJWT = SignedJWT.parse(tokenWithoutBearer);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            RegisterRequest registerRequest = new RegisterRequest();
            registerRequest.setEmail(claims.getStringClaim("email"));
            registerRequest.setKeycloakId(claims.getStringClaim("sub"));
//            registerRequest.setPassword("dummy@123123");
            registerRequest.setFirstName(claims.getStringClaim("given_name"));
            registerRequest.setLastName(claims.getStringClaim("family_name"));

            return registerRequest;
        } catch (Exception e) {
            log.error("Failed to parse token: {}", e.getMessage());
            return null;
        }
    }
}