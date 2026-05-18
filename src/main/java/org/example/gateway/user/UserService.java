package org.example.gateway.user;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

    private final WebClient userServiceWebClient;

    public Mono<Boolean> validateUser(String userId) {
        log.info("Calling User Validation API for userId: {}", userId);

        return userServiceWebClient.get()
                .uri("/api/users/{userId}/validate", userId)
                .retrieve()
                .bodyToMono(Boolean.class)
                .onErrorResume(WebClientResponseException.class, e -> {
                    if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                        return Mono.just(false);
                    }
                    log.error("Validation error: {}", e.getMessage());
                    return Mono.just(false);
                })
                .onErrorResume(e -> {
                    log.error("Unexpected validation error: {}", e.getMessage());
                    return Mono.just(false);
                });
    }

    public Mono<UserResponse> registerUser(RegisterRequest request) {
        log.info("Calling User Registration API for email: {}", request.getEmail());

        return userServiceWebClient.post()
                .uri("/api/users/register")
                .bodyValue(request)
                .retrieve()
                .bodyToMono(UserResponse.class)
                .onErrorResume(WebClientResponseException.class, e -> {
                    log.error("Registration error: {}", e.getMessage());
                    return Mono.empty();
                })
                .onErrorResume(e -> {
                    log.error("Unexpected registration error: {}", e.getMessage());
                    return Mono.empty();
                });
    }


    public Mono<UserShortInfo> getUserById(String userId) {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> (JwtAuthenticationToken) ctx.getAuthentication())
                .flatMap(auth -> userServiceWebClient.get()
                        .uri("/api/users/{userId}/short-info", userId)
                        .headers(h -> {
                            System.out.println("TOKEN (getUserById): " + auth.getToken().getTokenValue());
                            h.setBearerAuth(auth.getToken().getTokenValue());
                        })
                        .retrieve()
                        .bodyToMono(UserShortInfo.class)
                );
    }

    public Mono<List<UserShortInfo>> getManagers() {
        return ReactiveSecurityContextHolder.getContext()
                .map(ctx -> (JwtAuthenticationToken) ctx.getAuthentication())
                .flatMap(auth -> userServiceWebClient.get()
                        .uri("/api/users/managers")
                        .headers(h -> {
                            System.out.println("TOKEN (getManagers): " + auth.getToken().getTokenValue());
                            h.setBearerAuth(auth.getToken().getTokenValue());
                        })
                        .retrieve()
                        .bodyToFlux(UserShortInfo.class)
                        .collectList()
                );
    }


}