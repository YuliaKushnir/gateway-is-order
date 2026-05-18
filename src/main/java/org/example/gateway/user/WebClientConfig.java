package org.example.gateway.user;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {

    @Value("${base-url}")
    String baseUrl;

    @Bean
    public WebClient.Builder webClientBuilder() {
        return WebClient.builder()
                .filter((request, next) ->
                        ReactiveSecurityContextHolder.getContext()
                                .map(ctx -> ctx.getAuthentication())
                                .flatMap(auth -> {
                                    if (auth instanceof JwtAuthenticationToken jwtAuth) {
                                        String token = jwtAuth.getToken().getTokenValue();

                                        ClientRequest newRequest = ClientRequest.from(request)
                                                .headers(headers -> headers.setBearerAuth(token))
                                                .build();

                                        return next.exchange(newRequest);
                                    }
                                    return next.exchange(request);
                                })
                );
    }

    @Bean
    public WebClient userServiceWebClient(WebClient.Builder webClientBuilder) {
        return webClientBuilder
                .baseUrl(baseUrl)
                .build();
    }
}