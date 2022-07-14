package com.dev.nbbang.apigateway.filter;

import com.dev.nbbang.apigateway.util.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.Map;

@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
    @Autowired
    private JwtUtil jwtUtil;

    public AuthorizationHeaderFilter() {
        super(Config.class);
    }

    public static class Config {
        // Put configuration properties here
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String token = exchange.getRequest().getHeaders().get("Authorization").get(0).substring(7);
            Map<String, Object> userInfo = jwtUtil.getUserParseInfo(token);

            addAuthorizationHeaders(exchange.getRequest(), userInfo);

            return chain.filter(exchange);
        };
    }

    private void addAuthorizationHeaders(ServerHttpRequest request, Map<String, Object> userInfo) {
        request.mutate()
                .header("X-Authorization-Id", userInfo.get("memberId").toString())
                .build();
    }

    @Bean
    public ErrorWebExceptionHandler myExceptionHandler() {
        return new MyWebExceptionHandler();
    }

    public class MyWebExceptionHandler implements ErrorWebExceptionHandler {
        private String errorCodeMaker(String message) {
            return "{\"message\":" + message + "}";
        }

        @Override
        public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {

            HttpStatus httpStatus = HttpStatus.FORBIDDEN;
            String message = "잘못된 접근입니다.";

            if(ex.getClass() == ExpiredJwtException.class) {
                message = "만료된 토큰입니다.";
                httpStatus = HttpStatus.UNAUTHORIZED;
            }

            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(httpStatus);
//            int errorCode = 999;
//            if (ex.getClass() == NullPointerException.class) {
//                errorCode = 100;
//            } else if (ex.getClass() == ExpiredJwtException.class) {
//                errorCode = 56;
//            } else if (ex.getClass() == MalformedJwtException.class || ex.getClass() == SignatureException.class || ex.getClass() == UnsupportedJwtException.class) {
//                errorCode = 55;
//            } else if (ex.getClass() == IllegalArgumentException.class) {
//                errorCode = 51;
//            }

            byte[] bytes = errorCodeMaker(message).getBytes(StandardCharsets.UTF_8);
            DataBuffer buffer = response.bufferFactory().wrap(bytes);
            return response.writeWith(Flux.just(buffer));
        }
    }
}
