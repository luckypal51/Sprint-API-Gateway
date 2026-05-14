package com.app.api_gateway.security;

import java.util.List;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import com.app.api_gateway.util.ConstantValue;
import com.app.api_gateway.util.JwtUtil;

import io.jsonwebtoken.Claims;
@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config>{
	
	@Autowired
	private RouteValidator routevalidator;
	
    public static class Config{}
    
    public AuthenticationFilter(){
    	super(Config.class);
    }
    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {

            if (routevalidator.isSecured.test(exchange.getRequest())) {

                if (!exchange.getRequest().getHeaders()
                        .containsKey(HttpHeaders.AUTHORIZATION)) {
                    throw new RuntimeException(ConstantValue.MISSING_HEADER);
                }

                String authHeader = exchange.getRequest()
                        .getHeaders()
                        .getFirst(HttpHeaders.AUTHORIZATION); 

                if (authHeader == null || !authHeader.startsWith(ConstantValue.BEARER)) {
                    throw new RuntimeException(ConstantValue.INVALID_AUTHORIZATION_FORMAT);
                }

                String token = authHeader.substring(7);

                Claims claims;
                try {
                    claims = JwtUtil.getClaims(token); 
                } catch (Exception e) {
                    throw new RuntimeException(ConstantValue.INVALID_TOKEN);
                }
            
              
                String role = claims.get("roles", String.class);
                String path = exchange.getRequest().getURI().getPath();

                for (Map.Entry<String, List<String>> entry : routevalidator.roleAccessMap.entrySet()) {
                    if (path.startsWith(entry.getKey())) {
                        if (!entry.getValue().contains(role)) {
                            throw new RuntimeException(ConstantValue.NOT_PERMITE + role 
                                + ConstantValue.NOT_PERMITE_PATH + path);
                        }
                    }
                }
            }

            return chain.filter(exchange);
        });
    }
}