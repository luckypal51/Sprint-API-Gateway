package com.app.api_gateway.security;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;



@Component
public class RouteValidator {

    public static final List<String> openApiEndpoints = List.of(
            "/auth/signup",
            "/auth/signin",
            "/auth/login",
            "/oauth2/authorization/google",
            "/login",
            "/flight/service/search-flight-number",
            "/flight/service/search-flights",
            "/flight/service/search-flights-airline",
            "/seats/available-seats",
            "/seats/available-class",
            "/seats/search-id",
            "/seats/hold-seat",
            "/seats/release-seat",
            "/seats/confirm-seat",
            "/seats/count-by-class",
            "/seats/search-by-seatNumber",
            "/payment/success",
            "/payment/cancel",
            "/payments/webhook",   // ✅ was missing
            "/eureka"
    );

    public Predicate<ServerHttpRequest> isSecured =
            request ->
                request.getMethod() != HttpMethod.OPTIONS &&   // ✅ bypass all preflight
                openApiEndpoints.stream()
                    .noneMatch(uri -> request.getURI().getPath().startsWith(uri));

    public Map<String, List<String>> roleAccessMap = Map.of(
            "/admin/",    List.of("ROLE_ADMIN","ADMIN"),
            "/staff/",    List.of("ROLE_STAFF", "ROLE_ADMIN","ADMIN"),
            "/passenger/", List.of("ROLE_USER", "ROLE_ADMIN","USER"),
            "/payment/",  List.of("ROLE_USER", "ROLE_ADMIN","USER"),
            "/booking/",  List.of("ROLE_USER", "ROLE_ADMIN","USER"),
            "/user/",List.of("ROLE_USER", "ROLE_ADMIN","USER","ROLE_STAFF")
    );
}