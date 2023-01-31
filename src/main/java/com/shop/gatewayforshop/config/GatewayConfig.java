package com.shop.gatewayforshop.config;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

//@Configuration("gateway")
public class GatewayConfig {

    private Map<String, String> routes = new HashMap<>();

    public Map<String, String> getRoutes() {
        return routes;
    }

    public String backend(String service) {
        return routes.get(service);
    }
}