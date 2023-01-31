package com.shop.gatewayforshop;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.reactive.ReactiveUserDetailsServiceAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
//import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
//import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
//import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;


//@SpringBootApplication
//@SpringBootApplication(exclude = {SecurityAutoConfiguration.class,UserDetailsServiceAutoConfiguration.class,ReactiveUserDetailsServiceAutoConfiguration.class})
@SpringBootApplication (exclude = {ReactiveUserDetailsServiceAutoConfiguration.class })


@RefreshScope
//@EnableWebFluxSecurity
@EnableEurekaClient

public class GatewayForShopApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayForShopApplication.class, args);
    }

}
