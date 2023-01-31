package com.shop.gatewayforshop.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
//import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.web.server.authentication.OAuth2LoginAuthenticationWebFilter;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers.pathMatchers;

@Configuration
//@EnableWebSecurity
@EnableWebFluxSecurity
public class SecurityConfig {


//    @Bean
//    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
//        http.authorizeExchange(exchanges -> exchanges.anyExchange().authenticated())
//                .oauth2Login(withDefaults());
//        http.csrf().disable();
//        return http.build();
//    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain ( ServerHttpSecurity http) {

        http
                .authorizeExchange().pathMatchers("/eureka/**").permitAll()
                .anyExchange()
                .authenticated()
                .and()
                .oauth2Login(); // to redirect to oauth2 login page.

        return http.build();
    }

//    @Bean
//    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
//                                                            ReactiveClientRegistrationRepository clientRegistrationRepository) {
//        // Authenticate through configured OpenID Provider
//        http.oauth2Login();
//
//        // Also logout at the OpenID Connect provider
//        http.logout(logout -> logout.logoutSuccessHandler(
//                new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository)));
//
//        // Require authentication for all requests
//        http.authorizeExchange().anyExchange().authenticated();
//
//        // Allow showing /home within a frame
//        http.headers().frameOptions().mode(XFrameOptionsServerHttpHeadersWriter.Mode.SAMEORIGIN);
//
//        // Disable CSRF in the gateway to prevent conflicts with proxied service CSRF
//        http.csrf().disable();
//        return http.build();
//    }


//        @Bean
//    public ClientRegistration keycloakClientRegistration(){
//        return ClientRegistration.withRegistrationId("keycloak") // registration_id
//                .clientId("shopGateway")
//                .clientSecret("nxEEYS7EvN8WEHIK8ljqP83JYdCJFEBy")
//                .scope("openid")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//
//                // {baseUrl}/login/oauth2/code/{registration_id}
//                .redirectUri("http://localhost:8073/*")
//                .authorizationUri("http://localhost:8080/auth/realms/master/protocol/openid-connect/auth")
//                .tokenUri("http://localhost:8080/auth/realms/master/protocol/openid-connect/token")
//                .userInfoUri("http://localhost:8080/auth/realms/master/protocol/openid-connect/userinfo")
//                .jwkSetUri("http://localhost:8080/auth/realms/master/protocol/openid-connect/certs")
//                .userNameAttributeName(IdTokenClaimNames.SUB)
//                .clientName("Keycloak")
//                .tokenUri("http://localhost:8080/auth/realms/master-realm/protocol/openid-connect/token")
//                .issuerUri("http://localhost:8080/realms/master")
//                .build();
//    }

//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
//        return authenticationConfiguration.getAuthenticationManager();
//    }

    @Bean
    ReactiveJwtDecoder jwtDecoder() {
        //return ReactiveJwtDecoders.fromOidcIssuerLocation("http://localhost:8080/realms/master");
        //return ReactiveJwtDecoders.fromOidcIssuerLocation("http://localhost:8080/realms/spring-microservice");
        //return ReactiveJwtDecoders.fromOidcIssuerLocation("http://localhost:8080/realms/spring-microservice/protocol/openid-connect/token");
        return ReactiveJwtDecoders.fromOidcIssuerLocation("http://localhost:8080/auth/realms/spring-microservice");
    }

//    @Bean
//    public OAuth2AuthorizedClientRepository authorizedClientRepository(
//            OAuth2AuthorizedClientService authorizedClientService) {
//        return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
//    }


//    @Bean
//    public RouteLocator customRouteLocator(RouteLocatorBuilder builder,
//                                           TokenRelayGatewayFilterFactory filterFactory) {
//        return builder.routes()
//                .route("car-service", r -> r.path("/cars")
//                        .filters(f -> f.filter(filterFactory.apply()))
//                        .uri("lb://car-service/cars"))
//                .build();
//    }

//    @Bean
//    public WebClient rest() {
//        return WebClient.builder()
//                .filter(new ServerBearerExchangeFilterFunction())
//                .build();
//    }

//    @Bean
//    public WebClient webClient(ReactiveClientRegistrationRepository clientRegistrationRepo,
//                               ServerOAuth2AuthorizedClientRepository authorizedClientRepo) {
//        ServerOAuth2AuthorizedClientExchangeFilterFunction filter =
//                new ServerOAuth2AuthorizedClientExchangeFilterFunction(clientRegistrationRepo, authorizedClientRepo);
//
//        return WebClient.builder().filter(filter).build();
//    }

//    @Bean
//    public SecurityWebFilterChain mySecurityWebFilterChain(ServerHttpSecurity http){
////        http.csrf()
////                .disable()
////                .authorizeExchange(exchange-> exchange.pathMatchers("/eureka/**").permitAll()
//////                        .pathMatchers(HttpMethod.POST,"/shop/products/new").permitAll()
//////                        .pathMatchers(HttpMethod.POST,"/shop/products/new/**").permitAll()
//////                        .pathMatchers(HttpMethod.POST,"/shop/**").permitAll()
//////                        .pathMatchers(HttpMethod.POST,"/**").permitAll()
//////                        .pathMatchers(HttpMethod.POST,"http://localhost:8073/shop/products/new").permitAll()
//////                        .pathMatchers(HttpMethod.POST,"/posts/**").permitAll()
//////                        .pathMatchers(HttpMethod.POST,"http://localhost:8180/products/new").permitAll()
////
////                        //.pathMatchers(HttpMethod.POST).permitAll()
////                        .anyExchange()
////                        .authenticated()
////                        //.and().formLogin()
////                )//;
////                .oauth2ResourceServer(ServerHttpSecurity.OAuth2ResourceServerSpec::jwt);
//////                .oauth2ResourceServer(oauth2 -> oauth2
//////                .jwt(withDefaults()));
//////                .oauth2ResourceServer(oauth2 -> oauth2
//////                        .jwt(jwt -> jwt
//////                                .jwkSetUri("http://localhost:8080/auth/realms/spring-microservice/protocol/openid-connect/certs")
//////                        )
//////                );
////
////        return http.build();
//
//                http//.oauth2Login().and()
//                .csrf().disable()
//                .authorizeExchange()
//                //.pathMatchers("/headerrouting/**").permitAll()
//                .pathMatchers("/actuator/**").permitAll()
//                .pathMatchers("/eureka-server/**").permitAll()
//                .pathMatchers(HttpMethod.GET,"http://localhost:8080/*").permitAll()
//                .pathMatchers(HttpMethod.GET,"http://localhost:8080/**").permitAll()
//                .pathMatchers(HttpMethod.POST,"http://localhost:8080/*").permitAll()
//                .pathMatchers(HttpMethod.POST,"http://localhost:8080/**").permitAll()
//                //.pathMatchers(HttpMethod.GET).permitAll()
//                .pathMatchers("/eureka/**").permitAll();
//                //.pathMatchers("/oauth/**").permitAll()
//                //.pathMatchers("/config/**").permitAll();
//
//               // .pathMatchers("/login/**").permitAll()
////                .pathMatchers(HttpMethod.POST,"/shop/products/new").permitAll()
////                .pathMatchers(HttpMethod.POST,"/shop/products/new/**").permitAll()
////                .pathMatchers(HttpMethod.POST,"/products/new").permitAll()
////                .pathMatchers("/products/new").permitAll()
////                .pathMatchers(HttpMethod.POST,"/products/new/**").permitAll()
////                .pathMatchers(HttpMethod.POST,"/shop/**").permitAll()
////                .pathMatchers(HttpMethod.POST,"/**").permitAll()
////                .pathMatchers(HttpMethod.GET,"/**").permitAll()
////                .pathMatchers(HttpMethod.POST,"http://localhost:8073/shop/products/new").permitAll()
////                .pathMatchers(HttpMethod.POST,"http://localhost:8073/products/new").permitAll()
////                .pathMatchers(HttpMethod.POST,"http://localhost:8180/products/new").permitAll()
////                .pathMatchers(HttpMethod.POST).permitAll()
////                .pathMatchers(POST).permitAll()
//                //.anyExchange().authenticated()
//                        //http.oauth2ResourceServer(ServerHttpSecurity.OAuth2ResourceServerSpec::jwt);
//                        //http.oauth2ResourceServer().jwt();
//                        //http.oauth2Login();
//
//
//        return http.build();
//
////        http.csrf().disable()
////                .authorizeExchange()
////                .pathMatchers("/actuator/**", "/","/logout.html" ,"/eureka/**")
////                .permitAll()
////                .and()
////                .authorizeExchange()
////                .anyExchange()
////                .authenticated();//.and().oauth2ResourceServer(ServerHttpSecurity.OAuth2ResourceServerSpec::jwt);;//.and().oauth2Login() ;// to redirect to oauth2 login page.
////                //.and()
////                //.logout()
////                //.logoutSuccessHandler(handler);
////
////        return http.build();
//
//    }

//    private final ApplicationContext context;
//
//    public SecurityConfig(final ApplicationContext context) {
//        this.context = context;
//    }
////

//    @Bean
//    WebClient tokenAugmentingWebClient(
//            final ReactiveClientRegistrationRepository clientRegistrationRepository,
//            final ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
//        return WebClient.builder()
//                .filter(new ServerOAuth2AuthorizedClientExchangeFilterFunction(clientRegistrationRepository, authorizedClientRepository))
//                .build();
//    }

//
//    @Bean
//    SecurityWebFilterChain securityWebFilterChain() {
//        // the matcher for all paths that need to be secured (require a logged-in user)
//        final ServerWebExchangeMatcher apiPathMatcher = pathMatchers("/api/**");
//
//        // default chain for all requests
//        final ServerHttpSecurity http = this.context.getBean(ServerHttpSecurity.class);
//
//        return http
//                .authorizeExchange().matchers(apiPathMatcher).authenticated()
//                .pathMatchers("/eureka-server/**").permitAll()
//                //.pathMatchers(HttpMethod.GET).permitAll()
//                .pathMatchers("/eureka/**").permitAll()
//                .pathMatchers(HttpMethod.GET,"/oauth2/authorization/keycloak").permitAll()
//                .anyExchange().authenticated()
//                .and().httpBasic().disable()
//                .csrf().disable()
//                .oauth2Client()
//                .and()
//                .oauth2Login()
//                .and()
//                .build();
//    }
//private final ApplicationContext context;
//
//    public SecurityConfig(final ApplicationContext context) {
//        this.context = context;
//    }

//    @Bean
//    //public SecurityWebFilterChain springSecurityFilterChain ( ) {
//        public SecurityWebFilterChain springSecurityFilterChain ( ServerHttpSecurity http) {
////        final ServerWebExchangeMatcher apiPathMatcher = pathMatchers("/**");
////
////        // default chain for all requests
////        final ServerHttpSecurity http = this.context.getBean(ServerHttpSecurity.class);
////
////        return http.authorizeExchange()
////                .pathMatchers("/eureka/**").permitAll().and()
////                .authorizeExchange().pathMatchers("/eureka-server/**").permitAll().and()
////                .authorizeExchange().matchers(apiPathMatcher).authenticated()
////                .anyExchange().permitAll()
////                .and().httpBasic().disable()
////                .csrf().disable()
////                .oauth2Client()
////                .and()
////                .oauth2Login()
////                .and()
////                .build();
//
//        http.csrf().disable().authorizeExchange()
//                .pathMatchers("/actuator/**").permitAll()
//                .pathMatchers("/eureka-server/**").permitAll()
//                .pathMatchers("/eureka/**").permitAll()
//                .anyExchange()
//                .authenticated()
//                .and()
//                .oauth2Login(); // to redirect to oauth2 login page.
//
//        return http.build();
//    }


}
