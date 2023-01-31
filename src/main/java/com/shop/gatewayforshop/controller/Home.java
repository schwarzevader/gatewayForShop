package com.shop.gatewayforshop.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class Home {

    @GetMapping(value = "/")
    public String home(Principal principal){
        return principal.getName();
    }
}
