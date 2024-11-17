package com.example.learnspringsecuirty;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@SpringBootApplication
public class LearnSpringSecuirtyApplication {

    @Value("${todo.application.allowed.origin}")
    public String allowedOrigin;

    public static void main(String[] args) {
        SpringApplication.run(LearnSpringSecuirtyApplication.class, args);
    }



}
