package com.springSec.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SpringConfig {

   private final JWTFilter jwtFilter;

    public SpringConfig(JWTFilter jwtFilter) {
        this.jwtFilter = jwtFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable().cors().disable();
        http.authorizeHttpRequests().requestMatchers("/api/v1/auth/register", "/api/v1/auth/verify","/api/v1/auth/registerContentManager","/api/v1/auth/generate","/api/v1/auth/validate","/api/v1/auth/refresh","/api/v1/auth/logout").permitAll()
                .requestMatchers("/api/v1/auth/hi").hasRole("CONTENT_MANAGER")
                .requestMatchers("/api/v1/auth/hiUser").hasRole("USER")
                .anyRequest().authenticated()
                .and()
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class); // ✅ Register JWTFilter

        return http.build();


    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
