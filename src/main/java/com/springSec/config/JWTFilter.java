package com.springSec.config;

import com.springSec.entity.User;
import com.springSec.repo.UserRepository;
import com.springSec.securityService.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Component
public class JWTFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;


    public JWTFilter(JwtService jwtService,
                     UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        /*1.We will get the token from head
         * 2.We will extract bearer_ from token
         * 3.We Will extract the username from token the method present in jwt service clas
         * 4.We will find that user from db
         * 5.once user found we create the UsernamePasswordAuthentication and user credentials and authorities
         * 6.in last use dofilter(request,response)*/

        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            String jwtToken = token.substring(7);
            String username = jwtService.getUsername(jwtToken);
            Optional<User> byUsername = userRepository.findByUsername(username);
            if (byUsername.isPresent()) {
                User user = byUsername.get();
                String role = user.getRole();
                Collection<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(role));

                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        user
                        , null
                        , authorities
                );
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
