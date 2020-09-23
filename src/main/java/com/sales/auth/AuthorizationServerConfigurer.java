package com.sales.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;

@Configuration
public class AuthorizationServerConfigurer extends AuthorizationServerConfigurerAdapter {

    private AuthenticationManager authenticationManager;

    private UserDetailsService detailsService;

    private PasswordEncoder passwordEncoder;

    @Autowired
    public AuthorizationServerConfigurer(AuthenticationManager authenticationManager,
            UserDetailsService detailsService, PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.detailsService = detailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void configure (final ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("sale")
                .secret(passwordEncoder.encode("salepwd"))
                .authorizedGrantTypes("password")
                .scopes("web");
    }

    @Override
    public void configure (final AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager).userDetailsService(detailsService);
    }
}
