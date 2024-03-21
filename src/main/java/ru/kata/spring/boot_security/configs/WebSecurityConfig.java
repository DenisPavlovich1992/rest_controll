package ru.kata.spring.boot_security.configs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import ru.kata.spring.boot_security.service.UserServiceImp;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final SuccessUserHandler successUserHandler;

    private final UserServiceImp userServiceImp;

    public WebSecurityConfig(SuccessUserHandler successUserHandler,
                             UserServiceImp userServiceImp) {
        this.successUserHandler = successUserHandler;
        this.userServiceImp = userServiceImp;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "/login").permitAll()
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/api/admin").hasRole("ADMIN")
                .antMatchers("/user").hasRole("USER")
                .anyRequest().authenticated()
                .and()
                .formLogin().successHandler(successUserHandler)
                .loginPage("/login")
                .permitAll()
                .and()
                .logout()
                .permitAll();
    }

    /**
     * Используется не безопасный NoOpPasswordEncoder
     * только в рамках учебного проекта
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .userDetailsService(userServiceImp)
                .passwordEncoder(NoOpPasswordEncoder.getInstance());
    }

    /**
     * Разрешает доступ к статическим ресурсам /css
     * Разрешает доступ к статическим ресурсам /favIcon
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/css/**",
                                    "/favIcon/**");
    }

}