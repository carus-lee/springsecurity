package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.common.AjaxLoginAuthenticationEntryPoint;
import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.corespringsecurity.security.handler.AjaxAccessDeniedHandler;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationFailerHandler;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@Order(0)
public class AjaxSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(ajaxAuthenticationProvider());
    }

    @Bean
    public AuthenticationProvider ajaxAuthenticationProvider() {
        return new AjaxAuthenticationProvider();
    }

    @Bean
    public AuthenticationSuccessHandler ajaxAuthenticationSuccessHandler() {
        return new AjaxAuthenticationSuccessHandler();
    }

    @Bean
    public AuthenticationFailureHandler ajaxAuthenticationFailerHandler() {
        return new AjaxAuthenticationFailerHandler();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/api/**") //해당URI로 요청시에만 이 설정을 따름
                .authorizeRequests()
                .antMatchers("/api/messages").hasRole("MANAGER")
                .antMatchers("/api/login").permitAll()
                .anyRequest().authenticated();
        http
                .exceptionHandling()
                    .authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
                    .accessDeniedHandler(ajaxAccessDeniedHandler());
//        http
//                .addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class); //인증필터

//        http.csrf().disable();

        customConfigureAjax(http);
    }

    private void customConfigureAjax(HttpSecurity http) throws Exception {
        http
                .apply(new AjaxLoginConfigure<>())
                .successHandlerAjax(ajaxAuthenticationSuccessHandler())
                .failerHandlerAjax(ajaxAuthenticationFailerHandler())
                .setAuthenticationManager(authenticationManagerBean())
                .loginProcessingUrl("/api/login")
        ;
    }

    public AccessDeniedHandler ajaxAccessDeniedHandler() {
        return new AjaxAccessDeniedHandler();
    }

//    @Bean
//    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
//        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
//        ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManagerBean());
//        // 필터에 인증성공/실패 핸들러 등록
//        ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());
//        ajaxLoginProcessingFilter.setAuthenticationFailureHandler(ajaxAuthenticationFailerHandler());
//
//        return ajaxLoginProcessingFilter;
//    }

}
