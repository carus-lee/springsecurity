package io.security.corespringsecurity.security.provider;

import io.security.corespringsecurity.security.service.AccountContext;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class AjaxAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String)authentication.getCredentials();//사용자 입력 비밀번호

        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(username);//조회된 사용자정보를 담은 Account 객체
        if (!passwordEncoder.matches(password, accountContext.getAccount().getPassword())) {
            throw new BadCredentialsException("Invalid Password");
        }

        //아이디/비번 외 파라미터를 받아서 인증 체크 추가 (필요에 따라 사용 - 필수X)
        //ajax로 로그인시 부가정보 생략
//        FormWebAuthenticationDetailSource details = (FormWebAuthenticationDetailSource)authentication.getDetails();
//        String secretKey = details.getSecretKey();
//        if (secretKey == null || !"secret".equals(secretKey)) {
//            throw new InsufficientAuthenticationException("InsufficientAuthenticationException");
//        }

        AjaxAuthenticationToken authenticationToken =
                new AjaxAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());

        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AjaxAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
