package io.redbee.boot.oauth.handlers;


import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationTargetUrlRequestHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;



public class CustomLogoutSuccessHandler extends AbstractAuthenticationTargetUrlRequestHandler implements LogoutSuccessHandler{
	
	private static final Logger LOGGER = LoggerFactory.getLogger(CustomLogoutSuccessHandler.class);

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String redirectUri = request.getParameter("redirect_uri");
        LOGGER.info("Host: " + request.getRemoteHost());
        LOGGER.info("Address: " + request.getRemoteAddr());
        LOGGER.info("Attempt to redirect to: " + redirectUri);
        this.setDefaultTargetUrl(redirectUri);
        this.setAlwaysUseDefaultTargetUrl(true);
        super.handle(request, response, authentication);
    }

}
