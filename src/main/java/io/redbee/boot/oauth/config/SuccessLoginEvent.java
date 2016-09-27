package io.redbee.boot.oauth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;

import io.redbee.boot.oauth.model.OauthUser;

@Configuration
public class SuccessLoginEvent implements ApplicationListener<AbstractAuthenticationEvent>{
	
	    @Value("${ldap.mocked}")
	    private Boolean isMocked;

	    @Override
	    public void onApplicationEvent(AbstractAuthenticationEvent event) {
	        if(!isMocked) {
	            if(event.getAuthentication().isAuthenticated()) {
	                if (!((OauthUser) event.getAuthentication().getPrincipal()).isEnabled()) {
	                    throw new DisabledException("Cuenta Inhabilitada");
	                }
	            }
	        }

	    }

}
