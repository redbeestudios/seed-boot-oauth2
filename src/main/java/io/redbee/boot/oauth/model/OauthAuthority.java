package io.redbee.boot.oauth.model;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class OauthAuthority implements GrantedAuthority {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -2418641339691964172L;
	
	private Long tenant;
    private SimpleGrantedAuthority authority;
    private String ROLE_FORMAT = "ROLE_%s-%s";

	public OauthAuthority(String role, long tenant) {
		 this.tenant = tenant;
	        this.authority = new SimpleGrantedAuthority(role);
	}

	@Override
	public String getAuthority() {
		return String.format(ROLE_FORMAT,tenant,authority.getAuthority());
	}

}
