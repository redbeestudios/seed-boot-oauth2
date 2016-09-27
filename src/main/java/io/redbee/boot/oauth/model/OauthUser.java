package io.redbee.boot.oauth.model;

import java.util.Collection;
import java.util.Date;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import io.redbee.boot.oauth.config.AccountStatus;

public class OauthUser implements UserDetails{
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -7365825570851313146L;
	
	private String  keyEncrypt;
    private String  passEncrypt;
    private String  dbUser;
    private String  username;
    private String  userNames;
    private String  userSurname;
    private String  email;
    private Integer status;
    private Date    passExpiration;
    private Boolean accountNotLocked;
    
    
    private Collection<? extends GrantedAuthority> grantedAuthorities;
    
    public OauthUser(String dbUser, String username, String userNames, String userSurname, String email, String keyEncrypt, String passEncrypt, Integer status, Date passwordExpiration ,Collection<? extends GrantedAuthority> authorities) {
        this.dbUser = dbUser;
        this.username = username;
        this.userNames = userNames;
        this.userSurname = userSurname;
        this.email = email;
        this.keyEncrypt = keyEncrypt;
        this.passEncrypt = passEncrypt;
        this.status = status;
        this.passExpiration = passwordExpiration;     
        this.grantedAuthorities = authorities;
        this.status = status;
        
        AccountStatus acSt = AccountStatus.values()[this.status];
        
        switch (acSt) {
		case Valid:
			this.accountNotLocked = true;
			break;
		case Blocked:
			this.accountNotLocked = false;

		default:
			this.accountNotLocked = false;
		}
        
    }
    
    @Override
    public String getPassword() {
        return null;
    }


    public String getKeyEncrypt() {
        return this.keyEncrypt;
    }

    public String getPassEncrypt() {
        return this.passEncrypt;
    }

    public String getEmail() {
        return this.email;
    }

    public String getUserSurname() {
        return this.userSurname;
    }

    public String getUserNames() {
        return this.userNames;
    }

    public String getDbUser() {
        return this.dbUser;
    }
    

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.grantedAuthorities;
	}


	@Override
	public String getUsername() {
		
		return this.username;
	}

	@Override
	public boolean isAccountNonExpired() {
		
		return this.passExpiration.after( new Date() );
	}

	@Override
	public boolean isAccountNonLocked() {
		
		return this.accountNotLocked;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return this.passExpiration.after( new Date() );
	}

	@Override
	public boolean isEnabled() {
		
		return this.accountNotLocked;
	}

}
