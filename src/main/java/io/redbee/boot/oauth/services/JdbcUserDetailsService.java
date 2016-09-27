package io.redbee.boot.oauth.services;

import java.util.Collection;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.springframework.stereotype.Service;

import io.redbee.boot.oauth.model.OauthUser;

@Service
public class JdbcUserDetailsService implements UserDetailsContextMapper {
	
	 private static final Logger LOGGER = LoggerFactory.getLogger(JdbcUserDetailsService.class);
	 
	 private static final String USER_DETAILS_QUERY = "SELECT * FROM USER ru JOIN USERSDETAILS u ON ru.USR_NOMBRE = u.USR_NOMBRE WHERE ru.USR_NOMBRE = ? AND ru.USR_ESTADO <> 2";
	    private static final String KEY_ENCRYPT_RAW_COLUMN = "KEY_ENCRYPT_RAW";
	    private static final String PASS_ENCRYPT_RAW_COLUMN = "PASS_ENCRIPT_RAW";
	    private static final String USR_ESTADO_COLUMN ="USR_ESTADO";
	    private static final String USR_MAIL_COLUMN = "USR_MAIL";
	    private static final String USR_NOMBRES_COLUMN = "USER_NOMBRES";
	    private static final String USR_APELLIDOS_COLUMN = "USER_APELLIDOS";
	    private static final String USR_NOMBRE_COLUMN = "USR_NOMBRE";
	    private static final String PASS_EXPIRATION = "EXP_DATE";
	    
	    private JdbcTemplate jdbcTemplate;

	    @Autowired
	    public JdbcUserDetailsService(JdbcTemplate jdbcTemplate){
	        this.jdbcTemplate = jdbcTemplate;
	    }

	    /**
	     * Creates a fully populated UserDetails object for use by the security framework.
	     *
	     * @param ctx         the context object which contains the user information.
	     * @param username    the user's supplied login name.
	     * @param authorities collection permits
	     * @return the user object.
	     */
	    @Override
	    public UserDetails mapUserFromContext(DirContextOperations ctx, String username, Collection<? extends GrantedAuthority> authorities) {
	        try {
	            return getOauthUser(username, authorities);
	        } catch (EmptyResultDataAccessException e) {
	            LOGGER.debug("Error trying to mapping the user from context");
	            LOGGER.error("Stacktrace: ", e);
	            return null;
	        }
	    }

	    private OauthUser getOauthUser(String username, Collection<? extends GrantedAuthority> authorities) {
	        return jdbcTemplate.queryForObject(USER_DETAILS_QUERY,
	                new String[]{username.toUpperCase()},
	                (rs, rowNum) -> new OauthUser(
	                        rs.getString(USR_NOMBRE_COLUMN),
	                        username,
	                        rs.getString(USR_NOMBRES_COLUMN),
	                        rs.getString(USR_APELLIDOS_COLUMN),
	                        rs.getString(USR_MAIL_COLUMN),
	                        rs.getString(KEY_ENCRYPT_RAW_COLUMN),
	                        rs.getString(PASS_ENCRYPT_RAW_COLUMN),
	                        rs.getInt(USR_ESTADO_COLUMN),
	                        new Date(rs.getDate(PASS_EXPIRATION).getTime()),
	                        authorities)
	        );
	    }

	    /**
	     * Reverse of the above operation. Populates a context object from the supplied user object.
	     * Called when saving a user, for example.
	     *
	     * @param user {@link UserDetails}
	     * @param ctx {@link DirContextAdapter}
	     */
	 

		@Override
		public void mapUserToContext(UserDetails user, DirContextAdapter ctx) {
			// TODO Auto-generated method stub
			
		}
	 

}
