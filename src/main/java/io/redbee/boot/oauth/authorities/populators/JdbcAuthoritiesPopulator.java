package io.redbee.boot.oauth.authorities.populators;

import java.sql.SQLException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.ldap.AuthenticationException;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.stereotype.Component;

import io.redbee.boot.oauth.model.OauthAuthority;

@Component
public class JdbcAuthoritiesPopulator  implements LdapAuthoritiesPopulator {
	 private static final String USERNAME_QUERY = "SELECT US.USR_NOMBRE FROM USER US WHERE US.USR_NOMBRE = ?";
	    private static final String RL_BY_USER_QUERY = "SELECT RL.ROL_CODIGO, RL.TNT_CODIGO FROM ROLES RL, USER US  WHERE US.USR_NOMBRE = ? AND US.USR_NOMBRE = RL.USR_NOMBRE AND US.USR_ESTADO <> 2 ORDER BY TNT_CODIGO ASC";
	    public static final String RL_CODIGO_COLUMN = "ROL_CODIGO";
	    public static final String TNT_CODIGO_COLUMN = "TNT_CODIGO";
	    private JdbcTemplate jdbcTemplate;

	    @Autowired
	    public JdbcAuthoritiesPopulator(JdbcTemplate jdbcTemplate){
	        this.jdbcTemplate = jdbcTemplate;
	    }

	    /**
	     * Get the granted authorities for the given user.
	     * @param userData the context object which was returned by the LDAP authenticator.
	     * @param username that consulting the roles
	     * @return {@link List}&lt;{@link GrantedAuthority}&gt;}
	     */
	    @Override
	    public Collection<? extends GrantedAuthority> getGrantedAuthorities(DirContextOperations userData, String username) throws AuthenticationException {
	        try {
	            return getGrantedAuthoritiesByUser(getUsername(username));
	        } catch (SQLException e) {
	            return Collections.emptySet();
	        }
	    }

	    private List<GrantedAuthority> getGrantedAuthoritiesByUser(String username) throws SQLException {
	        List<GrantedAuthority> result = jdbcTemplate.query(RL_BY_USER_QUERY,
	                new String[]{username.toUpperCase()},
	                (rs, rowNum) -> new OauthAuthority(
	                        rs.getString(RL_CODIGO_COLUMN),
	                        rs.getLong(TNT_CODIGO_COLUMN)));
	        return result;
	    }

	    private String getUsername(String ldapUsername){
	        try {
	            return jdbcTemplate.queryForObject(USERNAME_QUERY,new String[]{ldapUsername.toUpperCase()}, String.class);
	        } catch (EmptyResultDataAccessException e){
	            throw new AuthenticationCredentialsNotFoundException("Nonexistent account");
	        }

	    }

		
}
