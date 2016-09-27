package io.redbee.boot.oauth.filters;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.web.filter.OncePerRequestFilter;

@Order(value = Ordered.HIGHEST_PRECEDENCE)
public class CORSFilter extends OncePerRequestFilter {
	
	 public static final String ACCESS_CONTROL_ALLOW_ORIGIN = "Access-Control-Allow-Origin";
	    public static final String ACCESS_CONTROL_ALLOW_ORIGIN_VALUE = "*";
	    public static final String ACCESS_CONTROL_ALLOW_METHODS = "Access-Control-Allow-Methods";
	    public static final String ACCESS_CONTROL_ALLOW_METHODS_VALUE = "POST, GET, OPTIONS, DELETE";
	    public static final String ACCESS_CONTROL_ALLOW_HEADERS = "Access-Control-Allow-Headers";
	    public static final String ACCESS_CONTROL_ALLOW_HEADERS_VALUE = "x-requested-with, Authorization, Oauth-Token";

	    @Override
	    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
	        response.setHeader(ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_ALLOW_ORIGIN_VALUE);
	        response.setHeader(ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_METHODS_VALUE);
	        response.setHeader(ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_HEADERS_VALUE);

	        if(!"OPTIONS".equalsIgnoreCase(request.getMethod())){
	            filterChain.doFilter(request, response);
	        }
	    }

}
