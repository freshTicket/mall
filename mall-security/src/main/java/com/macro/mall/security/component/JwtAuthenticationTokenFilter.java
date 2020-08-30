package com.macro.mall.security.component;

import com.macro.mall.security.util.JwtTokenUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * JWT登录授权过滤器
 * Created by macro on 2018/4/26.
 */
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthenticationTokenFilter.class);
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Value("${jwt.tokenHeader}")
    private String tokenHeader;
    @Value("${jwt.tokenHead}")
    private String tokenHead;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String authHeader = request.getHeader(this.tokenHeader);
        if (authHeader != null && authHeader.startsWith(this.tokenHead)) {
            String authToken = authHeader.substring(this.tokenHead.length());// The part after "Bearer "
            String username = jwtTokenUtil.getUserNameFromToken(authToken);
            LOGGER.info("checking username:{}", username);
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);  //调用重写的loadUserByUsername()方法，见SecurityConfig的子类MallSecurityConfig
                if (jwtTokenUtil.validateToken(authToken, userDetails)) {
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    LOGGER.info("authenticated user:{}", username);
                    /**
                     * 此处需要理解SpringSecurity的鉴权机制
                     * authentication只对单次请求有效
                     * 即使是同一个用户，该次请求通过了鉴权，那么鉴权后，也只对当次请求放行，下一次请求仍然需要鉴权
                     * 这是因为在每一次请求时，SecurityContextHolder.getContext()返回的SecurityContext对象并不是同一个对象
                     * 查看源码，SecurityContextHolder中有这么一段代码
                         public static void clearContext() {
                             strategy.clearContext();
                         }

                         public static SecurityContext getContext() {
                             return strategy.getContext();
                         }
                     --------------------------------------------------------------
                     GlobalSecurityContextHolderStrategy实现类中，有下面一段代码：
                        public void clearContext() {
                            contextHolder = null;
                        }

                         public SecurityContext getContext() {
                            if (contextHolder == null) {
                                contextHolder = new SecurityContextImpl();  //每次都会new一个对象
                            }
                            return contextHolder;
                         }
                     ---------------------------------------------------------------
                     * 此处推测，可能SecurityContextHolder并不是单例对象，每次请求都会new一个SecurityContextHolder实例，
                     * 而每次实例化都会调用SecurityContextHolder.clearContext()方法，将GlobalSecurityContextHolderStrategy对象中的contextHolder置空
                     * 导致contextHolder只能通过new()进行实例化
                     * 这就导致每次请求的SecurityContextHolder.getContext().setAuthentication(authentication)只对当次请求有效，
                     * 当次请求会被放行
                     * 而下一次请求时，SecurityContextHolder.getContext().getAuthentication()并不能获取到authentication对象
                     * 因此需要再次进行鉴权
                     */
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        }
        chain.doFilter(request, response);
    }
}
