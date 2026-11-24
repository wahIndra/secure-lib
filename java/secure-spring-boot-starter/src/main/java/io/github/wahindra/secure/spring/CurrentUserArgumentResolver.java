package io.github.wahindra.secure.spring;

import io.github.wahindra.secure.access.AccessDeniedException;
import io.github.wahindra.secure.access.ClaimMapping;
import io.github.wahindra.secure.access.ClaimsPrincipal;
import io.github.wahindra.secure.access.SecurityPrincipal;
import io.github.wahindra.secure.access.SimplePrincipal;
import org.springframework.core.MethodParameter;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.ClassUtils;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.util.ArrayList;
import java.util.List;

/**
 * Resolves {@link CurrentUser} parameters from Spring Security's authentication:
 * a JWT ({@code oauth2ResourceServer().jwt()}) goes through the configured {@link ClaimMapping};
 * any other authenticated user (session / form login) becomes a principal with its name and its
 * {@code ROLE_*} authorities as roles.
 */
public class CurrentUserArgumentResolver implements HandlerMethodArgumentResolver {

    private static final boolean JWT_PRESENT = ClassUtils.isPresent(
            "org.springframework.security.oauth2.jwt.Jwt", CurrentUserArgumentResolver.class.getClassLoader());

    private final ClaimMapping mapping;

    public CurrentUserArgumentResolver(ClaimMapping mapping) {
        this.mapping = mapping;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return parameter.hasParameterAnnotation(CurrentUser.class)
                && SecurityPrincipal.class.isAssignableFrom(parameter.getParameterType());
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mav, NativeWebRequest request,
                                  WebDataBinderFactory binderFactory) {
        CurrentUser annotation = parameter.getParameterAnnotation(CurrentUser.class);
        SecurityPrincipal user = current(mapping);
        if (user == null && (annotation == null || annotation.required())) {
            throw new AccessDeniedException("authentication required", true);
        }
        return user;
    }

    /** The authenticated caller, or {@code null}. */
    static SecurityPrincipal current(ClaimMapping mapping) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            return null;
        }
        if (JWT_PRESENT) {
            SecurityPrincipal fromJwt = Jwts.fromAuthentication(auth, mapping);
            if (fromJwt != null) {
                return fromJwt;
            }
        }
        List<String> roles = new ArrayList<String>();
        for (GrantedAuthority a : auth.getAuthorities()) {
            String name = a.getAuthority();
            if (name != null && name.startsWith("ROLE_")) {
                roles.add(name.substring("ROLE_".length()));
            }
        }
        return SimplePrincipal.builder(auth.getName()).roles(roles.toArray(new String[0])).build();
    }

    /** Separate class so the JWT types are only loaded when spring-security-oauth2-jose is present. */
    private static final class Jwts {
        static SecurityPrincipal fromAuthentication(Authentication auth, ClaimMapping mapping) {
            Object p = auth.getPrincipal();
            if (p instanceof org.springframework.security.oauth2.jwt.Jwt) {
                return ClaimsPrincipal.fromVerifiedClaims(((org.springframework.security.oauth2.jwt.Jwt) p).getClaims(), mapping);
            }
            return null;
        }
    }
}
