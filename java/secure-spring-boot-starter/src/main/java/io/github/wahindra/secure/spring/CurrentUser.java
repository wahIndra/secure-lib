package io.github.wahindra.secure.spring;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Injects the authenticated caller as a {@link io.github.wahindra.secure.access.SecurityPrincipal},
 * built from the verified token through the configured {@code secure.identity} mapping (or from
 * the Spring Security authentication for session logins). Identity therefore always comes from
 * authentication, never from the request.
 *
 * <pre>
 * &#64;GetMapping("/api/orders/{id}")
 * Order order(&#64;PathVariable long id, &#64;CurrentUser SecurityPrincipal user) {
 *     Order order = repo.findById(id).orElseThrow(NotFound::new);
 *     AccessGuard.requireOwnerOrRole(user, order.getOwnerId(), "admin");
 *     return order;
 * }
 * </pre>
 *
 * Without an authenticated user the request fails with 401, unless {@link #required()} is false,
 * in which case the parameter is {@code null}.
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface CurrentUser {

    boolean required() default true;
}
