// Scanner fixture: safe code. Must produce NO findings.
// An admin endpoint may take a user id on purpose, because only admins can call it.
package fixture;

@RestController
@PreAuthorize("hasRole('ADMIN')")
public class AdminUserController {

    @GetMapping("/admin/users/{userId}/orders")
    public List<Order> ordersOf(@PathVariable String userId) {
        return repository.findByOwnerId(userId);
    }

    // Regular users: identity only from the verified token.
    @GetMapping("/api/orders")
    public List<Order> myOrders(@AuthenticationPrincipal Jwt jwt) {
        SecurityPrincipal user = ClaimsPrincipal.fromVerifiedClaims(jwt.getClaims(), ClaimMapping.keycloak("orders-api"));
        return repository.findByOwnerId(user.getId());
    }
}
