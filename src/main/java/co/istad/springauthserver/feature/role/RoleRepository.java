package co.istad.springauthserver.feature.role;

import co.istad.springauthserver.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByRole(String role);

    boolean existsByRole(String role);
}
