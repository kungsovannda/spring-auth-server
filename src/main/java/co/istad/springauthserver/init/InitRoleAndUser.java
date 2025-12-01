package co.istad.springauthserver.init;

import co.istad.springauthserver.domain.Role;
import co.istad.springauthserver.domain.User;
import co.istad.springauthserver.feature.role.RoleRepository;
import co.istad.springauthserver.feature.user.UserRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;


@Component
@RequiredArgsConstructor
public class InitRoleAndUser {

    private final RoleRepository repo;
    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;

    @PostConstruct
    public void init() {
        Role role = Role.builder()
                .uuid(UUID.randomUUID().toString())
                .role("USER")
                .build();

        User user = User.builder()
                .uuid(UUID.randomUUID().toString())
                .roles(List.of(role))
                .email("kungsovannda@gmail.com")
                .password(passwordEncoder.encode("password"))
                .username("kungsovannda")
                .familyName("Kung")
                .givenName("Sovannda")
                .build();
        repo.save(role);
        userRepo.save(user);
    }
}
