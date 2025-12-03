package co.istad.springauthserver.domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
@Entity
@ToString(exclude = "users")
@Table(name = "roles")
public class Role implements GrantedAuthority {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String uuid;

    @Column(unique = true)
    private String role;

    @JsonIgnore
    @ManyToMany(mappedBy = "roles")
    private List<User> users;

    @Override
    public @Nullable String getAuthority() {
        return "ROLE_" + role;
    }
}
