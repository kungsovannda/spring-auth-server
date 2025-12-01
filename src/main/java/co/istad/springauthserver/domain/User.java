package co.istad.springauthserver.domain;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Entity
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Integer id;

    @Column(unique = true, nullable = false)
    private String uuid;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(length = 64, nullable = false)
    private String givenName;

    @Column(length = 64, nullable = false)
    private String familyName;

    @Column(unique = true, nullable = false)
    private String email;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "users_roles",
            inverseJoinColumns = {@JoinColumn(name = "role_id")},
            joinColumns = {@JoinColumn(name = "user_id")}
    )
    private List<Role> roles;

    @Column(nullable = false)
    private boolean isEnabled;

}
