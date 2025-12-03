package co.istad.springauthserver.security;

import co.istad.springauthserver.domain.User;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@Getter
@Setter
@NoArgsConstructor
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public class CustomUserDetails implements UserDetails {

    private User user;

    @Override
    @JsonProperty("roles")
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getRoles();
    }

    @Override
    @JsonIgnore   // never expose password in JSON
    public @Nullable String getPassword() {
        return user.getPassword();
    }

    @Override
    @JsonProperty("username")
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    @JsonProperty("enabled")
    public boolean isEnabled() {
        return user.isEnabled();
    }
}
