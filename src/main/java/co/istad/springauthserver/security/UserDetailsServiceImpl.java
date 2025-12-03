package co.istad.springauthserver.security;

import co.istad.springauthserver.domain.User;
import co.istad.springauthserver.feature.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not found"));
//        org.springframework.security.core.userdetails.User userDetails = new CustomUserDetails();
//        userDetails.setUser(user);
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .roles(user.getRoles().stream().toString())
                .password(user.getPassword())
                .build();
    }
}
