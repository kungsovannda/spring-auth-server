package co.istad.springauthserver.feature.user;

import co.istad.springauthserver.feature.user.dto.UserRequest;
import co.istad.springauthserver.feature.user.dto.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping(path = "/api/v1/users")
public class UserController {

    private final UserService userService;

    @PostMapping
    public UserResponse createUser(@RequestBody UserRequest userRequest) {
        return userService.createUser(userRequest);
    }

    @PutMapping("/{uuid}/enable")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void enableUser(@PathVariable String uuid) {
        userService.enableUser(uuid);
    }

    @PutMapping("/{uuid}/diable")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void diableUser(@PathVariable String uuid) {
        userService.disableUser(uuid);
    }
}
