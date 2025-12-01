package co.istad.springauthserver.feature.user;

import co.istad.springauthserver.feature.user.dto.UserRequest;
import co.istad.springauthserver.feature.user.dto.UserResponse;

public interface UserService {

    UserResponse createUser(UserRequest userRequest);
    void disableUser(String uuid);
    void enableUser(String uuid);

}
