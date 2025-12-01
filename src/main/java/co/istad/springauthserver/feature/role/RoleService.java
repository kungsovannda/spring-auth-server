package co.istad.springauthserver.feature.role;

import co.istad.springauthserver.feature.role.dto.RoleRequest;
import co.istad.springauthserver.feature.role.dto.RoleResponse;

public interface RoleService {

    RoleResponse createRole(RoleRequest roleRequest);
}
