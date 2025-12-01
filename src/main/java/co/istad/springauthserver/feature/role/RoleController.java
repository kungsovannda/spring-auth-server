package co.istad.springauthserver.feature.role;

import co.istad.springauthserver.feature.role.dto.RoleRequest;
import co.istad.springauthserver.feature.role.dto.RoleResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping(path = "/api/v1/roles")
public class RoleController {

    private final RoleService roleService;

    @PostMapping
    public RoleResponse createRole(@RequestBody RoleRequest roleRequest) {
        return roleService.createRole(roleRequest);
    }

}
