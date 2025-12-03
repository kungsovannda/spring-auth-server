package co.istad.springauthserver.feature.client;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/api/v1/clients")
@RequiredArgsConstructor
public class ClientController {

    private final JpaRegisteredClientRepository registeredClientRepository;

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public void registerClient(@RequestBody RegisteredClient request) {
        registeredClientRepository.save(request);
    }
}
