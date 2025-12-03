package co.istad.springauthserver.feature.client;

import java.util.Optional;


import co.istad.springauthserver.domain.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientRepository extends JpaRepository<Client, String> {
    Optional<Client> findByClientId(String clientId);

    boolean existsByClientId(String clientId);
}