package com.accommodationbooking.authorizationservice.repository;

import com.accommodationbooking.authorizationservice.model.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    @EntityGraph(attributePaths = "roles")
    Optional<User> findByEmail(final String email);

    boolean existsByEmail(final String email);
}
