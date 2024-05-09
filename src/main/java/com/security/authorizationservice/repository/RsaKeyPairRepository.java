package com.security.authorizationservice.repository;

import com.security.authorizationservice.model.RsaKeyPair;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RsaKeyPairRepository extends JpaRepository<RsaKeyPair, String> {
}
