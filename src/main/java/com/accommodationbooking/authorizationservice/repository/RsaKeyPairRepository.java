package com.accommodationbooking.authorizationservice.repository;

import com.accommodationbooking.authorizationservice.model.RsaKeyPair;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RsaKeyPairRepository extends JpaRepository<RsaKeyPair, String> {
}
