package com.shaliya.securitywithkeycloak.repository;

import com.shaliya.securitywithkeycloak.entity.Otp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import java.util.Optional;

@EnableJpaRepositories
public interface OtpRepo extends JpaRepository<Otp,String> {
    @Query(nativeQuery = true, value = "SELECT * FROM otp WHERE user_property_id=?1")
    public Optional<Otp> findBySystemUserId(String id);
}
