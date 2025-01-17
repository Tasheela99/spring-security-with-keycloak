package com.shaliya.securitywithkeycloak.repository;

import com.shaliya.securitywithkeycloak.entity.SystemUserAvatar;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import java.util.Optional;

@EnableJpaRepositories
public interface SystemUserAvatarRepo extends JpaRepository<SystemUserAvatar,String> {

    @Query(value = "SELECT * FROM system_user_avatar WHERE user_property_id=?1", nativeQuery = true)
    public Optional<SystemUserAvatar> findByUserId(String id);

}
