package com.learning.securitywithkeycloak.service;


import com.learning.securitywithkeycloak.dto.request.RequestSystemUserAvatarDto;
import com.shaliya.securitywithkeycloak.dto.request.*;
import org.springframework.web.multipart.MultipartFile;

import java.sql.SQLException;

public interface SystemUserAvatarService {
    void createSystemUserAvatar(RequestSystemUserAvatarDto dto, String email, MultipartFile file) throws SQLException;
}
