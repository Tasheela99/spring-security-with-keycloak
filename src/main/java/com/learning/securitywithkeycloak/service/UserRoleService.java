package com.learning.securitywithkeycloak.service;

import com.learning.securitywithkeycloak.dto.request.RequestUserRoleDto;
import com.learning.securitywithkeycloak.dto.response.ResponseUserRoleDTO;
import com.shaliya.securitywithkeycloak.dto.request.*;
import com.shaliya.securitywithkeycloak.dto.response.*;

import java.util.List;

public interface UserRoleService {
    void createUser(RequestUserRoleDto dto);

    List<ResponseUserRoleDTO> findAllUserRole();
}
