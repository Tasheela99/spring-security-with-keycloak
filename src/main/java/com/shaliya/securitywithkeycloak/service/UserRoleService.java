package com.shaliya.securitywithkeycloak.service;

import com.shaliya.securitywithkeycloak.dto.request.*;
import com.shaliya.securitywithkeycloak.dto.response.*;

import java.util.List;

public interface UserRoleService {
    void createUser(RequestUserRoleDto dto);

    List<ResponseUserRoleDTO> findAllUserRole();
}
