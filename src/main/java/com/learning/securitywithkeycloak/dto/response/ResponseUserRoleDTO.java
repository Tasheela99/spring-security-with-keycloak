package com.learning.securitywithkeycloak.dto.response;

import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class ResponseUserRoleDTO {
    private String roleName;
}
