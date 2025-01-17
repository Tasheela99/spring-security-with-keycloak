package com.shaliya.securitywithkeycloak.dto.request;

import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class RequestUserRoleDto {
    private String roleName;
}
