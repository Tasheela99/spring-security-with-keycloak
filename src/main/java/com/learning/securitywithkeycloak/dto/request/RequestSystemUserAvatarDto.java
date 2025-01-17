package com.learning.securitywithkeycloak.dto.request;

import lombok.*;

import java.util.Date;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class RequestSystemUserAvatarDto {
    private Date createdDate;
}
