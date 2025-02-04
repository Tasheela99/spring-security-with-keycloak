package com.learning.securitywithkeycloak.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ResponseUserDetailsDto {
    private String email;
    private String firstName;
    private String lastName;
    private String resourceUrl;
}
