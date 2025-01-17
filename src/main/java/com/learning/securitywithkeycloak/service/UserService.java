package com.learning.securitywithkeycloak.service;

import com.learning.securitywithkeycloak.dto.request.RequestUserDto;
import com.learning.securitywithkeycloak.dto.request.RequestUserLoginRequest;
import com.learning.securitywithkeycloak.dto.request.RequestUserPasswordResetDto;
import com.learning.securitywithkeycloak.dto.response.ResponseUserDetailsDto;
import com.shaliya.securitywithkeycloak.dto.request.*;
import com.shaliya.securitywithkeycloak.dto.response.*;


import java.io.IOException;

public interface UserService {
    public void createUser(RequestUserDto dto) throws IOException;
    public boolean verifyEmail(String otp, String email);
    public Object userLogin(RequestUserLoginRequest request);
    public boolean verifyAdmin(String email);
     public ResponseUserDetailsDto getUserDetails(String email);

    public void resend(String email);

    public void forgotPasswordSendVerificationCode(String email);

    public boolean verifyReset(String otp, String email);

    public boolean passwordReset(RequestUserPasswordResetDto dto);


}
