package com.shaliya.securitywithkeycloak.service;

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
