package com.shaliya.securitywithkeycloak.api;

import com.shaliya.securitywithkeycloak.dto.request.RequestUserDto;
import com.shaliya.securitywithkeycloak.dto.request.RequestUserLoginRequest;
import com.shaliya.securitywithkeycloak.dto.request.RequestUserPasswordResetDto;
import com.shaliya.securitywithkeycloak.dto.response.ResponseUserDetailsDto;
import com.shaliya.securitywithkeycloak.service.UserService;
import com.shaliya.securitywithkeycloak.service.impl.JwtService;
import com.shaliya.securitywithkeycloak.util.StandardResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/user-service/api/v1/users")
@RequiredArgsConstructor
public class SystemUserController {

    private final UserService userService;
    private final JwtService jwtService;

    @PostMapping("/signup")
    public ResponseEntity<StandardResponse> createUser(@RequestBody RequestUserDto dto) throws IOException {
        userService.createUser(dto);
        return new ResponseEntity<>(
                new StandardResponse(201,
                        "Account was created. verify your email now (%s)".formatted(dto.getEmail()), null),
                HttpStatus.CREATED
        );
    }

    @PostMapping("/login")
    public ResponseEntity<StandardResponse> loginUser(@RequestBody RequestUserLoginRequest dto) {
        return new ResponseEntity<>(
                new StandardResponse(200,
                        "Login Successful!", userService.userLogin(dto)),
                HttpStatus.OK
        );
    }

    @PostMapping("/verify-email")
    public ResponseEntity<StandardResponse> verifyEmail(@RequestParam String otp, @RequestParam String email) {
        boolean isVerified = userService.verifyEmail(otp, email);
        if (isVerified) {
            return new ResponseEntity<>(
                    new StandardResponse(200,
                            "Account was Verified. Please log in", null),
                    HttpStatus.OK
            );
        } else {
            return new ResponseEntity<>(
                    new StandardResponse(400,
                            "Invalid OTP. Please insert the correct code to verify your email.", null),
                    HttpStatus.BAD_REQUEST
            );
        }
    }

    @PostMapping(path = {"/resend"}, params = {"email"})
    public ResponseEntity<StandardResponse> resend(
            @RequestParam String email) throws IOException {
        userService.resend(email);
        return new ResponseEntity<>(
                new StandardResponse(201,
                        "OTP resent to your registered email".formatted(email), null),
                HttpStatus.CREATED
        );
    }

    @PostMapping(path = {"/forgot-password-request-code"}, params = {"email"})
    public ResponseEntity<StandardResponse> forgotPasswordSendVerificationCode(
            @RequestParam String email) throws IOException {

        userService.forgotPasswordSendVerificationCode(email);
        return new ResponseEntity<>(
                new StandardResponse(201,
                        "Password reset verification code has been sent", null),
                HttpStatus.CREATED
        );
    }

    @PostMapping(path = {"/verify-reset"}, params = {"otp", "email"})
    public ResponseEntity<StandardResponse> verifyReset(
            @RequestParam String otp, @RequestParam String email) {


        boolean isVerified = userService.verifyReset(otp, email);
        if (isVerified) {
            return new ResponseEntity<>(
                    new StandardResponse(200,
                            "Please reset your password now", true),
                    HttpStatus.OK
            );
        } else {
            return new ResponseEntity<>(
                    new StandardResponse(400,
                            "Invalid OTP. Please insert the correct code to verify your email.", false),
                    HttpStatus.BAD_REQUEST
            );
        }
    }

    @PostMapping(path = {"/reset-password"})
    public ResponseEntity<StandardResponse> passwordReset(
            @RequestBody RequestUserPasswordResetDto dto) {
        return new ResponseEntity<>(
                new StandardResponse(200,
                        "Password reset completed successfully", userService.passwordReset(dto)),
                HttpStatus.OK
        );


    }

    @GetMapping("/verify-admin")
    public ResponseEntity<StandardResponse> verifyAdmin(
            @RequestHeader("Authorization") String tokenHeader
    ) {
        String token = tokenHeader.replace("Bearer ", "");
        String email = jwtService.getEmail(token);


        boolean isVerified = userService.verifyAdmin(email);
        if (isVerified) {
            return new ResponseEntity<>(
                    new StandardResponse(200,
                            "Admin was Verified!", true),
                    HttpStatus.OK
            );
        } else {
            return new ResponseEntity<>(
                    new StandardResponse(400,
                            "User is not an Admin!", false),
                    HttpStatus.BAD_REQUEST
            );
        }
    }

    @GetMapping("/get-user-details")
    public ResponseEntity<StandardResponse> getUserDetails(
            @RequestHeader("Authorization") String tokenHeader
    ) {
        String token = tokenHeader.replace("Bearer ", "");
        String email = jwtService.getEmail(token);

        ResponseUserDetailsDto userDetails = userService.getUserDetails(email);
        System.out.println(userDetails.getResourceUrl());

        return new ResponseEntity<>(
                new StandardResponse(200,
                        "user details!", userDetails),
                HttpStatus.OK
        );
    }




}
