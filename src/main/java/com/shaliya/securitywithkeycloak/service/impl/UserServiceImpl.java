package com.shaliya.securitywithkeycloak.service.impl;

import com.shaliya.securitywithkeycloak.config.KeycloakSecurityUtil;
import com.shaliya.securitywithkeycloak.dto.request.*;
import com.shaliya.securitywithkeycloak.dto.response.*;

import com.shaliya.securitywithkeycloak.entity.*;
import com.shaliya.securitywithkeycloak.exception.*;
import com.shaliya.securitywithkeycloak.repository.*;
import com.shaliya.securitywithkeycloak.service.*;
import com.shaliya.securitywithkeycloak.util.*;

import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.common.util.CollectionUtil;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.*;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final KeycloakSecurityUtil keycloakUtil;
    private final SystemUserRepo systemUserRepo;
    private final EmailService emailService;
    private final OtpRepo otpRepo;
    private final OtpGenerator otpGenerator;
    private final FileDataExtractor fileDataExtractor;

    @Value("${keycloak.config.realm}")
    private String realm;

    @Value("${keycloak.config.client-id}")
    private String clientId;


    @Value("${keycloak.config.secret}")
    private String secret;

    @Value("${spring.security.oauth2.resourceserver.jwt.token-uri}")
    private String keyCloakApiUrl;


    @Override
    public void createUser(RequestUserDto dto) throws IOException {

        String userId = "";
        String otpId = "";
        Keycloak keycloak = null;

        UserRepresentation existingUser = null;
        keycloak = keycloakUtil.getKeycloakInstance();
        // Check if user already exists
        existingUser = keycloak.realm(realm).users().search(dto.getEmail()).stream()
                .findFirst().orElse(null);

        if (existingUser != null) {
            Optional<SystemUser> byEmail = systemUserRepo.findByEmail(existingUser.getEmail());
            if (byEmail.isEmpty()) {
                keycloak.realm(realm).users().delete(existingUser.getId());
            } else {
                throw new DuplicateEntryException("User with email " + dto.getEmail() + " already exists.");
            }

        } else {
            Optional<SystemUser> byEmail = systemUserRepo.findByEmail(dto.getEmail());
            if (byEmail.isPresent()) {
                Optional<Otp> bySystemUserId = otpRepo.findBySystemUserId(byEmail.get().getPropertyId());
                if (bySystemUserId.isPresent()) {
                    otpRepo.deleteById(bySystemUserId.get().getPropertyId());
                }
                systemUserRepo.deleteById(byEmail.get().getPropertyId());
            }
        }

        UserRepresentation userRep = mapUserRep(dto);
        Response res = keycloak.realm(realm).users().create(userRep);
        // Add the admin role to the newly created user
        if (res.getStatus() == Response.Status.CREATED.getStatusCode()) {
            RoleRepresentation userRole = keycloak.realm(realm).roles().get("user").toRepresentation();
            userId = res.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
            keycloak.realm(realm).users().get(userId).roles().realmLevel().add(Arrays.asList(userRole));
            SystemUser createdSystemUser = SystemUser.builder()
                    .propertyId(userId)
                    .activeState(false)
                    .email(dto.getEmail())
                    .firstName(dto.getFirstName())
                    .lastName(dto.getLastName())
                    .isAccountNonExpired(true)
                    .isEmailVerified(false)
                    .isAccountNonLocked(true)
                    .isEnabled(false)
                    .createdDate(dto.getCreatedDate())
                    .build();
            SystemUser savedUser = systemUserRepo.save(createdSystemUser);
            Otp otp = Otp.builder()
                    .propertyId(UUID.randomUUID().toString())
                    .code(otpGenerator.generateOtp(4))
                    .createdDate(dto.getCreatedDate())
                    .isVerified(false)
                    .attempts(0)
                    .systemUser(savedUser)
                    .build();
            otpRepo.save(otp);
            emailService.sendUserSignupVerificationCode(dto.getEmail(),
                    "Verify Your Email Address for Developers Stack Access", otp.getCode());
        }
    }

    @Override
    public void resend(String email) {
        try {
            Optional<SystemUser> selectedUserObj = systemUserRepo.findByEmail(email);
            if (selectedUserObj.isEmpty()) {
                throw new EntryNotFoundException("Unable to find any users associated with the provided email address.");
            }
            SystemUser systemUser = selectedUserObj.get();
            if (systemUser.getIsEmailVerified()) {
                throw new DuplicateEntryException("The email is already activated");
            }
            Otp selectedOtpObj = systemUser.getOtp();
            if (selectedOtpObj.getAttempts() >= 5) {
                String code = otpGenerator.generateOtp(4);


                emailService.sendUserSignupVerificationCode(email,
                        "Verify Your Email Address for Developers Stack Access", code);


                selectedOtpObj.setAttempts(0);
                selectedOtpObj.setCode(code);
                selectedOtpObj.setCreatedDate(new Date());
                otpRepo.save(selectedOtpObj);

                throw new TooManyRequestException("Too many unsuccessful attempts. New OTP sent and please verify.");
            }
            emailService.sendUserSignupVerificationCode(systemUser.getEmail(),
                    "Verify Your Email Address for Developers Stack Access", selectedOtpObj.getCode());

        } catch (Exception e) {

            if (e instanceof DuplicateEntryException) {
                throw new DuplicateEntryException("The email is already activated");
            } else if (e instanceof TooManyRequestException) {
                throw new TooManyRequestException("Too many unsuccessful attempts. New OTP sent and please verify.");
            } else if (e instanceof EntryNotFoundException) {
                throw new EntryNotFoundException("Unable to find any users associated with the provided email address.");
            } else {
                throw new UnauthorizedException("Invalid username or password. Please double-check your credentials and try again.");
            }

        }
    }

    @Override
    public void forgotPasswordSendVerificationCode(String email) {

        Optional<SystemUser> selectedUserObj = systemUserRepo.findByEmail(email);
        if (selectedUserObj.isEmpty()) {
            throw new EntryNotFoundException("Unable to find any users associated with the provided email address.");
        }
        SystemUser systemUser = selectedUserObj.get();
        Keycloak keycloak = null;
        keycloak = keycloakUtil.getKeycloakInstance();
        UserRepresentation existingUser = keycloak.realm(realm).users().search(email).stream()
                .findFirst().orElse(null);
        if (existingUser == null) {
            throw new EntryNotFoundException("Unable to find any users associated with the provided email address.");
        }

        Otp selectedOtpObj = systemUser.getOtp();
        String code = otpGenerator.generateOtp(4);
        selectedOtpObj.setCode(code);
        selectedOtpObj.setCreatedDate(new Date());
        otpRepo.save(selectedOtpObj);
        try {
            emailService.sendPasswordResetVerificationCode(systemUser.getEmail(),
                    "Verify Your Email Address for Developers Stack Access", selectedOtpObj.getCode());
        } catch (IOException e) {
            throw new UnauthorizedException("Invalid username or password. Please double-check your credentials and try again.");

        }


    }

    @Override
    public boolean verifyReset(String otp, String email) {

        try {
            Optional<SystemUser> selectedUserObj = systemUserRepo.findByEmail(email);
            if (selectedUserObj.isEmpty()) {
                throw new EntryNotFoundException("Unable to find any users associated with the provided email address.");
            }
            SystemUser systemUser = selectedUserObj.get();
            Otp selectedOtpObj = systemUser.getOtp();

            if (selectedOtpObj.getCode().equals(otp)) {

                return true;
            }
        } catch (Exception e) {
            if (e instanceof EntryNotFoundException) {
                throw new EntryNotFoundException("Unable to find any users associated with the provided email address.");
            } else {
                throw new InternalServerException("Something went wrong please try again later..");
            }

        }
        return false;
    }

    @Override
    public boolean passwordReset(RequestUserPasswordResetDto dto) {
        Optional<SystemUser> selectedUserObj = systemUserRepo.findByEmail(dto.getEmail());
        System.out.println(dto.getCode());
        if (selectedUserObj.isPresent()) {
            SystemUser systemUser = selectedUserObj.get();
            Otp selectedOtpObj = systemUser.getOtp();
            Keycloak keycloak = keycloakUtil.getKeycloakInstance();
            List<UserRepresentation> keycloakUsers = keycloak.realm(realm).users().search(systemUser.getEmail());
            if (!keycloakUsers.isEmpty() && selectedOtpObj.getCode().equals(dto.getCode())) {
                UserRepresentation keycloakUser = keycloakUsers.get(0);
                UserResource userResource = keycloak.realm(realm).users().get(keycloakUser.getId());
                CredentialRepresentation newPassword = new CredentialRepresentation();
                newPassword.setType(CredentialRepresentation.PASSWORD);
                newPassword.setValue(dto.getPassword());
                newPassword.setTemporary(false);
                userResource.resetPassword(newPassword);

                return true;
            }

            throw new BadRequestException("Something went wrong with the OTP, Please try again");

        }
        System.out.println("6");
        throw new EntryNotFoundException("Unable to find any users associated with the provided email address.");


    }

    @Override
    public boolean verifyEmail(String otp, String email) {
        try {
            Optional<SystemUser> selectedUserObj = systemUserRepo.findByEmail(email);
            if (selectedUserObj.isEmpty()) {
                throw new EntryNotFoundException("Unable to find any users associated with the provided email address.");
            }
            SystemUser systemUser = selectedUserObj.get();

            Otp selectedOtpObj = systemUser.getOtp();

            if (selectedOtpObj.getIsVerified()) {
                throw new BadRequestException("This OTP has already been used. Please request another one for verification.");
            }

            if (selectedOtpObj.getAttempts() >= 5) {
                String code = otpGenerator.generateOtp(4);

                emailService.sendUserSignupVerificationCode(email,
                        "Verify Your Email Address for Developers Stack Access", code);

                selectedOtpObj.setAttempts(0);
                selectedOtpObj.setCode(code);
                selectedOtpObj.setCreatedDate(new Date());
                otpRepo.save(selectedOtpObj);

                throw new TooManyRequestException("Too many unsuccessful attempts. New OTP sent and please verify.");
            }

            if (selectedOtpObj.getCode().equals(otp)) {

                UserRepresentation keycloakUser = keycloakUtil.getKeycloakInstance().realm(realm)
                        .users()
                        .search(email)
                        .stream()
                        .findFirst()
                        .orElseThrow(() -> new EntryNotFoundException("User not found! Contact support for assistance"));

                keycloakUser.setEmailVerified(true);
                keycloakUser.setEnabled(true);

                keycloakUtil.getKeycloakInstance().realm(realm)
                        .users()
                        .get(keycloakUser.getId())
                        .update(keycloakUser);

                systemUser.setActiveState(true);
                systemUser.setIsEnabled(true);
                systemUser.setIsEmailVerified(true);

                systemUserRepo.save(systemUser);

                selectedOtpObj.setIsVerified(true);
                selectedOtpObj.setAttempts(selectedOtpObj.getAttempts() + 1);

                otpRepo.save(selectedOtpObj);

                return true;

            } else {
                selectedOtpObj.setAttempts(selectedOtpObj.getAttempts() + 1);
                otpRepo.save(selectedOtpObj);
            }


        } catch (IOException exception) {
            throw new InternalServerException("Something went wrong please try again later..");
        }
        return false;
    }

    @Override
    public Object userLogin(RequestUserLoginRequest request) {
        try {
            Optional<SystemUser> selectedUserObj = systemUserRepo.findByEmail(request.getUsername());
            SystemUser systemUser = selectedUserObj.get();
            if (!systemUser.getIsEmailVerified()) {

                Otp selectedOtpObj = systemUser.getOtp();
                if (selectedOtpObj.getAttempts() >= 5) {

                    String code = otpGenerator.generateOtp(4);

                    emailService.sendUserSignupVerificationCode(systemUser.getEmail(),
                            "Verify Your Email Address for Developers Stack Access", code);

                    selectedOtpObj.setAttempts(0);
                    selectedOtpObj.setCode(code);
                    selectedOtpObj.setCreatedDate(new Date());
                    otpRepo.save(selectedOtpObj);

                    throw new TooManyRequestException("Too many unsuccessful attempts. New OTP sent and please verify.");
                }
                emailService.sendUserSignupVerificationCode(systemUser.getEmail(),
                        "Verify Your Email Address for Developers Stack Access", selectedOtpObj.getCode());
                throw new RedirectionException("Your email has not been verified. Please verify your email");

            } else {
                MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
                requestBody.add("client_id", clientId);
                requestBody.add("grant_type", OAuth2Constants.PASSWORD);
                requestBody.add("username", request.getUsername());
                requestBody.add("client_secret", secret);
                requestBody.add("password", request.getPassword());
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
                RestTemplate restTemplate = new RestTemplate();
                ResponseEntity<Object> response = restTemplate.postForEntity(keyCloakApiUrl, requestBody, Object.class);
                return response.getBody();
            }

        } catch (Exception e) {
            System.out.println(e);
            if (e instanceof RedirectionException) {
                throw new RedirectionException("Your email has not been verified. Please verify your email");
            } else if (e instanceof TooManyRequestException) {
                throw new TooManyRequestException("Too many unsuccessful attempts. New OTP sent and please verify.");
            } else {
                throw new UnauthorizedException("Invalid username or password. Please double-check your credentials and try again.");
            }

        }

    }

    @Override
    public boolean verifyAdmin(String email) {
        UserRepresentation keycloakUser = keycloakUtil.getKeycloakInstance().realm(realm)
                .users()
                .search(email)
                .stream()
                .findFirst()
                .orElseThrow(() -> new EntryNotFoundException("User not found! Contact support for assistance"));

        List<RoleRepresentation> roleRepresentations = keycloakUtil.getKeycloakInstance().realm(realm).users()
                .get(keycloakUser.getId()).roles().realmLevel().listAll();

        for (RequestRoleDto requestRole : mapRoles(roleRepresentations)
        ) {
            if (requestRole.getName().equals("admin")) {
                return true;
            }
        }
        return false;
    }


    @Override
    public ResponseUserDetailsDto getUserDetails(String email) {
        Optional<SystemUser> byEmail = systemUserRepo.findByEmail(email);
        if (byEmail.isEmpty()) {
            throw new EntryNotFoundException("User was not found");
        }

        SystemUserAvatar systemUserAvatar = byEmail.get().getSystemUserAvatar();
        System.out.println(fileDataExtractor.byteArrayToString(systemUserAvatar.getResourceUrl()));
        return ResponseUserDetailsDto.builder()
                .email(byEmail.get().getEmail())
                .firstName(byEmail.get().getFirstName())
                .lastName(byEmail.get().getLastName())
                .resourceUrl(systemUserAvatar != null ? fileDataExtractor.byteArrayToString(systemUserAvatar.getResourceUrl()) : null)
                .build();
    }



    private ResponseUserDto mapToResponseUserDto(UserRepresentation user) {
        return ResponseUserDto.builder()
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail())
                .username(user.getUsername())
                .build();

    }

    private boolean checkRoleExists(String role, List<RoleRepresentation> list) {
        for (RequestRoleDto requestRole : mapRoles(list)
        ) {
            if (requestRole.getName().equals(role)) {
                return true;
            }
        }
        return false;
    }

    public List<RequestRoleDto> mapRoles(List<RoleRepresentation> representations) {
        List<RequestRoleDto> roles = new ArrayList<>();
        if (CollectionUtil.isNotEmpty(representations)) {
            representations.forEach(roleRep -> roles.add(mapRole(roleRep)));
        }
        return roles;
    }

    public RequestRoleDto mapRole(RoleRepresentation roleRep) {
        RequestRoleDto role = new RequestRoleDto();
        role.setId(roleRep.getId());
        role.setName(roleRep.getName());
        return role;
    }

    private UserRepresentation mapUserRep(RequestUserDto user) {
        UserRepresentation userRep = new UserRepresentation();
        userRep.setUsername(user.getEmail());
        userRep.setFirstName(user.getFirstName());
        userRep.setLastName(user.getLastName());
        userRep.setEmail(user.getEmail());
        userRep.setEnabled(false);
        userRep.setEmailVerified(false);
        List<CredentialRepresentation> creds = new ArrayList<>();
        CredentialRepresentation cred = new CredentialRepresentation();
        cred.setTemporary(false);
        cred.setValue(user.getPassword());
        creds.add(cred);
        userRep.setCredentials(creds);
        return userRep;
    }

}
