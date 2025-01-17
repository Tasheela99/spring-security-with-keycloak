package com.shaliya.securitywithkeycloak.api;

import com.shaliya.securitywithkeycloak.dto.request.RequestUserRoleDto;
import com.shaliya.securitywithkeycloak.service.UserRoleService;
import com.shaliya.securitywithkeycloak.util.StandardResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/user-service/api/v1/user-roles")
@RequiredArgsConstructor
public class SystemUserRoleController {
    private final UserRoleService service;
    @PostMapping("/admin/create")
    @PreAuthorize("hasRole('admin')")
    public ResponseEntity<StandardResponse> createUser(@RequestBody RequestUserRoleDto dto) throws IOException {
        service.createUser(dto);
        return new ResponseEntity<>(
                new StandardResponse(201,
                        "User Role was add",null ),
                HttpStatus.CREATED
        );
    }
    @GetMapping("/admin/list")
    @PreAuthorize("hasRole('admin')")
    public ResponseEntity<StandardResponse> findAllUserRole() throws IOException {

        return new ResponseEntity<>(
                new StandardResponse(200,
                        "User Role list",service.findAllUserRole() ),
                HttpStatus.CREATED
        );
    }
}
