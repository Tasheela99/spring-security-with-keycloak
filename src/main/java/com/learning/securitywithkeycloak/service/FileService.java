package com.learning.securitywithkeycloak.service;

import com.learning.securitywithkeycloak.util.CommonFileSavedBinaryDataDTO;
import com.shaliya.securitywithkeycloak.util.*;
import org.springframework.web.multipart.MultipartFile;

public interface FileService {
    public CommonFileSavedBinaryDataDTO createResource(MultipartFile file, String directory, String bucket);
    public void deleteResource(String bucket,String directory, String fileName);
    public byte[] downloadFile(String bucket, String fileName);
}
