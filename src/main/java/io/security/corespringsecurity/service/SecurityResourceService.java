package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.repository.ResourcesRepository;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;


public class SecurityResourceService {

    private ResourcesRepository resourcesRepository;

    public SecurityResourceService(ResourcesRepository resourcesRepository) {
        this.resourcesRepository = resourcesRepository;
    }

    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();
        List<Resources> resourceList = resourcesRepository.findAllResources();
        resourceList.forEach(re -> {
            List<ConfigAttribute> configAttributes = new ArrayList<>();
            re.getRoleSet().forEach(role -> {
                configAttributes.add(new SecurityConfig(role.getRoleName()));
                result.put(new AntPathRequestMatcher(re.getResourceName()), configAttributes);
            });
        });
        return result;
    }
}
