package com.dante.restapi.authentication.service;

import com.dako.forohub.user.domain.RolesEnum;
import com.dako.forohub.user.domain.User;
import com.dako.forohub.user.repositories.UserRepository;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class AuthorizationService {

    private final UserRepository userRepository;

    public AuthorizationService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public String getAuthenticatedUsername() {
        return ((UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUsername();
    }

    public User findUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public boolean isAuthorizedToUpdate(User author, Long authorId) {
        boolean isAdmin = author.getRoles().stream()
                .anyMatch(role -> role.getName() == RolesEnum.ADMIN);
        return author.getId().equals(authorId) || isAdmin;
    }
}
