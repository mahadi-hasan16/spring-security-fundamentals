package com.springSecurity.fundamentals.service;

import com.springSecurity.fundamentals.entity.UserEntity;
import com.springSecurity.fundamentals.repository.UserRepository;
import com.springSecurity.fundamentals.utility.classes.UserPrincipal;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AppUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;
    public AppUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @NonNull
    public UserDetails loadUserByUsername(@NonNull String username) throws UsernameNotFoundException {
        UserEntity user =  userRepository.findByUsername(username);

        if (user == null) {
            throw new UsernameNotFoundException("User: "+username+"not found");
        }

        return new UserPrincipal(user);
    }
}
