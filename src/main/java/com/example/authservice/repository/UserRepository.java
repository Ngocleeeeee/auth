package com.example.authservice.repository;

import com.example.authservice.model.enities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
    User findByEmail(String email);

    User findByUsername(String username);
    User findByVerificationCode(String verificationCode);
    User findByResetPasswordCode(String resetPasswordCode);

    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
    List<User> findAll();

    List<User> findAllByIsDeleted(boolean isDeleted);
}
