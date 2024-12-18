package com.example.authservice.service;


import com.example.authservice.exception.EmailAlreadyExistsException;
import com.example.authservice.exception.UsernameAlreadyExistException;
import com.example.authservice.jwt.CodeGenerator;
import com.example.authservice.jwt.JwtService;
import com.example.authservice.model.enities.CustomUserDetail;
import com.example.authservice.model.enities.User;
import com.example.authservice.model.payload.ChangePasswordRequest;
import com.example.authservice.model.payload.JwtResponse;
import com.example.authservice.model.payload.LoginRequest;
import com.example.authservice.model.payload.RegisterRequest;
import com.example.authservice.repository.UserRepository;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;

@Service
public class AuthService {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private UserService userService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private EmailService emailService;
    @Autowired
    private UserRepository userRepository;


    public JwtResponse login(LoginRequest loginRequest){
        if(loginRequest.getPassword().length()<6){
            throw new RuntimeException("Password must be more than 6");
        }
        if (!isValidEmail(loginRequest.getEmail())) {
            throw new EmailAlreadyExistsException("Invalid email format");
        }
        if(loginRequest.getPassword().isEmpty()||loginRequest.getEmail().isEmpty()){
            throw new RuntimeException("Values that cannot be null");
        }
        authenticateByEmail(loginRequest.getEmail(), loginRequest.getPassword());
        UserDetails userDetails=userService.loadUserByEmail(loginRequest.getEmail());
        String token = jwtService.generateToken((CustomUserDetail) userDetails);
        return  new JwtResponse(token);
    }

    public void register(RegisterRequest request) throws MessagingException {
        if (userService.existsByUsername(request.getUsername())) {
            throw new UsernameAlreadyExistException("Username already exist: "+request.getUsername());
        }
        if (userService.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException("Email already exist: "+request.getEmail());
        }
        if(request.getPassword().length()<6){
            throw new RuntimeException("Password must be more than 6");
        }
        if (!isValidEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException("Invalid email format");
        }
        if(request.getPassword().isEmpty()||request.getEmail().isEmpty()||request.getPhoneNumber().isEmpty()||request.getUsername().isEmpty()){
            throw new RuntimeException("Values that cannot be null");
        }
        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole("USER");
        user.setPhoneNumber(request.getPhoneNumber());
        user.setCreatedAt(LocalDateTime.now());
        user.setUpdatedAt(LocalDateTime.now());

        String verificationCode = CodeGenerator.generateVerificationCode(6);
        user.setVerificationCode(verificationCode);
        String body = "<d>Your verification code is: </d> <h1  style=\\\"letter-spacing: 5px;\\> <strong>" + verificationCode + "</strong></h1>";

        emailService.sendEmail(user.getEmail(), "Verification Code", body);
        userService.saveUser(user);
    }

    public void verifyAccountRegister(String code) {
        User user = userService.findByVerificationCode(code);

        if (user == null) {
            throw new UsernameNotFoundException("Invalid verification code");
        }
        user.setVerified(true);
        user.setVerificationCode(null);
        userService.saveUser(user);
    }

    public void forgotPassword(String email) throws MessagingException {
        User user = userService.findByEmail(email);
        if (user == null) {
           throw new UsernameNotFoundException("Not found Email: "+email);
        }
        // Tạo mã xác thực quên mật khẩu
        String resetCode = CodeGenerator.generateVerificationCode(6);
        user.setResetPasswordCode(resetCode);
        userService.saveUser(user);

        // Gửi email mã xác thực
        String body = "<d>Your password Reset Code is: </d> <h1  style=\\\"letter-spacing: 5px;\\> <strong>" + resetCode + "</strong></h1>";
        emailService.sendEmail(user.getEmail(), "Password Reset Code", body);
    }

    public void resetPassword( String resetCode, String newPassword) {
        User user = userService.findByResetPasswordCode(resetCode);
        if (user == null) {
            throw new UsernameNotFoundException("Invalid or expired reset code");
        }
        // Đặt lại mật khẩu mới
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setResetPasswordCode(null);
        userService.saveUser(user);
    }

    public void changePassword(ChangePasswordRequest request, HttpServletRequest httpRequest) {
        String token = httpRequest.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        }

        String email = jwtService.getEmailFromToken(token);

        User user = userService.findByEmail(email);
        if (user == null) {
            throw new EmailAlreadyExistsException("Not found inValid Email");
        }

        // Kiểm tra mật khẩu cũ
        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            throw new RuntimeException("Incorrect current password");
        }

        // Cập nhật mật khẩu mới
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userService.saveUser(user);
    }
    private void authenticateByEmail(String email, String password) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
        } catch (DisabledException e) {
            throw new RuntimeException("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new RuntimeException("INVALID_CREDENTIALS", e);
        }
    }
    private boolean isValidEmail(String email) {
        String emailRegex = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@[a-zA-Z0-9-]+(?:\\.[a-zA-Z0-9-]+)*$";
        Pattern pattern = Pattern.compile(emailRegex);
        return pattern.matcher(email).matches();
    }
}
