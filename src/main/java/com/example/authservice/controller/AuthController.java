package com.example.authservice.controller;


import com.example.authservice.exception.EmailAlreadyExistsException;
import com.example.authservice.jwt.JwtService;
import com.example.authservice.model.dto.BaseResponse;
import com.example.authservice.model.enities.CustomUserDetail;
import com.example.authservice.model.enities.User;
import com.example.authservice.model.payload.ChangePasswordRequest;
import com.example.authservice.model.payload.LoginRequest;
import com.example.authservice.model.payload.RegisterRequest;
import com.example.authservice.service.AuthService;
import com.example.authservice.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@CrossOrigin
@Tag(name = "Authentication", description = "APIs for user authentication and registration")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final AuthService authService;
    private final PasswordEncoder passwordEncoder;
    private  final UserService userService;


    @PostMapping("/login")
    @Operation(summary = "User login", description = "Authenticate user and return JWT token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Đăng nhập thành công, trả về JWT token."),
            @ApiResponse(responseCode = "403", description = "Xác thực không thành công.",
                    content = @Content(examples = @ExampleObject(value = "{ \"error\": \"Unauthorized\" }"))),
            @ApiResponse(responseCode = "500", description = "Lỗi máy chủ.",
                    content = @Content(examples = @ExampleObject(value = "{ \"error\": \"Internal Server Error\" }")))
    })
    public ResponseEntity<?> login(@RequestBody LoginRequest jwtRequest) {

            return ResponseEntity.ok(authService.login(jwtRequest));
    }

    @PostMapping("/register")
    @Operation(summary = "User registration", description = "Register a new user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Người dùng được đăng ký thành công."),
            @ApiResponse(responseCode = "400", description = "Tên người dùng hoặc email đã tồn tại.",
                    content = @Content(examples = @ExampleObject(value = "{ \"error\": \"Bad Request\" }"))),
            @ApiResponse(responseCode = "500", description = "Lỗi máy chủ.",
                    content = @Content(examples = @ExampleObject(value = "{ \"error\": \"Internal Server Error\" }")))
    })
    public ResponseEntity<?> register(@RequestBody RegisterRequest request){
        try {
            authService.register(request);
        }
        catch (MessagingException ex) {
            return new ResponseEntity<>("An unexpected error occurred", HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(BaseResponse.builder().message("User registered successfully").build());
    }


    @PostMapping("/verify-register")
    public ResponseEntity<BaseResponse<?>> verifyAccountRegister(@RequestParam("code") String code) {
        authService.verifyAccountRegister(code);
        return ResponseEntity.ok(BaseResponse.builder().message("Account verified successfully").build());

    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Forgot password", description = "Send a password reset code to the user's email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Mã xác thực quên mật khẩu đã được gửi."),
            @ApiResponse(responseCode = "404", description = "Email không tồn tại.",
                    content = @Content(examples = @ExampleObject(value = "{ \"error\": \"Email not found\" }")))
    })
    public ResponseEntity<String> forgotPassword(@RequestParam("email") String email) throws MessagingException {
        try{
            authService.forgotPassword(email);
        }catch (UsernameNotFoundException ex){
            return new ResponseEntity<>(ex.getMessage(),HttpStatus.NOT_FOUND);
        }
        return ResponseEntity.ok("Password reset code sent successfully");
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Reset password", description = "Verify the password reset code and set a new password")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Mật khẩu đã được đặt lại thành công."),
            @ApiResponse(responseCode = "400", description = "Mã xác thực không hợp lệ hoặc đã hết hạn.",
                    content = @Content(examples = @ExampleObject(value = "{ \"error\": \"Invalid or expired reset code\" }")))
    })
    public ResponseEntity<String> resetPassword(@RequestParam("resetCode") String resetCode, @RequestParam("newPassword") String newPassword) {
       try{
           authService.resetPassword(resetCode,newPassword);
       }catch (UsernameNotFoundException ex){
           return new ResponseEntity<>(ex.getMessage(),HttpStatus.NOT_FOUND);
       }
        return ResponseEntity.ok("Password reset successfully");
    }

    @PostMapping("/change-password")
    @Operation(summary = "Change user password", description = "Change the password for a user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password changed successfully."),
            @ApiResponse(responseCode = "400", description = "Invalid input or incorrect current password.",
                    content = @Content(examples = @ExampleObject(value = "{ \"error\": \"Bad Request\" }"))),
            @ApiResponse(responseCode = "500", description = "Internal server error.",
                    content = @Content(examples = @ExampleObject(value = "{ \"error\": \"Internal Server Error\" }")))
    })
    public ResponseEntity<String> changePassword(@RequestBody ChangePasswordRequest request, HttpServletRequest httpRequest) {
        try {
            authService.changePassword(request,httpRequest);
        }catch (EmailAlreadyExistsException ex){
            return new ResponseEntity<>(ex.getMessage(),HttpStatus.NOT_FOUND);
        }catch (RuntimeException ex){
            return new ResponseEntity<>(ex.getMessage(),HttpStatus.BAD_REQUEST);
        }
        return ResponseEntity.ok("Password changed successfully");
    }

    @GetMapping("/check_auth")
    public ResponseEntity<User> checkAuth(HttpServletRequest httpServletRequest){
        String authHeader = httpServletRequest.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            String email = jwtService.getEmailFromToken(token);
            if (email != null) {
                UserDetails user = userService.loadUserByEmail(email);
                if (jwtService.validateToken(token, (CustomUserDetail) user)) {
                    return ResponseEntity.ok(((CustomUserDetail) user).getUser());
                }else{
                    return ResponseEntity.ok(null);
                }
            }
        }
        return  ResponseEntity.ok(null);
    }
}
