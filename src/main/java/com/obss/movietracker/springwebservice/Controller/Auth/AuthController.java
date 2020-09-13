package com.obss.movietracker.springwebservice.Controller.Auth;

import java.util.HashMap;
import java.util.Map;

import com.obss.movietracker.springwebservice.Exceptions.PasswordWrongException;
import com.obss.movietracker.springwebservice.Messages.InfoMessage;
import com.obss.movietracker.springwebservice.Model.Form.PasswordChangeForm;
import com.obss.movietracker.springwebservice.Model.Jwt.JwtAuthenticationToken;
import com.obss.movietracker.springwebservice.Model.Jwt.JwtUser;
import com.obss.movietracker.springwebservice.Model.Jwt.JwtUserDetails;
import com.obss.movietracker.springwebservice.Model.UserEntity;
import com.obss.movietracker.springwebservice.Service.Impl.UserServiceImpl;
import com.obss.movietracker.springwebservice.Service.Impl.Util.PasswordServiceImpl;
import com.obss.movietracker.springwebservice.Service.Jwt.JwtTokenUtilService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "http://localhost:3000", allowedHeaders = "*")
@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private PasswordServiceImpl passwordService;

    @Autowired
    private UserServiceImpl userService;

    @Autowired
    private JwtTokenUtilService jwtTokenUtilService;

    // LOGIN USER ✔
    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody JwtUser jwtUser) {

        if (jwtUser.getUsername() == null || jwtUser.getPassword() == null) {
            return new ResponseEntity<>(new InfoMessage("Please fill the form"), HttpStatus.BAD_REQUEST);
        }

        JwtUserDetails jwtUserDetails;

        try {
            jwtUserDetails = (JwtUserDetails) userService.loadUserByUsernameAndPassword(jwtUser.getUsername(),
                    jwtUser.getPassword());

        } catch (UsernameNotFoundException | PasswordWrongException ex) {
            System.out.println(ex.getMessage());
            return new ResponseEntity<>(new InfoMessage("Username or password wrong"), HttpStatus.BAD_REQUEST);
        }

        String token = userService.generateJWTToken(jwtUser.getUsername(), jwtUser.getPassword());

        Map<String, Object> newObject = new HashMap<>();
        newObject.put("user",
                new JwtAuthenticationToken(token, jwtUserDetails.getAuthorities(), jwtUserDetails.getUsername()));
        newObject.put("fullName", jwtUserDetails.getFullName());

        return ResponseEntity.ok(newObject);
    }

    // CREATE USER ✔
    @PostMapping("/register")
    public ResponseEntity<Object> createUser(@RequestBody JwtUser jwtUser) {
        String username = jwtUser.getUsername().trim();
        String password = jwtUser.getPassword().trim();

        if (username == null || password == null) {
            return new ResponseEntity<>(new InfoMessage("Please enter your username and password"),
                    HttpStatus.BAD_REQUEST);
        }

        if (username.length() < 5 || password.length() < 5) {
            return new ResponseEntity<>(
                    new InfoMessage("You must enter at least 5 characters to both your username and password"),
                    HttpStatus.BAD_REQUEST);
        }

        UserEntity user = userService.saveUser(jwtUser);

        if (user == null) {
            return new ResponseEntity<>(new InfoMessage("User Creation failed"), HttpStatus.EXPECTATION_FAILED);
        }

        String token;
        Map<String, Object> registerUserData = new HashMap<>();
        try {
            token = userService.generateJWTToken(username, password);

            if (token != null) {
                registerUserData.put("authenticated", true);
                registerUserData.put("token", token);
                registerUserData.put("user", user);

                return new ResponseEntity<>(registerUserData, HttpStatus.CREATED);
            } else {
                return new ResponseEntity<>(new InfoMessage("Token creation failed"), HttpStatus.BAD_REQUEST);
            }

        } catch (Exception e) {
            return new ResponseEntity<>(new InfoMessage(e.getMessage()), HttpStatus.EXPECTATION_FAILED);
        }
    }

    // UPDATING PASSWORD ✔
    @PutMapping("/password")
    public ResponseEntity<Object> changePassword(@RequestBody PasswordChangeForm passwordChangeForm) {
        String username = passwordChangeForm.getUsername();
        String password = passwordChangeForm.getPassword();

        if (username == null || password == null) {
            return new ResponseEntity<>(new InfoMessage("Please enter your username & password"),
                    HttpStatus.BAD_REQUEST);
        }

        UserEntity user = userService.findUserByUsernameAndPassword(username, password);

        if (user == null) {
            return new ResponseEntity<>(new InfoMessage("User is not found"), HttpStatus.BAD_REQUEST);
        }

        String newPassword = passwordChangeForm.getNewPassword();
        String hashedNewPassword = passwordService.hashPassword(newPassword);

        user.setPassword(hashedNewPassword);

        UserEntity updatedUser = userService.saveUser(user);

        return new ResponseEntity<>(updatedUser, HttpStatus.OK);
    }
}
