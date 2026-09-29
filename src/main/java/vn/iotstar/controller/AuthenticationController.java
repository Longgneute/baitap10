package vn.iotstar.controller;

import vn.iotstar.entity.User;
import vn.iotstar.model.LoginResponse;
import vn.iotstar.model.LoginUserModel;
import vn.iotstar.model.RegisterUserModel;
import vn.iotstar.service.AuthenticationService;
import vn.iotstar.service.JwtService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {
	private final JwtService jwtService;
	private final AuthenticationService authenticationService;

	public AuthenticationController(JwtService jwtService, AuthenticationService authenticationService) {
		this.jwtService = jwtService;
		this.authenticationService = authenticationService;
	}

	@PostMapping("/signup")
	public ResponseEntity<User> signup(@RequestBody RegisterUserModel input) {
		return ResponseEntity.ok(authenticationService.signup(input));
	}

	@PostMapping("/login")
	public ResponseEntity<LoginResponse> login(@RequestBody LoginUserModel input) {
		User authenticatedUser = authenticationService.authenticate(input.getEmail(), input.getPassword());
		String jwtToken = jwtService.generateToken(authenticatedUser);
		return ResponseEntity.ok(new LoginResponse(jwtToken, 3600000));
	}
}
