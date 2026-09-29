package vn.iotstar.controller;

import vn.iotstar.entity.User;
import vn.iotstar.service.UserService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {
	private final UserService userService;

	public UserController(UserService userService) {
		this.userService = userService;
	}

	@GetMapping("/me")
	public User authenticatedUser(@AuthenticationPrincipal User user) {
		return user;
	}

	@GetMapping
	public List<User> allUsers() {
		return userService.allUsers();
	}
}
