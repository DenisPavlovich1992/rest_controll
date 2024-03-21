package ru.kata.spring.boot_security.service;

import ru.kata.spring.boot_security.dto.UserDto;
import ru.kata.spring.boot_security.model.User;

import java.util.List;
import java.util.Map;

public interface UserService {


    void delete(Long id);

    Map<User, List<String>> getAllUsersWithRoles();

    void addUserWithRoles(UserDto userDto);

    void updateUserWithRoles(UserDto userDto);

    User findByEmail(String email);

}
