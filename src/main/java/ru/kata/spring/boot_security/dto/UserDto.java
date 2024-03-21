package ru.kata.spring.boot_security.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class UserDto {

    private Long id;
    private String firstname;
    private String lastname;
    private Integer age;
    private String email;
    private String password;
    private Set<RoleDto> roles;

}
