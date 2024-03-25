package ru.kata.spring.boot_security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import ru.kata.spring.boot_security.model.Role;
import ru.kata.spring.boot_security.model.User;
import ru.kata.spring.boot_security.repository.RoleRepository;
import ru.kata.spring.boot_security.repository.UserRepository;

import javax.annotation.PostConstruct;
import java.util.HashSet;
import java.util.List;

/**
 * Класс для начальной загрузки данных в базу данных при запуске приложения.
 */
@Component
public class DatabaseLoader {

    @Autowired
    private PasswordEncoder passwordEncoder;

    private final UserRepository userRepository;

    private final RoleRepository roleRepository;

    public DatabaseLoader(UserRepository userRepository, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @PostConstruct
    private void postConstruct() {
        Role admRole = new Role("ROLE_ADMIN");
        Role userRole = new Role("ROLE_USER");
        this.roleRepository.save(admRole);
        this.roleRepository.save(userRole);
        String encodedPassword1 = passwordEncoder.encode("admin");
        String encodedPassword2 = passwordEncoder.encode("user");
        User admin = new User("admin", "admin", "admin@mail.ru", 30, encodedPassword1);
        admin.setRoles(new HashSet<>(List.of(admRole, userRole)));

        User user = new User("user", "User", "user@mail.ru", 30, encodedPassword2);
        user.setRoles(new HashSet<>(List.of(userRole)));
        this.userRepository.save(admin);
        this.userRepository.save(user);
    }

}
