package ru.kata.spring.boot_security;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import ru.kata.spring.boot_security.model.Role;
import ru.kata.spring.boot_security.model.User;
import ru.kata.spring.boot_security.repository.RoleRepository;
import ru.kata.spring.boot_security.repository.UserRepository;

import java.util.HashSet;
import java.util.List;

/**
 * Класс для начальной загрузки данных в базу данных при запуске приложения.
 */
@Component
public class DatabaseLoader implements CommandLineRunner {

    private final UserRepository userRepository;

    private final RoleRepository roleRepository;

    public DatabaseLoader(UserRepository userRepository, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }

    @Override
    public void run(String... strings) {
        Role adminRole = new Role("ROLE_ADMIN");
        Role userRole = new Role("ROLE_USER");

        this.roleRepository.save(adminRole);
        this.roleRepository.save(userRole);

        User admin = new User("admin", "admin", "admin@mail.ru", 30, "admin");
        admin.setRoles(new HashSet<>(List.of(adminRole, userRole)));

        User user = new User("user", "User", "user@mail.ru", 30, "user");
        user.setRoles(new HashSet<>(List.of(userRole)));

        this.userRepository.save(admin);
        this.userRepository.save(user);
    }
}