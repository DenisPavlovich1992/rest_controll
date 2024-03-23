package ru.kata.spring.boot_security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.kata.spring.boot_security.repository.RoleRepository;
import ru.kata.spring.boot_security.repository.UserRepository;
import ru.kata.spring.boot_security.dto.RoleDto;
import ru.kata.spring.boot_security.dto.UserDto;
import ru.kata.spring.boot_security.model.User;
import ru.kata.spring.boot_security.model.Role;
import ru.kata.spring.boot_security.util.UserMapper;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class UserServiceImp implements UserService, UserDetailsService {
    @Autowired
    private PasswordEncoder passwordEncoder;

    private final UserRepository userRepository;

    private final RoleRepository roleRepository;

    private final UserMapper userMapper;


    public UserServiceImp(UserRepository userRepository,
                          RoleRepository roleRepository,
                          UserMapper userMapper) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.userMapper = userMapper;
    }

    @Transactional
    @Override
    public void delete(Long id) {
        userRepository.deleteById(id);
    }

    @Transactional(readOnly = true)
    @Override
    public User findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    /**
     * Получить всех пользователей и их роли, отсортированные по идентификатору пользователя.
     * Роли пользователя также сортируются и из них удаляется префикс "ROLE_".
     *
     * @return Map, где ключ - пользователь, а значение - список его ролей.
     */
    @Transactional(readOnly = true)
    @Override
    public Map<User, List<String>> getAllUsersWithRoles() {
        return userRepository
                .findAll(Sort.by("id"))
                .stream()
                .sorted(Comparator.comparing(User::getId))
                .collect(Collectors.toMap(
                        Function.identity(),
                        user -> user.getRoles().stream()
                                .map(Role::getName)
                                .map(roleName -> roleName.replace("ROLE_", ""))
                                .sorted()
                                .toList(),
                        (oldValue, newValue) -> oldValue,
                        LinkedHashMap::new
                ));
    }

    /**
     * Загружает детали пользователя по его email.
     *
     * @param email Email пользователя.
     * @return Объект UserDetails с информацией о пользователе.
     * @throws UsernameNotFoundException если пользователь с указанным email не найден.
     */
    @Transactional(readOnly = true)
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException(email);
        }
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());

        return new org.springframework.security.core.userdetails.
                User(user.getUsername(), user.getPassword(), authorities);
    }

    /**
     * Добавляет пользователя и его роли в базу данных.
     * Преобразует UserDto в модель User, использует метод setRolesToUser для установки ролей,
     * указанных в UserDto, и сохраняет пользователя в базе данных.
     *
     * @param userDto DTO пользователя с информацией о пользователе и его ролях.
     */
    @Transactional
    @Override
    public void addUserWithRoles(UserDto userDto) {
        User user = userMapper.toModel(userDto);
        user.setPassword(passwordEncoder.encode(userDto.getPassword()));
        setRolesToUser(user, userDto.getRoles());
        userRepository.save(user);
    }

    /**
     * Обновляет пользователя и его роли в базе данных.
     * Находит существующего пользователя по id из UserDto, обновляет его поля,
     * использует метод setRolesToUser для установки ролей, указанных в UserDto,
     * и сохраняет обновленного пользователя в базе данных.
     *
     * @param userDto DTO пользователя с информацией о пользователе и его ролях.
     */
    @Transactional
    @Override
    public void updateUserWithRoles(UserDto userDto) {
        User existingUser = userRepository.findById(userDto.getId()).orElse(null);

        if (existingUser != null) {
            existingUser.setFirstname(userDto.getFirstname());
            existingUser.setLastname(userDto.getLastname());
            existingUser.setAge(userDto.getAge());
            existingUser.setEmail(userDto.getEmail());
            existingUser.setPassword(passwordEncoder.encode(userDto.getPassword()));
            setRolesToUser(existingUser, userDto.getRoles());

            userRepository.save(existingUser);
        } else {
            throw new IllegalArgumentException("userRepository or userDto cannot be null");
        }
    }

    /**
     * Устанавливает роли для пользователя.
     * Метод преобразует набор RoleDto в набор Role, находя каждую роль в базе данных по ее имени,
     * затем устанавливает этот набор ролей для указанного пользователя.
     *
     * @param user пользователь, которому нужно установить роли.
     * @param roleDtoSet набор DTO ролей, которые нужно установить пользователю.
     */
    private void setRolesToUser(User user, Set<RoleDto> roleDtoSet) {
        Set<Role> roles = roleDtoSet.stream()
                .map(roleDto -> roleRepository.findByName("ROLE_" + roleDto.getName()))
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        user.setRoles(roles);
    }
}
