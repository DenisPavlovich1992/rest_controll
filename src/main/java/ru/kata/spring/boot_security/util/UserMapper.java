package ru.kata.spring.boot_security.util;

import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Component;
import ru.kata.spring.boot_security.dto.UserDto;
import ru.kata.spring.boot_security.model.User;

/**
 * Класс UserMapper используется для преобразования объектов
 * типа UserDto в объекты типа User.
 * Для преобразования используется библиотека ModelMapper,
 * которая автоматически сопоставляет поля с одинаковыми именами.
 */
@Component
public class UserMapper {

    private final ModelMapper modelMapper;

    public UserMapper(ModelMapper modelMapper) {
        this.modelMapper = modelMapper;
    }

    public User toModel(UserDto dto) {
        return modelMapper.map(dto, User.class);
    }

}