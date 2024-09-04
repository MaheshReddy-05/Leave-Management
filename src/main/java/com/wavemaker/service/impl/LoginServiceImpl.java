package com.wavemaker.service.impl;

import com.wavemaker.factory.SingletonLoginRepository;
import com.wavemaker.repository.LoginRepository;
import com.wavemaker.service.LoginService;

import java.sql.SQLException;

public class LoginServiceImpl implements LoginService {
    private static LoginRepository loginRepository;

    public LoginServiceImpl() throws SQLException {
        loginRepository = SingletonLoginRepository.getInDBLoginRepositoryInstance();
    }

    @Override
    public int isEmployee(String username, String password) throws SQLException {
        return loginRepository.isEmployee(username, password);
    }
}
