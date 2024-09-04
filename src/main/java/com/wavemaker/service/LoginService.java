package com.wavemaker.service;

import java.sql.SQLException;

public interface LoginService {
    public int isEmployee(String username, String password) throws SQLException;
}
