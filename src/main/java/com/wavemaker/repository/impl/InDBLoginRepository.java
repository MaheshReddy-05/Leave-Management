package com.wavemaker.repository.impl;

import com.wavemaker.repository.LoginRepository;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.wavemaker.util.DBConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class InDBLoginRepository implements LoginRepository {
    public static Connection connection = null;
    private static final String queryIsEmployee = "SELECT * FROM CREDENTIALS WHERE USER_NAME= ? AND PASSWORD=?";
    private static final Logger logger = LoggerFactory.getLogger(InDBLeaveRepository.class);

    public InDBLoginRepository() throws SQLException {
        connection = DBConnector.connect();
    }

    @Override
    public int isEmployee(String username, String password) {
        try {
            PreparedStatement statement = connection.prepareStatement(queryIsEmployee);
            statement.setString(1, username);
            statement.setString(2, password);
            ResultSet resultSet = statement.executeQuery();
            if (resultSet.next()) {
                return resultSet.getInt("EMPLOYEE_ID");
            }
        } catch (Exception e) {
            logger.error("Error while checking login credentials");
        }
        return -1;
    }
}
