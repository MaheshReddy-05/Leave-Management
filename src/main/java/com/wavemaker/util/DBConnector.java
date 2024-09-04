package com.wavemaker.util;

import com.mysql.cj.jdbc.Driver;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;


public class DBConnector {
    private final static String DB_URL = "jdbc:mysql://127.0.0.1:3306/leavemanagement";
    private final static String DB_USERNAME = "root";
    private final static String DB_PASSWORD = "Reddy7168";

    private static volatile Connection connection;

    public static Connection connect() throws SQLException {
        try {
            if (connection == null || !connection.isClosed()) {
                synchronized (DBConnector.class) {
                    if (connection == null || !connection.isClosed()) {
                        DriverManager.registerDriver(new Driver());
                        connection = DriverManager.getConnection(DB_URL, DB_USERNAME, DB_PASSWORD);

                    }
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return connection;
    }
}
