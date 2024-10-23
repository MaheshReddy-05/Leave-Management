package com.wavemaker.repository.impl;

import com.wavemaker.model.Leave;
import com.wavemaker.model.RequestLeaves;
import com.wavemaker.repository.LeaveRepository;
import com.wavemaker.util.DBConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class InDBLeaveRepository implements LeaveRepository {
    public static Connection connection;
    private static final Logger logger = LoggerFactory.getLogger(InDBLeaveRepository.class);
    private final static String queryApplyLeave = "INSERT INTO LEAVES (EMPLOYEE_ID, MANAGER_ID, LEAVE_TYPE, REASON," +
            " CREATED_AT, FROM_DATE, TO_DATE, LEAVE_COUNT, STATUS) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    private final static String queryUpdateLeave = "UPDATE LEAVES SET STATUS = ? WHERE LEAVE_ID = ?";
    private final static String queryGetAllLeavesByEmployeeId = "SELECT * FROM LEAVES WHERE EMPLOYEE_ID = ? AND" +
            " (STATUS = ? OR ? = 'all')";
    private final static String queryGetLeavesAsManager =
            "SELECT e.EMPLOYEE_ID, e.EMPLOYEE_NAME, l.LEAVE_ID, l.REASON, l.LEAVE_TYPE, " +
                    "l.CREATED_AT, l.FROM_DATE, l.TO_DATE, l.LEAVE_COUNT, l.STATUS " +
                    "FROM EMPLOYEE e " +
                    "JOIN LEAVES l ON e.EMPLOYEE_ID = l.EMPLOYEE_ID " +
                    "WHERE l.MANAGER_ID = ? " +
                    "AND (? = 'All' OR l.STATUS = ?);";
    private final static String queryGetManagerId = "SELECT MANAGER_ID FROM EMPLOYEE WHERE EMPLOYEE_ID =?";

    public InDBLeaveRepository() throws SQLException {
        connection = DBConnector.connect();
    }

    @Override
    public Leave applyLeave(Leave leave) {
        try {
            int managerId = getManagerId(leave.getEmployeeId());
            PreparedStatement preparedStatement = connection.prepareStatement(queryApplyLeave, Statement.RETURN_GENERATED_KEYS);
            preparedStatement.setInt(1, leave.getEmployeeId());
            preparedStatement.setInt(2, managerId);
            preparedStatement.setString(3, leave.getLeaveType());
            preparedStatement.setString(4, leave.getReason());
            preparedStatement.setDate(5, java.sql.Date.valueOf(leave.getCreatedAt()));
            preparedStatement.setDate(6, java.sql.Date.valueOf(leave.getFromDate()));
            preparedStatement.setDate(7, java.sql.Date.valueOf(leave.getToDate()));
            preparedStatement.setInt(8, leave.getLeaveCount());
            preparedStatement.setString(9, leave.getStatus());
            int affectedRows = preparedStatement.executeUpdate();
            if (affectedRows > 0) {
                try (ResultSet generatedKeys = preparedStatement.getGeneratedKeys()) {
                    if (generatedKeys.next()) {
                        leave.setLeaveId(generatedKeys.getInt(1));
                    } else {
                        throw new SQLException("Creating task failed, no ID Generated");
                    }
                }
            }
            if (affectedRows < 0) logger.info("Not updated while applying leave");
        } catch (SQLException e) {
            logger.error("Error creating leave", e);
        }
        return leave;
    }

    @Override
    public Leave updateLeave(Leave leave) {
        try {
            PreparedStatement preparedStatement = connection.prepareStatement(queryUpdateLeave);
            preparedStatement.setString(1, leave.getStatus());
            preparedStatement.setInt(2, leave.getLeaveId());
            int affectedRow = preparedStatement.executeUpdate();
            if (affectedRow < 0) logger.info("Status not updated");
            return leave;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public List<Leave> getAllLeavesByEmployeeId(int employeeId, String action) {
        Leave leave = null;
        List<Leave> leaves = new ArrayList<>();
        try {
            PreparedStatement preparedStatement = connection.prepareStatement(queryGetAllLeavesByEmployeeId);
            preparedStatement.setInt(1, employeeId);
            preparedStatement.setString(2, action);
            preparedStatement.setString(3, action);
            ResultSet resultSet = preparedStatement.executeQuery();
            while (resultSet.next()) {
                leave = new Leave();
                leave.setLeaveId(resultSet.getInt("LEAVE_ID"));
                leave.setEmployeeId(resultSet.getInt("EMPLOYEE_ID"));
                leave.setManagerId(resultSet.getInt("MANAGER_ID"));
                leave.setReason(resultSet.getString("REASON"));
                leave.setLeaveType(resultSet.getString("LEAVE_TYPE"));
                leave.setCreatedAt(resultSet.getDate("CREATED_AT").toLocalDate());
                leave.setFromDate(resultSet.getDate("FROM_DATE").toLocalDate());
                leave.setToDate(resultSet.getDate("TO_DATE").toLocalDate());
                leave.setLeaveCount(resultSet.getInt("LEAVE_COUNT"));
                leave.setStatus(resultSet.getString("STATUS"));
                leaves.add(leave);
            }
        } catch (SQLException e) {
            logger.error("Error while retrieving leaves", e);
        }
        return leaves;
    }

    @Override
    public List<RequestLeaves> getLeavesAsManager(int managerId, String action) {
        List<RequestLeaves> listOfRequestLeave = new ArrayList<>();
        try {
            PreparedStatement preparedStatement = connection.prepareStatement(queryGetLeavesAsManager);
            preparedStatement.setInt(1, managerId);
            preparedStatement.setString(2, action);
            preparedStatement.setString(3, action);
            ResultSet resultSet = preparedStatement.executeQuery();

            while (resultSet.next()) {
                RequestLeaves requestLeaves = new RequestLeaves();
                requestLeaves.setLeaveId(resultSet.getInt("LEAVE_ID"));
                requestLeaves.setEmployeeId(resultSet.getInt("EMPLOYEE_ID"));
                requestLeaves.setEmployeeName(resultSet.getString("EMPLOYEE_NAME"));
                requestLeaves.setLeaveType(resultSet.getString("LEAVE_TYPE"));
                requestLeaves.setReason(resultSet.getString("REASON"));
                requestLeaves.setCreatedAt(resultSet.getDate("CREATED_AT").toLocalDate());
                requestLeaves.setFromDate(resultSet.getDate("FROM_DATE").toLocalDate());
                requestLeaves.setToDate(resultSet.getDate("TO_DATE").toLocalDate());
                requestLeaves.setLeaveCount(resultSet.getInt("LEAVE_COUNT"));
                requestLeaves.setStatus(resultSet.getString("STATUS"));

                listOfRequestLeave.add(requestLeaves);
            }
        } catch (SQLException e) {
            logger.error("Error while getting team leaves", e);
        }
        return listOfRequestLeave;
    }

    public int getManagerId(int employeeId) {
        int managerId = -1;
        try {
            PreparedStatement preparedStatement = connection.prepareStatement(queryGetManagerId);
            preparedStatement.setInt(1, employeeId);
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                managerId = resultSet.getInt("MANAGER_ID");
            }
        } catch (SQLException e) {
            logger.error("While querying for managerId of {}", employeeId, e);
        }
        return managerId;
    }
}
