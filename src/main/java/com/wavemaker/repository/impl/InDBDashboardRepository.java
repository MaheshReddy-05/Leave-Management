package com.wavemaker.repository.impl;

import com.wavemaker.model.Holiday;
import com.wavemaker.model.Leave;
import com.wavemaker.model.LeavesSummary;
import com.wavemaker.repository.DashboardRepository;
import com.wavemaker.util.DBConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class InDBDashboardRepository implements DashboardRepository {
    public static Connection connection;
    private static final Logger logger = LoggerFactory.getLogger(InDBDashboardRepository.class);
    private final static String queryGetGender = "SELECT GENDER, EMPLOYEE_NAME FROM EMPLOYEE WHERE EMPLOYEE_ID = ?";
    private final static String queryLeaveSummary = "SELECT LEAVE_TYPE, SUM(LEAVE_COUNT) AS total_leave_days" +
            " FROM LEAVES WHERE EMPLOYEE_ID = ? AND STATUS = 'Approved' GROUP BY LEAVE_TYPE;";
    private final static String queryGetHolidays = "SELECT * FROM HOLIDAYS;";
    private final static String queryGetTopFourApprovedLeaveByEmployeeId = "SELECT * FROM LEAVES WHERE" +
            " EMPLOYEE_ID = ? AND STATUS = 'Approved' ORDER BY CREATED_AT DESC LIMIT 4;";
    private final static String queryDoEmployeeHadTeam = "SELECT * FROM EMPLOYEE WHERE MANAGER_ID = ?";
    private final static String queryGetAllTeamMembersByManagerId1 = "SELECT EMPLOYEE_ID, EMPLOYEE_NAME " +
            "FROM EMPLOYEE WHERE MANAGER_ID = ?";
    public InDBDashboardRepository() throws SQLException {
        connection = DBConnector.connect();
    }

    @Override
    public List<Holiday> getHolidays() {
        List<Holiday> listHolidays = null;
        try {
            PreparedStatement preparedStatement = connection.prepareStatement(queryGetHolidays);
            ResultSet resultSet = preparedStatement.executeQuery();
            listHolidays = new ArrayList<>();
            while (resultSet.next()) {
                Holiday holiday = new Holiday();
                holiday.setHolidayId(resultSet.getInt("HOLIDAY_ID"));
                holiday.setHolidayName(resultSet.getString("HOLIDAY_NAME"));
                holiday.setHolidayDate(resultSet.getDate("HOLIDAY_DATE").toLocalDate());
                listHolidays.add(holiday);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }

        return listHolidays;
    }

    @Override
    public String getGenderByEmployeeId(int employeeId) {
        try {
            PreparedStatement preparedStatement = connection.prepareStatement(queryGetGender);
            preparedStatement.setInt(1, employeeId);
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                String gender = resultSet.getString("GENDER");
                String employeeName = resultSet.getString("EMPLOYEE_NAME");
                return gender + " " + employeeName;
            }
        } catch (SQLException e) {
            logger.error("Unable to fetch employee gender for employeeid: {}", employeeId, e);
        }
        return "";
    }

    @Override
    public LeavesSummary getLeaveSummaryById(int employeeId) {
        PreparedStatement preparedStatement = null;
        LeavesSummary leavesSummary = new LeavesSummary();
        try {
            preparedStatement = connection.prepareStatement(queryLeaveSummary);
            preparedStatement.setInt(1, employeeId);
            ResultSet resultSet = preparedStatement.executeQuery();

            while (resultSet.next()) {
                String leaveType = resultSet.getString("LEAVE_TYPE");
                int totalLeaveDays = resultSet.getInt("total_leave_days");

                switch (leaveType) {
                    case "Compensatory Off":
                        leavesSummary.setCompensatoryOff(totalLeaveDays);
                        break;
                    case "Loss of Pay":
                        leavesSummary.setLossOffPay(totalLeaveDays);
                        break;
                    case "Maternity Leave":
                        leavesSummary.setMaternityLeave(totalLeaveDays);
                        break;
                    case "Paternity Leave":
                        leavesSummary.setPaternityLeave(totalLeaveDays);
                        break;
                    case "Personal Time Off":
                        leavesSummary.setPersonalTimeOff(totalLeaveDays);
                        break;
                    default:
                        break;
                }
            }
            return leavesSummary;
        } catch (SQLException e) {
            logger.error("Error while getting leaves summary", e);
        }
        return leavesSummary;
    }

    @Override
    public List<Leave> getTopFourApprovedLeaveByEmployeeId(int employeeId) {
        PreparedStatement preparedStatement = null;
        List<Leave> recentLeavesList = new ArrayList<>();
        Leave leave = null;
        try {
            preparedStatement = connection.prepareStatement(queryGetTopFourApprovedLeaveByEmployeeId);
            preparedStatement.setInt(1, employeeId);
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
                recentLeavesList.add(leave);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return recentLeavesList;
    }

    @Override
    public boolean doEmployeeHadTeam(int employeeId) {
        PreparedStatement preparedStatement = null;
        try {
            preparedStatement = connection.prepareStatement(queryDoEmployeeHadTeam);
            preparedStatement.setInt(1, employeeId);
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) return true;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return false;
    }

    @Override
    public List<LeavesSummary> getAllTeamMembersByManagerId(int managerId) {
        List<LeavesSummary> listOfTeamMembers = new ArrayList<LeavesSummary>();
        PreparedStatement preparedStatement = null;
        try {
            preparedStatement = connection.prepareStatement(queryGetAllTeamMembersByManagerId1);
            preparedStatement.setInt(1, managerId);
            ResultSet resultSet = preparedStatement.executeQuery();
            while (resultSet.next()) {
                LeavesSummary leavesSummary = new LeavesSummary();
                int employeeId = resultSet.getInt("EMPLOYEE_ID");
                String employeeName = resultSet.getString("EMPLOYEE_NAME");
                leavesSummary = getLeaveSummaryById(employeeId);
                leavesSummary.setEmployeeId(employeeId);
                leavesSummary.setEmployeeName(employeeName);
                leavesSummary.setGender(getGenderByEmployeeId(employeeId));
                listOfTeamMembers.add(leavesSummary);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return listOfTeamMembers;
    }

}
