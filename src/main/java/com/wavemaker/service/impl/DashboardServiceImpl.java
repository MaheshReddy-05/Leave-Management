package com.wavemaker.service.impl;

import com.wavemaker.factory.SingletonDashboardRepository;
import com.wavemaker.model.Holiday;
import com.wavemaker.model.Leave;
import com.wavemaker.model.LeavesSummary;
import com.wavemaker.repository.DashboardRepository;
import com.wavemaker.service.DashboardService;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class DashboardServiceImpl implements DashboardService {

    private static DashboardRepository dashboardRepository;

    public DashboardServiceImpl() throws SQLException {
        dashboardRepository = SingletonDashboardRepository.getInDBDashboardRepositoryInstance();
    }

    @Override
    public String getGenderByEmployeeId(int employeeId) {
        return dashboardRepository.getGenderByEmployeeId(employeeId);
    }

    @Override
    public List<Holiday> getHolidays() {
        return dashboardRepository.getHolidays();
    }

    @Override
    public LeavesSummary getLeaveSummaryById(int employeeId) {
        return dashboardRepository.getLeaveSummaryById(employeeId);
    }

    @Override
    public List<Leave> getTopFourApprovedLeaveByEmployeeId(int employeeId) {
        return dashboardRepository.getTopFourApprovedLeaveByEmployeeId(employeeId);
    }

    @Override
    public boolean doEmployeeHadTeam(int employeeId) {
        return dashboardRepository.doEmployeeHadTeam(employeeId);
    }

    @Override
    public List<LeavesSummary> getAllTeamMembersByManagerId(int managerId) {
        return dashboardRepository.getAllTeamMembersByManagerId(managerId);
    }


}
