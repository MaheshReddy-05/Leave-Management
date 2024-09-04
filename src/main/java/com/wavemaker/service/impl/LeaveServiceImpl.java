package com.wavemaker.service.impl;

import com.wavemaker.factory.SingletonLeaveRepository;
import com.wavemaker.model.Leave;
import com.wavemaker.model.RequestLeaves;
import com.wavemaker.repository.LeaveRepository;
import com.wavemaker.service.LeaveService;

import java.sql.SQLException;
import java.util.List;

public class LeaveServiceImpl implements LeaveService {
    private static LeaveRepository leaveRepository;

    public LeaveServiceImpl() throws SQLException {
        leaveRepository = SingletonLeaveRepository.getInDBLeaveRepositoryInstance();
    }

    @Override
    public Leave applyLeave(Leave leave) {
        return leaveRepository.applyLeave(leave);

    }

    @Override
    public Leave updateLeave(Leave leave) {
        return leaveRepository.updateLeave(leave);
    }

    @Override
    public List<Leave> getAllLeavesByEmployeeId(int employeeId, String action) {
        return leaveRepository.getAllLeavesByEmployeeId(employeeId, action);
    }

    @Override
    public List<RequestLeaves> getLeavesAsManager(int managerId, String action) {
        return leaveRepository.getLeavesAsManager(managerId, action);
    }
}
