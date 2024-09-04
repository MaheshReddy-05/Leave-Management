package com.wavemaker.factory;

import com.wavemaker.repository.LeaveRepository;
import com.wavemaker.repository.impl.InDBLeaveRepository;

import java.sql.SQLException;

public class SingletonLeaveRepository {
    private static LeaveRepository leaveRepository = null;

    public static LeaveRepository getInDBLeaveRepositoryInstance() throws SQLException {
        if (leaveRepository != null) return leaveRepository;
        leaveRepository = new InDBLeaveRepository();
        return leaveRepository;
    }
}
