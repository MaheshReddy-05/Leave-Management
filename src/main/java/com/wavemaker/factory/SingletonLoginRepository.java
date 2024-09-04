package com.wavemaker.factory;

import com.wavemaker.repository.LoginRepository;
import com.wavemaker.repository.impl.InDBLoginRepository;

import java.sql.SQLException;

public class SingletonLoginRepository {
    private static LoginRepository loginRepository = null;

    public static LoginRepository getInDBLoginRepositoryInstance() throws SQLException {
        if (loginRepository != null) return loginRepository;
        loginRepository = new InDBLoginRepository();
        return loginRepository;
    }
}
