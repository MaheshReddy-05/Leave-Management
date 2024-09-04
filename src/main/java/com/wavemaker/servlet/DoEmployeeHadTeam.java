package com.wavemaker.servlet;

import com.google.gson.Gson;
import com.wavemaker.config.GsonConfig;
import com.wavemaker.service.DashboardService;
import com.wavemaker.service.impl.DashboardServiceImpl;
import com.wavemaker.util.JsonResponse;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.SQLException;

@WebServlet(urlPatterns = "/employee_had_team")
public class DoEmployeeHadTeam extends HttpServlet {
    DashboardService dashboardService;
    Gson gson;
    private static final Logger logger = LoggerFactory.getLogger(DoEmployeeHadTeam.class);

    @Override
    public void init(ServletConfig config) throws ServletException {
        gson = GsonConfig.createGson();
        try {
            dashboardService = new DashboardServiceImpl();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        HttpSession session = req.getSession();
        int employeeId = -1;
        String jsonResponse = null;
        try {
            employeeId = (Integer) session.getAttribute("AuthCookie");
            boolean employeeHadTeam = dashboardService.doEmployeeHadTeam(employeeId);
            jsonResponse = gson.toJson(employeeHadTeam);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        } finally {
            JsonResponse.sendResponse(resp, jsonResponse);
        }
    }
}
