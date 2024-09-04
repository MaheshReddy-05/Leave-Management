package com.wavemaker.servlet;

import com.google.gson.Gson;
import com.wavemaker.config.GsonConfig;
import com.wavemaker.model.Holiday;
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
import java.util.List;

@WebServlet(urlPatterns = "/holidays")
public class HolidaysServlet extends HttpServlet {
    private static final Logger logger = LoggerFactory.getLogger(HolidaysServlet.class);
    private static Gson gson;
    private DashboardService dashboardService;

    @Override
    public void init(ServletConfig config) throws ServletException {
        gson = GsonConfig.createGson();
        try {
            dashboardService = new DashboardServiceImpl();
        } catch (SQLException e) {
            logger.error(e.getMessage(), e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        HttpSession session = req.getSession();
        int employeeId = -1;
        String jsonResponse = null;
        List<Holiday> listHoliday = null;
        try {
            listHoliday = dashboardService.getHolidays();
            jsonResponse = gson.toJson(listHoliday);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        } finally {
            JsonResponse.sendResponse(resp, jsonResponse);
        }

    }
}





