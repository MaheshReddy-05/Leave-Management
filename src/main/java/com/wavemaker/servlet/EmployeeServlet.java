package com.wavemaker.servlet;

import com.google.gson.Gson;
import com.wavemaker.config.GsonConfig;
import com.wavemaker.model.Leave;
import com.wavemaker.service.LeaveService;
import com.wavemaker.service.impl.LeaveServiceImpl;
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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.SQLException;
import java.util.List;


@WebServlet(urlPatterns = "/employees")
public class EmployeeServlet extends HttpServlet {
    private static Gson gson;
    private static LeaveService leaveService;
    private static final Logger logger = LoggerFactory.getLogger(EmployeeServlet.class);
    HttpSession session;

    @Override
    public void init(ServletConfig config) throws ServletException {
        gson = GsonConfig.createGson();
        try {
            leaveService = new LeaveServiceImpl();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession();
        int employeeId = -1;
        String action = request.getParameter("status");
        String jsonResponse = null;
        List<Leave> leaveList = null;
        try {
            employeeId = (Integer) session.getAttribute("AuthCookie");
            leaveList = leaveService.getAllLeavesByEmployeeId(employeeId, action);
            jsonResponse = gson.toJson(leaveList);

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        } finally {
            JsonResponse.sendResponse(response, jsonResponse);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        String jsonResponse = null;
        BufferedReader bufferedReader = null;
        int employeeId = -1;
        Leave leave = null;
        HttpSession session = req.getSession(false);
        try {
            employeeId = (Integer) session.getAttribute("AuthCookie");
            if (employeeId == -1) return;
            bufferedReader = req.getReader();
            leave = gson.fromJson(bufferedReader, Leave.class);
            leave.setEmployeeId(employeeId);
            leave = leaveService.applyLeave(leave);
            jsonResponse = gson.toJson(leave);
            JsonResponse.sendResponse(resp, jsonResponse);
        } catch (IOException e) {
            logger.error("Failed to apply leave ", e);
        }
    }

    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse resp) {
        String jsonResponse = null;
        BufferedReader bufferedReader = null;
        int employeeId = -1;
        Leave leave = null;
        HttpSession session = req.getSession(false);
        try {
            employeeId = (Integer) session.getAttribute("AuthCookie");
            if (employeeId == -1) return;
            bufferedReader = req.getReader();
            leave = gson.fromJson(bufferedReader, Leave.class);
            leave.setEmployeeId(employeeId);
            leaveService.updateLeave(leave);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
