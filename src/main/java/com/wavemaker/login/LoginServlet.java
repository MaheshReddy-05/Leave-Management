package com.wavemaker.login;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.wavemaker.config.GsonConfig;
import com.wavemaker.factory.SingletonLoginRepository;
import com.wavemaker.model.Login;
import com.wavemaker.repository.LoginRepository;
import com.wavemaker.util.CookieStore;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.SQLException;
import java.util.UUID;

@WebServlet(urlPatterns = "/login")
public class LoginServlet extends HttpServlet {
    private static LoginRepository loginRepository;
    private static Gson gson;
    private static final Logger logger = LoggerFactory.getLogger(LoginServlet.class);

    @Override
    public void init(ServletConfig config) throws ServletException {
        gson = GsonConfig.createGson();
        try {
            loginRepository = SingletonLoginRepository.getInDBLoginRepositoryInstance();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to initialize LoginRepository", e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String jsonResponse;
        try (BufferedReader bufferedReader = req.getReader()) {
            Login login = gson.fromJson(bufferedReader, Login.class);
            int employeeId = loginRepository.isEmployee(login.getEmail(), login.getPassword());
            String cookieValue = UUID.randomUUID().toString();

            if (employeeId != -1) {
                HttpSession session = req.getSession(true);
                session.setMaxInactiveInterval(30 * 60);
                String cookieName = "AuthCookie";
                Cookie cookie = new Cookie(cookieName, cookieValue);

                cookie.setHttpOnly(true);
                cookie.setSecure(false);
                cookie.setPath("/");
                cookie.setMaxAge(30 * 60);
//                cookie.setSameSite("None");

                session.setAttribute("AuthCookie", employeeId);
                session.setAttribute("employeeId", employeeId);
                resp.addCookie(cookie);

                String sessionId = session.getId();
                resp.setHeader("Set-Cookie", "JSESSIONID=" + sessionId + "; HttpOnly; SameSite=None; Secure");

                CookieStore.addUserCookie(employeeId, cookieValue);

                jsonResponse = gson.toJson("Valid");
                sendResponse(resp, jsonResponse);
            } else {
                jsonResponse = gson.toJson("Invalid login credentials");
                sendResponse(resp, jsonResponse);
            }
        } catch (JsonSyntaxException e) {
            jsonResponse = gson.toJson("Invalid JSON format");
            sendResponse(resp, jsonResponse);
        }
    }

    private void sendResponse(HttpServletResponse httpServletResponse, String jsonResponse) {
        try (PrintWriter printWriter = httpServletResponse.getWriter()) {
            httpServletResponse.setContentType("application/json");
            printWriter.print(jsonResponse);
            printWriter.flush();
        } catch (IOException e) {
            logger.error("Failed while sending response", e);
        }
    }
}
