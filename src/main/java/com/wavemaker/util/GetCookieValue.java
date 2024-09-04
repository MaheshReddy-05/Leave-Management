package com.wavemaker.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

public class GetCookieValue {
    public static String getCookieValue(String cookieName, HttpServletRequest req) {
        Cookie[] cookie = req.getCookies();
        if (cookie != null) {
            for (Cookie c : cookie) {
                if (c.getName().equals(cookieName)) {
                    return c.getValue();
                }
            }
        }
        return null;
    }
}
