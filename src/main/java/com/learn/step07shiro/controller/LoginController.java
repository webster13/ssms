package com.learn.step07shiro.controller;


import com.learn.step04log4j.HelloLog4jController;
import com.learn.step06ehcache.entity.User;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

@Controller
@RequestMapping(value = "/learn")
public class LoginController {

    public static final int UNKNOWN_ACCOUT_ERROR_CODE = 1;
    public static final int LOCKED_ACCOUT_ERROR_CODE = 2;
    public static final int AUTHENTICATION_ERROR_CODE = 4;
    public static final int INVALID_CAPTCHA_ERROR_CODE = 8;
    public static final int OTHER_ERROR_CODE = 16;

    public static Logger logger = LoggerFactory.getLogger(HelloLog4jController.class);


    @RequestMapping( method = RequestMethod.GET)
    public String showLearnIndex() {
        return "learn/learn";
    }


    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String showLoginPage() {
        return "learn/login";
    }


    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public String login(HttpServletRequest request, HttpSession session) {
        logger.debug(String.format(
                        "Handle login request with session[id=%s,createOn=%s,lastAccessedOn=%s]",
                        session.getId(),
                        session.getCreationTime(),
                        session.getLastAccessedTime()
                )
        );
        Subject subject = SecurityUtils.getSubject();

        if (subject.isAuthenticated()) {
            subject.logout();
        }
        try {
            String username = WebUtils.getCleanParam(request, "username");
            String password = WebUtils.getCleanParam(request, "password");
            AuthenticationToken token = new UsernamePasswordToken(username, password);
            subject.login(token);

        } catch (Exception e) {
            logger.error("login occur exception.", e);
            return "redirect:/admin/login?code=" + translateException(e);
        }
        return "redirect:/learn/login";

    }

    private int translateException(Exception e) {

        if (e instanceof UnknownAccountException) {
            return UNKNOWN_ACCOUT_ERROR_CODE;
        }

        if (e instanceof LockedAccountException) {
            return LOCKED_ACCOUT_ERROR_CODE;
        }

        if (e instanceof AuthenticationException) {
            return AUTHENTICATION_ERROR_CODE;
        }

        return OTHER_ERROR_CODE;
    }




}
