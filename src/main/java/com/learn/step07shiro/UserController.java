package com.learn.step07shiro;


import java.text.SimpleDateFormat;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import com.learn.step04log4j.HelloLog4jController;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
@RequestMapping(value = "learn")
public class UserController {

	public static Logger log = LoggerFactory.getLogger(HelloLog4jController.class);


    @RequestMapping(method = RequestMethod.GET)
    public String index() {
        return "learn/learn";
    }



	@RequestMapping(value = "/login",method = RequestMethod.GET)
	public String loginPage() {
		String now = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
				.format(new Date());
		log.debug(now + "to LoginPage!!!");
		return "learn/login";
	}

    @RequestMapping(value = "/login_out",method = RequestMethod.GET)
    public String logOut() {
        Subject subject = SecurityUtils.getSubject();
        subject.logout();
        return "learn/learn";
    }

	@RequestMapping(value = "/login",method = RequestMethod.POST)
	public String login(HttpServletRequest request, String username,
						String password,Boolean rememberMe) {
        log.debug("username:" + username + "----" + "password:"
                + password);
		Subject subject = SecurityUtils.getSubject();
		UsernamePasswordToken token = new UsernamePasswordToken(username,
				password,rememberMe);
		String error = null;
		try {
			subject.login(token);
		} catch (UnknownAccountException e) {
			error = "用户名无效";
		} catch (IncorrectCredentialsException e) {
			error = "用户名/密码错误";
		} catch (ExcessiveAttemptsException e) {
			error = "登录失败多次，账户锁定10分钟";
		} catch (AuthenticationException e) {
			// 其他错误，比如锁定，如果想单独处理请单独catch处理
			error = "其他错误：" + e.getMessage();
		}
		if (error != null) {// 出错了，返回登录页面
			request.setAttribute("msg", error);
			return "learn/login";
		} else {// 登录成功
			return "learn/learn";
		}

	}

}
