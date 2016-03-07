package com.learn.step07shiro;

import javax.annotation.Resource;

import com.learn.step06ehcache.entity.User;
import com.learn.step06ehcache.service.UserService;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;


public class MyRealm extends AuthorizingRealm {

    @Resource
    private UserService userService;

    /**
     * 回调函数,用于权限验证
     * @param principals 用户名
     * @return 验证信息
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(
            PrincipalCollection principals) {
        return null;
    }

    /**
     * 回调函数,用于登录验证
     * @param token 钥匙
     * @return 验证信息
     * @throws AuthenticationException 无法验证的异常
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String username = (String) token.getPrincipal();
        // 调用userService查询是否有此用户  
        User user = userService.findByUsername(username);
        if (user == null) {
            // 抛出 帐号找不到异常  
            throw new UnknownAccountException();
        }
        // 判断帐号是否锁定  
        if (Boolean.TRUE.equals(user.getLocked())) {
            // 抛出 帐号锁定异常  
            throw new LockedAccountException();
        }
        // 交给AuthenticatingRealm使用CredentialsMatcher进行密码匹配  
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(
                user.getUsername(), // 用户名  
                user.getPassword(), // 密码  
                ByteSource.Util.bytes(user.getUsername()+user.getSalt()),// salt=username+salt
                getName() // realm name  
        );
        return authenticationInfo;
    }


    /**
     * 清除缓存
     */
    public void clearAllCache() {
        getAuthenticationCache().clear();
        getAuthorizationCache().clear();
    }

}