# Spring Security

github地址：[https://github.com/MrNiebit/SpringSecurity](https://github.com/MrNiebit/SpringSecurity)

## 静态资源素材。
地址：[https://wwa.lanzous.com/iglQVep876f
](https://wwa.lanzous.com/iglQVep876f
)


## 简介

Spring Security 是针对Spring项目的安全框架，也是Spring Boot底层安全模块默认的技术选型，
它可以实现强大的web安全机制，对于安全机制，我们仅需要引入spring-boot-starter-security
模块，进行少量的配置，即可实现的强大的安全管理。

记住几个类：

- WebSecurityConfigurerAdapter：自定义Security策略
- AuthenticationManagerBulder：自定义认证策略。
- @EnableWebSecurity：开启WebSecurity模式

Spring Security 的两个主要的目标是 认证 和 授权 （访问控制）

- 认证（Authentication）
- 授权（Authorization）

这个概念是通用的，而不是只在Spring Security中存在。

## 依赖

```xml
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>

        <!--thymeleaf 和 springsecurity4整合包-->
        <dependency>
            <groupId>org.thymeleaf.extras</groupId>
            <artifactId>thymeleaf-extras-springsecurity5</artifactId>
            <version>3.0.4.RELEASE</version>
        </dependency>


        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>

```
## 配置类

```java
package com.example.config;


import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    /**
     * 授权
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 首页所有人可以访问，功能页只有对应权限的人才能访问。
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");

        // 没有权限会默认跳到登陆页面  loginPage 定制 登陆界面。login为登陆控制器，参数一般是 username 和 password
        http.formLogin().loginPage("/toLogin")
                .loginProcessingUrl("/login")
                .usernameParameter("name")
                .passwordParameter("pwd");

        // 关闭csrf  不然 logout 可能会有问题。需要携带csrf token 退出登陆。
        http.csrf().disable();

        // 注销 开启注销功能，跳到首页。
        http.logout().logoutSuccessUrl("/");

        // 开启 记住我 的功能。cookie 默认保存两周  rememberMeParameter 自定义 登陆的参数。
        http.rememberMe()
                .rememberMeParameter("rememberMyLogin");
    }


    /**
     * 认证
     * springboot 2.1.x 可以直接使用
     * security 5.0+ 新增了很多的加密方法
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // jdbc认证
//        auth.jdbcAuthentication()
        // 内存认证。
        // 正常情况这些数据应该是从数据库中获取的。
        auth.inMemoryAuthentication()
                .passwordEncoder(new BCryptPasswordEncoder())
                .withUser("admin")
                .password(new BCryptPasswordEncoder().encode("12356")).roles("vip1", "vip2")
                .and()
                .withUser("root")
                .password(new BCryptPasswordEncoder().encode("123456")).roles("vip1", "vip2", "vip3")
                .and()
                .withUser("guest")
                .password(new BCryptPasswordEncoder().encode("123456")).roles("vip1");

    }
}

```


## 在thymeleaf使用 sec 的时候，一定要主义springboot和 security thymeleaf整合包 的版本问题。