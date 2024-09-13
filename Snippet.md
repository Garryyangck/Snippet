# 1. Spring Boot

## 配置

### Redis 配置

> Springboot3；解决不能写入问题；解决写入序列化异常问题

RedisConfig.java：

```java
@Configuration
public class RedisConfig {

    /**
     * RedisTemplate模板
     */
    @Bean("redisTemplate")
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(factory);

        // 使用字符串序列化value，防止默认使用JDK序列化机制，导致value变为形如“\xac\xed\x00\x05t\x00\x04kr1m”的乱码
        redisTemplate.setKeySerializer(new StringRedisSerializer());
        redisTemplate.setValueSerializer(new StringRedisSerializer());
        redisTemplate.setHashKeySerializer(new StringRedisSerializer());
        redisTemplate.setHashValueSerializer(new StringRedisSerializer());

        redisTemplate.afterPropertiesSet();
        return redisTemplate;
    }

    /**
     * StringRedisTemplate模板
     */
    @Bean
    public StringRedisTemplate stringRedisTemplate(RedisConnectionFactory factory) {
        StringRedisTemplate stringRedisTemplate = new StringRedisTemplate();
        stringRedisTemplate.setConnectionFactory(factory);
        stringRedisTemplate.setKeySerializer(new StringRedisSerializer());
        return stringRedisTemplate;
    }
}
```

外部依赖：

```xml
<!--redis依赖-->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
    <version>3.0.0</version>
</dependency>
<!-- Spring集成Redis组件 -->
<dependency>
    <groupId>org.springframework.integration</groupId>
    <artifactId>spring-integration-redis</artifactId>
    <version>6.3.0</version>
</dependency>
```

配置：

```yml
spring:
  data:
    redis:  # Redis配置
      host: 127.0.0.1
      port: 6379
      database: 1
      timeout: 3000 # 读超时
      connectTimeout: 5000  # 连接超时
      lettuce:  # Lettuce连接池
        pool:
          min-idle: 5 # 最小空闲连接
          max-idle: 10  # 最大空闲连接
          max-active: 100 # 最大连接数
          max-wait: 2000  # 连接分配应该阻塞的最大时间
```

---



### logback 配置

> 需要手动修改日志存储的地址：
>
> `<property name="PATH" value="./log/gateway"></property>`
>
> ---
>
> 注意：`<Pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %highlight(%-5level) %yellow([%-50.50class] [%-18X{LOG_ID}]) >>> %cyan(%msg) %n</Pattern>` 中的 LOG_ID 是自定义的一个变量，需要在后端代码中通过：
>
> ```java
> // MDC 是 Slf4j 自带的，用于存放我们自定义的键值对，比如在logback-spring.xml中的LOG_ID
> MDC.put("LOG_ID", CommonUtil.generateUUID(CommonConst.LOG_ID_LENGTH));
> ```
>
> 进行赋值。

logback-spring.xml：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!--suppress ALL -->
<configuration>
    <!--该模块日志文件的生成位置，其相对于整个项目的路径-->
    <!--本质上是创建一个PATH变量，不同的模块只有这里需要修改-->
    <property name="PATH" value="./log/gateway"></property>

    <!--控制台打印日志的配置-->
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <!--[%-18X{LOG_ID}]是为了打印线程的流水号-->
            <Pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %highlight(%-5level) %yellow([%-50.50class] [%-18X{LOG_ID}]) >>> %cyan(%msg) %n</Pattern>
        </encoder>
    </appender>

    <appender name="TRACE_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>${PATH}/trace.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <FileNamePattern>${PATH}/trace.%d{yyyy-MM-dd}.%i.log</FileNamePattern>
            <timeBasedFileNamingAndTriggeringPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedFNATP">
                <maxFileSize>10MB</maxFileSize>
            </timeBasedFileNamingAndTriggeringPolicy>
        </rollingPolicy>
        <layout>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level [%-50.50class] [%-18X{LOG_ID}] >>> %msg %n</pattern>
        </layout>
    </appender>

    <appender name="ERROR_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>${PATH}/error.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <FileNamePattern>${PATH}/error.%d{yyyy-MM-dd}.%i.log</FileNamePattern>
            <timeBasedFileNamingAndTriggeringPolicy class="ch.qos.logback.core.rolling.SizeAndTimeBasedFNATP">
                <maxFileSize>10MB</maxFileSize>
            </timeBasedFileNamingAndTriggeringPolicy>
        </rollingPolicy>
        <layout>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level [%-50.50class] [%-18X{LOG_ID}] >>> %msg %n</pattern>
        </layout>
        <filter class="ch.qos.logback.classic.filter.LevelFilter">
            <level>ERROR</level>
            <onMatch>ACCEPT</onMatch>
            <onMismatch>DENY</onMismatch>
        </filter>
    </appender>

    <!--ERROR级别的日志放到ERROR_FILE-->
    <root level="ERROR">
        <appender-ref ref="ERROR_FILE" />
    </root>

    <!--TRACE级别的日志放到TRACE_FILE-->
    <root level="TRACE">
        <appender-ref ref="TRACE_FILE" />
    </root>

    <!--INFO级别的日志打印到控制台STDOUT-->
    <root level="INFO">
        <appender-ref ref="STDOUT" />
    </root>
</configuration>
```

---



### 网关路由转发的配置

```yml
spring:
  cloud:
    gateway:
      routes: # 网关配置
        - id: member # 路由目的地的Id
          uri: http://127.0.0.1:8081 # 路由目的地的uri
          predicates:
            - Path=/member/** # 将所有以 member为前缀的请求(e.g. http://localhost:8080/member/hello)都转发到 http://127.0.0.1:8081
```

---



### 网关允许跨域访问的配置

```yml
spring:
  cloud:
    gateway:
      globalcors: # 允许跨域
        cors-configurations:
          '[/**]':
            allowed-origin-patterns: # 允许所有来源
              - "*"
            allowed-headers: # 允许携带的头信息
              - "*"
            allowed-methods: # 允许的请求方式
              - "*"
            allow-credentials: true  # 是否允许携带 cookie
            max-age: 3600  # 跨域检测的有效期，前端会发起一个 OPTION请求看接口是否可用，可用才会真正发起你的 POST | GET 请求
```

---



### Mybatis 配置

```yml
spring:
  datasource: # Mybatis 数据库连接配置
    driver-class-name: com.mysql.jdbc.Driver  # driver-class-name：5.7版本为 com.mysql.jdbc.Driver；8.0版本为 com.mysql.cj.jdbc.Driver
    username: 
    password: 
    url: jdbc:mysql://localhost:3306/your_datebase?characterEncoding=UTF-8&autoReconnect=true&useSSL=false&serverTimezone=Asia/Shanghai

mybatis:
  mapper-locations: classpath:/mapper/**/*.xml  # 指定对应的 xml文件的位置为：target/classes/mapper下的所有文件夹的所有.xml文件
```

外部依赖：

> 特别注意，一定要根据 springboot 的版本和 mysql 的版本引入对应的依赖，mybatis 依赖包的版本不是统一管理的，必须自己手动配置！

```xml
<!--mybatis依赖，必须要3.0.0才能支持Springboot3-->
<dependency>
    <groupId>org.mybatis.spring.boot</groupId>
    <artifactId>mybatis-spring-boot-starter</artifactId>
    <version>3.0.0</version>
</dependency>
<!--mysql驱动，5.1开头的版本支持mysql5.7-->
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
    <version>5.1.46</version>
</dependency>
```

---



## 切面编程

### LogAspect

> Springboot3；Controller的日志打印；参数、返回值、用时

LogAspect.java：

```java
@Slf4j
@Aspect
@Component
public class LogAspect {
    private final String[] excludeProperties = {};

    /**
     * 定义一个切点
     * *: 所有的返回值
     * garry: garry下的所有子包
     * ..*Controller: 结尾为Controller的所有类
     * .*: 这些类下的任何方法
     * (..): 任何返回值
     */
    @Pointcut("execution(public * garry..*Controller.*(..))")
    public void controllerPointcut() {
    }

    /**
     * 前置通知
     */
    @Before("controllerPointcut()")
    public void doBefore(JoinPoint joinPoint) {

        // 开始打印请求日志
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        HttpServletRequest request = attributes.getRequest();
        Signature signature = joinPoint.getSignature();
        String name = signature.getName();

        // 打印请求信息
        log.info("------------- 开始 -------------");
        log.info("请求地址: {} {}", request.getRequestURL().toString(), request.getMethod());
        log.info("类名方法: {}.{}", signature.getDeclaringTypeName(), name);
        log.info("远程地址: {}", request.getRemoteAddr());

        // 打印请求参数
        Object[] args = joinPoint.getArgs();

        // 排除特殊类型的参数，如文件类型
        Object[] arguments = new Object[args.length];
        for (int i = 0; i < args.length; i++) {
            if (args[i] instanceof ServletRequest
                    || args[i] instanceof ServletResponse
                    || args[i] instanceof MultipartFile) {
                continue;
            }
            arguments[i] = args[i];
        }
        // 排除字段，敏感字段或太长的字段不显示：身份证、手机号、邮箱、密码等
        PropertyPreFilters filters = new PropertyPreFilters();
        PropertyPreFilters.MySimplePropertyPreFilter excludeFilter = filters.addFilter();
        excludeFilter.addExcludes(excludeProperties);
        log.info("请求参数: {}", JSONObject.toJSONString(arguments, excludeFilter));
    }

    /**
     * 环绕通知
     */
    @Around("controllerPointcut()")
    public Object doAround(ProceedingJoinPoint proceedingJoinPoint) throws Throwable {
        long startTime = System.currentTimeMillis();
        Object result = proceedingJoinPoint.proceed();
        // 排除字段，敏感字段或太长的字段不显示：身份证、手机号、邮箱、密码等
        PropertyPreFilters filters = new PropertyPreFilters();
        PropertyPreFilters.MySimplePropertyPreFilter excludeFilter = filters.addFilter();
        excludeFilter.addExcludes(excludeProperties);
        log.info("返回结果: {}", JSONObject.toJSONString(result, excludeFilter));
        log.info("------------- 结束 耗时：{} ms -------------\n", System.currentTimeMillis() - startTime);
        return result;
    }

}
```

外部依赖：

```xml
<!--spring-boot切面编程-->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-aop</artifactId>
    <version>3.0.0</version>
</dependency>
```

---



## 统一异常处理

> Springboot3；为不同的异常进行特定的处理，也可以自定义一个异常

```java
@Slf4j
@ControllerAdvice
public class ControllerExceptionHandler {

    @ExceptionHandler({Exception.class})
    @ResponseBody // 这里必须要加ResponseBody，否则返回的不是JSON字符串！
    public ResponseVo exceptionHandler(Exception e) {
        log.error("系统异常: {}", e.getMessage());
        e.printStackTrace();
        return ResponseVo.error(ResponseEnum.ERROR);
    }

    @ExceptionHandler({RuntimeException.class})
    @ResponseBody
    public ResponseVo bindExceptionHandler(BindException e) {
        log.error("运行时异常: {}", e.getMessage());
        return ResponseVo.error(ResponseEnum.ERROR);
    }
}
```

---



## 工具类

### JWTUtil

> 创建JWT；校验JWT；获取JWT的内容

```java
@Slf4j
public class JWTUtil {

    private static final String key = "theBravestGarry20240201";

    /**
     * 生成 JWT
     */
    public static String createToken(Long id, String mobile) {
        HashMap<String, Object> payload = new HashMap<>();
        payload.put("id", id);
        payload.put("mobile", mobile);

        DateTime now = DateTime.now();
        DateTime expireTime = now.offsetNew(DateField.HOUR, 24);
        payload.put(JWTPayload.ISSUED_AT, now); // 签发时间
        payload.put(JWTPayload.EXPIRES_AT, expireTime); // 过期时间
        payload.put(JWTPayload.NOT_BEFORE, now); // 生效时间

        String token = cn.hutool.jwt.JWTUtil.createToken(payload, key.getBytes());
        log.info("已为手机号 {} 的用户生成 JWT: {}", mobile, token);
        return token;
    }

    /**
     * 校验 token 是否有效，无效则抛出业务异常，供统一异常处理
     */
    public static boolean validate(String token) {
        try {
            JWT jwt = JWT.of(token).setKey(key.getBytes());
            return jwt.validate(0);
        } catch (Exception e) {
            log.error("校验异常", e);
            return false;
        }
    }

    /**
     * 获取 JWT 中的原始内容
     */
    public static JSONObject getJSONObject(String token) {
        validate(token);
        JWT jwt = JWT.of(token).setKey(key.getBytes());
        JSONObject payloads = jwt.getPayloads();
        payloads.remove(JWTPayload.ISSUED_AT);
        payloads.remove(JWTPayload.EXPIRES_AT);
        payloads.remove(JWTPayload.NOT_BEFORE);
        log.info("根据token获取的原始内容: {}", payloads);
        return payloads;
    }
}
```

外部依赖：

```xml
<!--hutool-->
<dependency>
    <groupId>cn.hutool</groupId>
    <artifactId>hutool-all</artifactId>
    <version>5.8.10</version>
</dependency>
```

---



## 统一响应类

```java
@Data
public class ResponseVo<T> {
    private boolean success = true;

    private Integer code;

    private String msg;

    private T data;

    private ResponseVo(Integer code, String msg, T data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }

    private ResponseVo(Integer code, String msg) {
        this(code, msg, null);
    }

    private ResponseVo(Integer code, String msg, boolean success) {
        this.code = code;
        this.msg = msg;
        this.success = success;
    }

    public static ResponseVo success() {
        return new ResponseVo(ResponseEnum.SUCCESS.getCode(), ResponseEnum.SUCCESS.getMsg());
    }

    public static <T> ResponseVo<T> success(T data) {
        return new ResponseVo<>(ResponseEnum.SUCCESS.getCode(), ResponseEnum.SUCCESS.getMsg(), data);
    }

    public static ResponseVo error(ResponseEnum responseEnum) {
        return new ResponseVo(responseEnum.getCode(), responseEnum.getMsg(), false);
    }

    public static ResponseVo error(String errorMsg) {
        return new ResponseVo(ResponseEnum.ERROR.getCode(), errorMsg, false);
    }

    public static ResponseVo error(ResponseEnum responseEnum, String errorMsg) {
        return new ResponseVo(responseEnum.getCode(), errorMsg, false);
    }
}
```

对应的 ResponseEnum：

```java
@Getter
public enum ResponseEnum {
    ERROR(-1, "服务器异常"),

    SUCCESS(0, "操作成功"),
    ;

    private final Integer code;

    private final String msg;

    ResponseEnum(Integer code, String msg) {
        this.code = code;
        this.msg = msg;
    }
}
```

---



## 拦截器

### 网关统一登录拦截器

> `String token = exchange.getRequest().getHeaders().getFirst("token");` 要求前端传来的 Request.headers 里面必须有一个自定义的 `token` 字段。

```java
@Slf4j
@Component
public class MemberLoginFilter implements GlobalFilter, Ordered {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        log.info("------------- 开始 {} -------------", path);

        // 排除不需要过滤的接口
        if (path.contains("/admin")
                || path.contains("/hello")
                || path.contains("/member/member/login")
                || path.contains("/member/member/send-code")) {
            log.info("{} 不需要登录", path);
        } else {
            String token = exchange.getRequest().getHeaders().getFirst("token");
            log.info("会员登录验证开始，token = {}", token);
            if (StrUtil.isBlank(token) || !JWTUtil.validate(token)) {
                log.info("token为空、无效或已过期");
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                log.info("------------- 结束 {} -------------\n", path);
                return exchange.getResponse().setComplete();
            }
        }

        return chain.filter(exchange).then(Mono.fromRunnable(() -> {
            // 在请求处理之后执行的逻辑
            log.info("------------- 结束 {} -------------\n", path);
        }));
    }

    @Override
    public int getOrder() {
        return -1; // 设置过滤器的优先级，数字越小优先级越高
    }
}
```

---



## 第三方服务

### 阿里云短信服务

SmsServiceImpl:

> templateParam 必须是 JSON 字符串，可以用 fastjson 的 JSONObject.toJSONString() 方法获取。

```java
@Slf4j
@Service
public class SmsServiceImpl implements SmsService {
    @Value("${aliyun.sms.accessKeyId}")
    private String accessKeyId;

    @Value("${aliyun.sms.accessKeySecret}")
    private String accessKeySecret;

    @Value("${aliyun.sms.signName}")
    private String signName;

    @Value("${aliyun.sms.templateCode}")
    private String templateCode;

    //短信API产品名称（短信产品名固定，无需修改）
    private final String product = "Dysmsapi";

    //短信API产品域名（接口地址固定，无需修改）
    private final String domain = "dysmsapi.aliyuncs.com";

    @Override
    public void sendSms(String phoneNumber, String templateParam) {
        try {
            // 创建DefaultAcsClient实例并初始化
            DefaultProfile profile = DefaultProfile.getProfile("cn-hangzhou", accessKeyId, accessKeySecret);
            DefaultProfile.addEndpoint("cn-hangzhou", "cn-hangzhou", product, domain);
            IAcsClient client = new DefaultAcsClient(profile);

            // 创建SendSmsRequest实例，并设置相应的参数
            SendSmsRequest request = new SendSmsRequest();
            request.setMethod(MethodType.POST);
            request.setPhoneNumbers(phoneNumber);
            request.setSignName(signName);
            request.setTemplateCode(templateCode);
            request.setTemplateParam(templateParam);

            // 发起请求并处理响应
            SendSmsResponse response = client.getAcsResponse(request);
            if (!StringUtils.equals("OK", response.getCode())){
                log.error("[短信服务] 发送短信失败，手机号码：{}，原因：{}，response = {}", phoneNumber, response.getMessage(), JSONObject.toJSON(response));
                throw new BusinessException(ResponseEnum.MESSAGE_CODE_SEND_FAILED);
            } else {
                log.info("[短信服务] 发送短信成功，response = {}", JSONObject.toJSON(response));
            }

        } catch (ClientException e) {
            log.error("[短信服务] 发送短信异常，手机号码：{}，错误码：{}，错误信息：{}", phoneNumber, e.getErrCode(), e.getErrMsg());
            throw new BusinessException(ResponseEnum.MESSAGE_CODE_SEND_FAILED);
        } catch (Exception e) {
            log.error("[短信服务] 发送短信异常，手机号码：{}", phoneNumber, e);
            throw new BusinessException(ResponseEnum.MESSAGE_CODE_SEND_FAILED);
        }
    }
}
```

外部依赖：

```xml
<!--阿里云短信服务提供商的API，核心包-->
<dependency>
    <groupId>com.aliyun</groupId>
    <artifactId>aliyun-java-sdk-core</artifactId>
    <version>4.6.3</version>
</dependency>
<!--阿里云短信服务提供商的API，dysmsapi包-->
<dependency>
    <groupId>com.aliyun</groupId>
    <artifactId>aliyun-java-sdk-dysmsapi</artifactId>
    <version>2.2.1</version>
</dependency>
```

配置：

> 阿里云短信控制台获取 signName、templateCode；在控制台右上角点击头像->点击AccessKey 获取 accessKeyId、accessKeySecret。

```yml
aliyun:
  sms:  # 短信发送服务的配置参数
    accessKeyId: 
    accessKeySecret: 
    signName: 
    templateCode: 
```

---



## 代码生成器

### mybatis-generator

> 会同步生成 xxxExample.java，以便我们使用生成的持久层接口。

generator-config.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE generatorConfiguration
        PUBLIC "-//mybatis.org//DTD MyBatis Generator Configuration 1.0//EN"
        "http://mybatis.org/dtd/mybatis-generator-config_1_0.dtd">

<generatorConfiguration>
    <context id="Mysql" targetRuntime="MyBatis3" defaultModelType="flat">

        <!-- 自动检查关键字，为关键字增加反引号(比如如果一张表的名字是select，则会自动将其变为`select`) -->
        <property name="autoDelimitKeywords" value="true"/>
        <property name="beginningDelimiter" value="`"/>
        <property name="endingDelimiter" value="`"/>

        <!--覆盖生成XML文件-->
        <plugin type="org.mybatis.generator.plugins.UnmergeableXmlMappersPlugin" />
        <!-- 生成的实体类添加toString()方法 -->
        <plugin type="org.mybatis.generator.plugins.ToStringPlugin"/>

        <!-- 不生成注释 -->
        <commentGenerator>
            <property name="suppressAllComments" value="true"/>
        </commentGenerator>

        <!-- 配置数据源，需要根据自己的项目修改 -->
        <jdbcConnection driverClass="com.mysql.jdbc.Driver"
                        connectionURL="jdbc:mysql://localhost:3306/train_member?characterEncoding=UTF-8&amp;autoReconnect=true&amp;useSSL=false&amp;serverTimezone=Asia/Shanghai"
                        userId="root"
                        password="1234">
        </jdbcConnection>

        <!-- domain类的位置 targetProject是相对pom.xml的路径-->
        <javaModelGenerator targetProject="../member/src/main/java"
                            targetPackage="garry.train.member.pojo"/>

        <!-- mapper xml的位置 targetProject是相对pom.xml的路径 -->
        <sqlMapGenerator targetProject="../member/src/main/resources"
                         targetPackage="mapper"/>

        <!-- mapper类的位置 targetProject是相对pom.xml的路径 -->
        <javaClientGenerator targetProject="../member/src/main/java"
                             targetPackage="garry.train.member.mapper"
                             type="XMLMAPPER"/>
		
        <!-- 需要生成哪些表，生成的实体类叫什么 -->
        <table tableName="member" domainObjectName="Member"/>
    </context>
</generatorConfiguration>
```

---



## 注解

### @RestController

@RestController = @Controller + @ResponseBody

### @RequestMapping

作用在类上：

```java
@RequestMapping(value = "/member")
public class MemberController
```

作用在方法上：

```java
@RequestMapping(value = "/count", method = RequestMethod.GET)
public ResponseVo<Integer> count()
```

### @NotBlank

```java
@Data
public class MemberLoginForm {
    @NotBlank(message = "手机号不能为空")
    @Pattern(regexp = "^$|^(13[0-9]|14[01456879]|15[0-35-9]|16[2567]|17[0-8]|18[0-9]|19[0-35-9])\\d{8}$",
            message = "手机号码格式不正确")
    private String mobile;

    @NotBlank(message = "验证码不能为空")
    private String code;
}
```

### @Valid

> 启动对参数的校验，比如 @NotBlank。

```java
public ResponseVo register(@Valid @RequestBody MemberRegisterForm form)
```

### @RequestBody

> 必须使用@RequestBody，才能接收(application/json)格式的请求。

```java
public ResponseVo register(@Valid @RequestBody MemberRegisterForm form)
```

### @ResponseBody

> 使返回的格式为 JSON 字符串。

```java
@ExceptionHandler({Exception.class})
@ResponseBody // 这里必须要加ResponseBody，否则返回的不是JSON字符串！
public ResponseVo exceptionHandler(Exception e) {
    log.error("系统异常: {}", e.getMessage());
    e.printStackTrace();
    return ResponseVo.error(ResponseEnum.ERROR);
}
```

### @Configuration @Bean

```java
@Configuration
public class RedisConfig {
    @Bean("redisTemplate")
    public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory factory) {
        ...
        return redisTemplate;
    }
    @Bean
    public StringRedisTemplate stringRedisTemplate(RedisConnectionFactory factory) {
        ...
        return stringRedisTemplate;
    }
}
```

### @Value

> org.springframework.beans.factory.annotation.Value

```java
@Value("${aliyun.sms.accessKeyId}")
private String accessKeyId;
```

### @Pointcut

```java
/**
 * 定义一个切点
 * *: 所有的返回值
 * garry: garry下的所有子包
 * ..*Controller: 结尾为Controller的所有类
 * .*: 这些类下的任何方法
 * (..): 任何返回值
 */
@Pointcut("execution(public * garry..*Controller.*(..))")
public void controllerPointcut() {}
```

### @ComponentScan

```java
@ComponentScan("garry") // 由于Application类放到了config包下，它只能扫描和自己同包的类，因此需要新增ComponentScan注解让其扫描整个garry包下的类
```

### @MapperScan

```java
@MapperScan("garry.train.member.mapper") // 扫描mybatis的代码
```

---



# 2. Vue3

## 导包

### Ant-design-vue

```javascript
import Antd from 'ant-design-vue' // 全局引入 ant-design-vue 的所有组件
import 'ant-design-vue/dist/antd.css' // 全局引入 ant-design-vue 的 css
import * as Icons from '@ant-design/icons-vue'; // 全局引入 ant-design-vue 的所有图标

const app = createApp(App);
app.use(Antd);

/**
 * 全局注册图标组件
 */
Object.keys(Icons).forEach((key) => {
    app.component(key, Icons[key]);
});

app.mount('#app');
```

---



### 自定义的 js

在 index.html 的 <head> 中加入：

```html
<script src="<%= BASE_URL %>js/session-storage.js"></script>
```

---



## 拦截器

### axios 拦截器

main.js 中：

```javascript
/**
 * axios 拦截器
 */
axios.interceptors.request.use(function (config) {
    // 给所有的请求加上token
    console.log('请求参数: ', config);
    const token = store.state.member.token;
    if (token) {
        config.headers.token = token; /*必须写死token，因为网关就写死从headers里面获取"token"*/
        console.log('在' + config.url + '的 headers 增加 token: ' + token);
    }
    return config;
}, error => {
    return Promise.reject(error);
});

axios.interceptors.response.use(function (response) {
    console.log('返回结果: ', response);
    return response;
}, error => {
    const response = error.response;
    const status = response.status;
    if (status === 401) {
        // 特殊处理 401，权限不足，跳转到 /login
        console.log('未登录或登录超时，跳转到登录页面');
        notification.error({description: '未登录或登录超时'});
        router.push('/login');
    }
    console.log('返回错误: ', error);
    return Promise.reject(error);
});
```

---



### 路由拦截器

router/index.js 中：

```javascript
// 统一路由拦截校验
router.beforeEach((to, from, next) => {
    // 要不要对meta.loginRequire属性做监控拦截
    if (to.matched.some(function (item) {
        console.log("\"" + item.path + "\"是否需要登录校验：", item.meta.loginRequire || false);
        return item.meta.loginRequire;
    })) {
        const member = store.state.member;
        console.log("member = ", member);
        if (!member || !member.token) {
            console.log("未登录或登录超时，跳转到登录页面");
            notification.error({ description: "未登录或登录超时" });
            next('/login');
        } else {
            next();
        }
    } else {
        next();
    }
});
```

---



