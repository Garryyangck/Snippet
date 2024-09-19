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



### Interceptor 配置

```java
@Configuration
public class InterceptorConfig implements WebMvcConfigurer {
    @Resource
    MemberInterceptor memberInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 路径不要包含context-path(即 application.yml 中配置的，最前面的：/member)
        registry.addInterceptor(memberInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns(
                        "/hello",
                        "/member/send-code",
                        "/member/login"
                );
    }
}
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



### PageAspect

所有涉及分页的 Service 方法，返回值都必须是 PageVo：

```java
@EqualsAndHashCode(callSuper = true)
@Data
public class PageVo<T> extends PageInfo<T> {
    /**
     * 后端额外携带的分页信息
     */
    private String msg;
}
```

所有涉及分页的 Service 方法，参数必须继承 PageForm：

```java
/**
 * 作为所有需要分页的 form 请求的父类，统一提供 pageNum 和 pageSize
 */
@Data
public class PageForm {
    /**
     * 查询页码
     */
    @NotNull(message = "【查询页码】不能为空")
    private Integer pageNum; // 不能使用 int，int 有默认值 0，而 Integer 的默认值是 null，int 会“蒙混过关”

    /**
     * 每页条数
     */
    @NotNull(message = "【每页条数】不能为空")
    @Max(value = 50, message = "【每页条数】不能超过上限50")
    private Integer pageSize;
}
```

这样就可以定义切面，并且对参数和返回值进行安全的向下转型，得到 PageAspect：

```java
/**
 * 拦截 service 层所有涉及到分类的方法
 */
@Slf4j
@Aspect
@Component
public class PageAspect {

    /**
     * 在包 garry 及其子包中，
     * 类名包含 Service 的所有类中的所有公共方法，
     * 这些方法的返回值必须是 garry.train.common.vo.PageVo 类型，
     * 无论它们的方法名和参数是什么。
     */
    @Pointcut("execution(public garry.train.common.vo.PageVo garry..*Service*.*(..))")
    public void pageServicePointcut() {
    }

    @Around("pageServicePointcut()")
    public Object doAround(ProceedingJoinPoint proceedingJoinPoint) throws Throwable {
        Object[] args = proceedingJoinPoint.getArgs();
        PageForm form = null;
        for (Object arg : args) {
            if (arg instanceof PageForm) {
                form = (PageForm) arg;
                break;
            }
        }
        if (ObjectUtil.isNotNull(form)) {
            log.info("查询页码: {}", form.getPageNum());
            log.info("每页条数: {}", form.getPageNum());
        }

        Object result = proceedingJoinPoint.proceed();

        if (result instanceof PageVo) {
            PageVo vo = (PageVo) result;
            log.info("总行数: {}", vo.getSize());
            log.info("总页数: {}", vo.getPages());
        }

        return result;
    }
}
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



### HostHolder

```java
@Slf4j
@Component
public class HostHolder {
    private final ThreadLocal<MemberLoginVo> members = new ThreadLocal<>();

    public void setMember(MemberLoginVo vo) {
        members.set(vo);
    }

    public MemberLoginVo getMember() {
        return members.get();
    }

    public void remove() {
        members.remove();
    }

    public Long getMemberId() {
        try {
            return members.get().getId();
        } catch (Exception e) {
            log.error(ResponseEnum.THREAD_LOCAL_ERROR.getMsg());
            throw new BusinessException(ResponseEnum.THREAD_LOCAL_ERROR);
        }
    }
}
```

---



### PageHelper

1. 依赖(必须要 1.4.6+ 的版本才支持 Springboot3.x)：

	```xml
	<!--pageHelper，必须要1.4.6+的版本才支持Springboot3.x-->
	<dependency>
	    <groupId>com.github.pagehelper</groupId>
	    <artifactId>pagehelper-spring-boot-starter</artifactId>
	    <version>1.4.6</version>
	</dependency>
	```

2. 使用，原理是将遇到的一条 sql 进行 limit 改造：

	```java
	// 启动分页
	PageHelper.startPage(form.getPageNum(), form.getPageSize());
	
	// 获取 passengers
	List<Passenger> passengers = passengerMapper.selectByExample(passengerExample);
	
	// 获得 pageInfo 对象，并将其 List 的模板类型改为 PassengerQueryVo
	// 注意这里必须先获取 pageInfo，再尝试获取 List<PassengerQueryVo>，否则无法正确获取 pageNum，pages 等重要属性
	PageInfo<Passenger> pageInfo = new PageInfo<>(passengers);
	List<PassengerQueryVo> voList = BeanUtil.copyToList(pageInfo.getList(), PassengerQueryVo.class);
	
	// 获取 PageVo 对象
	PageVo<PassengerQueryVo> vo = BeanUtil.copyProperties(pageInfo, PageVo.class);
	vo.setList(voList);
	vo.setMsg("queryList success");
	return vo;
	```

3. PageInfo 对象的样子，可见有很多前端可以很方便使用的属性，比如 nextPage、navigatePages：

	```json
	"PageInfo": {
	    "total": 15,
	    "list": [
	        {
	            "id": 1834949134566690816,
	            "memberId": 1833041335083470848,
	            "name": "13",
	            "idCard": "123111",
	            "type": "2",
	            "createTime": "2024-09-14T13:35:40.044+00:00",
	            "updateTime": "2024-09-14T13:35:40.044+00:00"
	        },
	        {
	            "id": 1834958731079716864,
	            "memberId": 1833041335083470848,
	            "name": "14",
	            "idCard": "000000200401270000",
	            "type": "3",
	            "createTime": "2024-09-14T14:13:48.031+00:00",
	            "updateTime": "2024-09-14T14:13:48.031+00:00"
	        },
	        {
	            "id": 1834958759143804928,
	            "memberId": 1833041335083470848,
	            "name": "15",
	            "idCard": "000000200401270000",
	            "type": "3",
	            "createTime": "2024-09-14T14:13:54.722+00:00",
	            "updateTime": "2024-09-14T14:13:54.722+00:00"
	        }
	    ],
	    "pageNum": 2,
	    "pageSize": 12,
	    "size": 3,
	    "startRow": 13,
	    "endRow": 15,
	    "pages": 2,
	    "prePage": 1,
	    "nextPage": 0,
	    "isFirstPage": false,
	    "isLastPage": true,
	    "hasPreviousPage": true,
	    "hasNextPage": false,
	    "navigatePages": 8,
	    "navigatepageNums": [
	        1,
	        2
	    ],
	    "navigateFirstPage": 1,
	    "navigateLastPage": 2
	}
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

### 网关统一登录过滤器

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
            } else {
                log.info("登录校验通过");
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



### 非网关拦截器

```java
@Slf4j
@Component
public class MemberInterceptor implements HandlerInterceptor {
    @Resource
    private HostHolder hostHolder;

    /**
     * 获取 request header 中的 token，由此获取 token 中的原始信息，保存到 hostHolder 中
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        log.info("------------- MemberInterceptor 开始 -------------");
        String path = request.getContextPath() + request.getServletPath();
        log.info("MemberInterceptor 拦截路径 = {}", path);
        String token = request.getHeader("token");
        if (StrUtil.isNotBlank(token)) {
            log.info("获取会员登录 token = {}", token);
            JSONObject loginMember = JWTUtil.getJSONObject(token);
            MemberLoginVo memberLoginVo = JSONUtil.toBean(loginMember, MemberLoginVo.class);
            memberLoginVo.setToken(token);
            log.info("当前登录会员：{}", memberLoginVo);
            hostHolder.setMember(memberLoginVo);
        } else {
            log.info("{} 的 token 不存在或已过期", path);
        }

        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) {
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        hostHolder.remove();
    }
}
```

相应的，拦截器的配置类：

```java
@Configuration
public class InterceptorConfig implements WebMvcConfigurer {
    @Resource
    MemberInterceptor memberInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // 路径不要包含context-path(即 application.yml 中配置的，最前面的：/member)
        registry.addInterceptor(memberInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns(
                        "/hello",
                        "/member/send-code",
                        "/member/login"
                );
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



### freemarker 引擎

1. 引入依赖：

	```xml
	<!--模板引擎 freemarker-->
	<dependency>
	    <groupId>org.freemarker</groupId>
	    <artifactId>freemarker</artifactId>
	    <version>2.3.31</version>
	</dependency>
	```

2. 工具类：

	```java
	public class FreemarkerUtil {
	
	    static String ftlPath = "generator/src/main/java/garry/train/generator/ftl/";
	
	    static Template temp;
	
	    /**
	     * 读模板
	     */
	    public static void initConfig(String ftlName) throws IOException {
	        // 这里的版本与你实际使用的 freemarker 的版本一致
	        Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);
	        cfg.setDirectoryForTemplateLoading(new File(ftlPath));
	        cfg.setObjectWrapper(new DefaultObjectWrapper(Configuration.VERSION_2_3_31));
	        temp = cfg.getTemplate(ftlName);
	    }
	
	    /**
	     * 根据模板，生成文件
	     */
	    public static void generator(String fileName, Map<String, Object> map) throws IOException, TemplateException {
	        FileWriter fw = new FileWriter(fileName);
	        BufferedWriter bw = new BufferedWriter(fw);
	        temp.process(map, bw);
	        bw.flush();
	        fw.close();
	    }
	}
	```

3. ftl 模板：

	```js
	public class ${domain} {
	    public String str;
	}
	```

4. 使用：

	```java
	public class ServerGenerator {
	    private static String toPath = "generator/src/main/java/garry/train/generator/test/";
	
	    public static void main(String[] args) throws Exception {
	        FreemarkerUtil.initConfig("test.ftl");
	        HashMap<String, Object> map = new HashMap<>();
	        map.put("domain", "Test");
	        FreemarkerUtil.generator(toPath + "Test.java", map);
	    }
	}
	```

----



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
>
> 只有POST类型的请求才加@RequestBody，因为Content-type=application/json
>
> 而GET类型请求由于Accept=application/json，因此加了@RequestBody反而会报错！

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

### @JsonSerialize

主要用于改变 Long 类型的序列化方式，避免后端 Long 类型传递到前端时，精度损失：

```java
@Data
public class PassengerQueryVo {
    @JsonSerialize(using = ToStringSerializer.class)
    private Long id;

    @JsonSerialize(using = ToStringSerializer.class)
    private Long memberId;

    private String name;

    private String idCard;

    private String type;

    private Date createTime;

    private Date updateTime;
}
```

---



### @PathVariable

```java
@RequestMapping(value = "/delete/{id}", method = RequestMethod.DELETE)
public ResponseVo delete(@PathVariable Long id) {
    passengerService.delete(id);
    return ResponseVo.success();
}
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



## 脚本

### watch() 用法

```javascript
/**
 * 动态监视 router.currentRoute.value.path 的变化，变化时触发后面的函数
 */
watch(() => router.currentRoute.value.path, (newValue) => {
    selectedKeys.value = [];
    selectedKeys.value.push(newValue);
}, {immediate: true});
```

---



### axios 请求服务器

```javascript
axios.post('member/passenger/save', {
    param1: 'xxx',
    param2: 'xxx',
}).then(response => {
    let responseVo = response.data;
    if (responseVo.success) {
        notification.success({description: '成功'});
    } else {
        notification.error({description: responseVo.msg});
    }
})
```

---



### 模态框

```vue
<template>
  <div>
    <a-button type="primary" @click="showModal">新增</a-button>
    <a-modal v-model:visible="visible" title="乘车人" @ok="handleOk"
             ok-text="确认" cancel-text="取消">
      <a-form :label-col="{span: 4}" :wrapper-col="{span: 14}">
        <a-form-item label="姓名">
          <a-input v-model:value="passenger.name"/>
        </a-form-item>
        <a-form-item label="身份证号">
          <a-input v-model:value="passenger.idCard"/>
        </a-form-item>
        <a-form-item label="乘客类型">
          <a-select v-model:value="passenger.type">
            <a-select-option value="1">成人</a-select-option>
            <a-select-option value="2">儿童</a-select-option>
            <a-select-option value="3">学生</a-select-option>
          </a-select>
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>
```

---



## 组件

### 导航栏

```vue
<template>
  <a-layout-header class="header">
    <a-menu
        v-model:selectedKeys="selectedKeys"
        theme="dark"
        mode="horizontal"
        :style="{ lineHeight: '64px' }"
    >
      <a-menu-item key="/welcome">
        <router-link to="/welcome">
          <coffee-outlined/> &nbsp; 欢迎
        </router-link>
      </a-menu-item>
      <a-menu-item key="/passenger">
        <router-link to="/passenger">
          <user-outlined/> &nbsp; 乘车
        </router-link>
      </a-menu-item>
    </a-menu>
  </a-layout-header>
</template>
```

---



### 侧边栏

```vue
<template>
  <a-layout-sider width="15%" style="background: #fff; height: 100vh">
    <a-menu
        v-model:selectedKeys="selectedKeys"
        v-model:openKeys="openKeys"
        mode="inline"
        :style="{ height: '100%', borderRight: 0 }"
    >
      <a-menu-item key="/welcome">
        <router-link to="/welcome">
          <coffee-outlined/> &nbsp; 欢迎
        </router-link>
      </a-menu-item>
      <a-menu-item key="/passenger">
        <router-link to="/passenger">
          <user-outlined/> &nbsp; 乘车
        </router-link>
      </a-menu-item>
    </a-menu>
  </a-layout-sider>
</template>
```

---



### 表格

```vue
<a-table :dataSource="passengers"
         :columns="columns"
         :pagination="pagination"
         @change="handleTableChange"
         :loading="loading">
    <template #bodyCell="{ column, record }"> <!--自带两个参数-->
<template v-if="column.dataIndex === 'operation'">
    <a-space>
        <a-popconfirm
                      title="删除后不可恢复，确认删除?"
                      @confirm="onDelete(record)"
                      ok-text="确认" cancel-text="取消"
                      >
            <a style="color: red">删除</a>
        </a-popconfirm>
        <a @click="onEdit(record)">编辑</a>
        </a-space>
    </template>
    <template v-else-if="column.dataIndex === 'type'">
<span v-for="item in PASSENGER_TYPE_ARRAY" :key="item.code">
    <span v-if="item.code === record.type">
        {{ item.desc }}
        </span>
        </span>
    </template>
    </template>
</a-table>
```

js：

```javascript
export default defineComponent({
  setup() {
    const passengers = ref([]);
    const loading = ref(false);

    const pagination = ref({ // 框架规定的属性名，不能改属性名！
      total: 0, /*所有的总数，list.total*/
      current: 1, /*list.pageNum*/
      pageSize: 10,
    });

    const columns = ref([
      {
        title: '姓名',
        dataIndex: 'name',
        key: 'name',
      },
      {
        title: '身份证号',
        dataIndex: 'idCard',
        key: 'idCard',
      },
      {
        title: '乘客类型',
        dataIndex: 'type',
        key: 'type',
      },
      {
        title: '操作',
        dataIndex: 'operation',
      }
    ]);

    /**
     * 处理查询请求
     * @param param {pageNum, pageSize}
     */
    const handleQuery = (param) => {
      let byRefresh = false;
      if (!param) {
        param = {
          pageNum: 1,
          pageSize: pagination.value.pageSize,
        };
        byRefresh = true;
      }
      loading.value = true;
      axios.get('member/passenger/query-list', {
        params: {
          pageNum: param.pageNum,
          pageSize: param.pageSize,
        }
      }).then(response => {
        loading.value = false;
        let responseVo = response.data;
        if (responseVo.success) {
          passengers.value = responseVo.data.list;
          pagination.value.total = responseVo.data.total;
          // 设置当前的页码，如果不设置的话，就只会设置第二页的内容，但是页码依然是第一页
          pagination.value.current = responseVo.data.pageNum;
          if (byRefresh)
            notification.success({description: '刷新成功'});
        } else {
          notification.error({description: responseVo.msg});
        }
      })
    };

    /**
     * 表格发生改变的回调函数，点击页码也算改变
     * @param pagination
     */
    const handleTableChange = (pagination) => {
      // handleTableChange 自带一个 pagination 参数，含有 total，current，pageSize 三个属性
      handleQuery({
        pageNum: pagination.current,
        pageSize: pagination.pageSize,
      });
    };

    /**
     * 页面初始化的触发函数
     */
    onMounted(() => {
      handleQuery({
        pageNum: 1,
        pageSize: pagination.value.pageSize,
      })
    });

    return {
      ...
    };
  },
});
```

---

