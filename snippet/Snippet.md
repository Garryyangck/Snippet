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



## 定时调度

### SpringBoot Scheduler

1. SpringBootTestJob：

	```java
	/**
	 * 缺点，适合单体应用，不适合集群。
	 * 原因：我们生成每日报表的跑批任务，只需要跑一次，如果每个节点上都部署的话，就会重复执行。
	 * 针对该问题的一个解决方法是：借助 redis 使用分布式锁，其它拿不到锁就无法执行。
	 * 还有一个问题是：无法主动地暂停、继续执行。
	 */
	@Slf4j
	@Component
	@EnableScheduling
	public class SpringBootTestJob {
	
	    /**
	     * 定义一个定时任务，每 2 秒执行一次
	     */
	    @Scheduled(fixedRate = 2000)
	    public void reportCurrentTime() {
	        // 在此加分布式锁
	        log.info("当前时间: {}", System.currentTimeMillis() / 1000);
	    }
	
	    /**
	     * 使用 cron，秒、分、时、日、月、星期
	     * 每分钟的秒数除以 2，余数为 0 则执行
	     */
	    @Scheduled(cron = "0/2 * * * * *")
	    public void executeTaskWithCron() {
	        // 在此加分布式锁
	        log.info("执行任务: {}", System.currentTimeMillis() / 1000);
	    }
	}
	```

2. 缺点：适合单体应用，不适合集群。

3. 原因：我们生成每日报表的跑批任务，只需要跑一次，如果每个节点上都部署的话，就会重复执行。

4. 针对该问题的一个解决方法是：借助 redis 使用分布式锁，其它拿不到锁就无法执行。

5. 还有一个问题是：无法主动地暂停、继续执行，以及修改跑批时间。

---



### Quartz

1. 依赖：

	```xml
	<!--quartz的springboot依赖-->
	<dependency>
	    <groupId>org.springframework.boot</groupId>
	    <artifactId>spring-boot-starter-quartz</artifactId>
	</dependency>
	```

2. TestJob，必须实现 Job 接口：

	```java
	@Slf4j
	@DisallowConcurrentExecution // 禁止任务并发执行
	public class TestJob implements Job {
	
	    private static final Long baseTimeSecond;
	
	    static {
	        baseTimeSecond = System.currentTimeMillis() / 1000;
	    }
	
	    @Override
	    public void execute(JobExecutionContext context) throws JobExecutionException {
	        String logId = CommonUtil.generateUUID(CommonConst.LOG_ID_LENGTH);
	        MDC.put("LOG_ID", logId);
	        log.info("开始时间: {} 秒", System.currentTimeMillis() / 1000 - baseTimeSecond);
	        try {
	            Thread.sleep(3000);
	        } catch (InterruptedException e) {
	            throw new RuntimeException("被唤醒了");
	        }
	        log.info("结束时间: {} 秒", System.currentTimeMillis() / 1000 - baseTimeSecond);
	    }
	}
	```

3. 使用配置类写死任务的方法：在 QuartzConfig 中配置需要执行的任务，和任务何时执行的触发器：

	```java
	/**
	 * 该配置类只有在第一次被读取时，会将其配置内容存储到数据库中，
	 * 之后就直接读取数据库获取配置，而不再读取此配置类了。
	 * Quartz 发现数据库中有某个 Job 的 Detail 配置和触发器 Trigger 配置，就会自动的按配置执行该任务
	 */
	@Configuration
	public class QuartzConfig {
	
	    /**
	     * 声明一个任务
	     */
	    @Bean
	    public JobDetail jobDetail() {
	        return JobBuilder.newJob(TestJob.class)
	                .withIdentity("TestJob", "test")
	                .storeDurably()
	                .build();
	    }
	
	    /**
	     * 声明一个触发器，什么时候执行任务
	     */
	    @Bean
	    public Trigger trigger() {
	        return TriggerBuilder.newTrigger()
	                .forJob(jobDetail())
	                .withIdentity("TestJobTrigger", "trigger")
	                .startNow()
	                // 每2秒执行一次
	                .withSchedule(CronScheduleBuilder.cronSchedule("*/2 * * * * ?"))
	                .build();
	    }
	}
	```

4. 但是写死配置类的方法并不灵活，我们想让 quartz 将任务和触发器存储到数据库，然后我们对外提供 http 接口，这样前端就可以通过访问这些接口，修改数据库中的数据，实现暂停跑批、修改跑批时间频率等操作，以下为提供 http 接口的操作：

5. MyJobFactory：

	```java
	@Component
	public class MyJobFactory extends SpringBeanJobFactory {
	
	    @Resource
	    private AutowireCapableBeanFactory beanFactory;
	
	    /**
	     * 这里覆盖了 super 的 createJobInstance 方法，对其创建出来的类再进行 autowire。
	     */
	    @Override
	    protected Object createJobInstance(TriggerFiredBundle bundle) throws Exception {
	        Object jobInstance = super.createJobInstance(bundle);
	        beanFactory.autowireBean(jobInstance);
	        return jobInstance;
	    }
	}
	```

6. SchedulerConfig，集成官方提供的 Mysql 数据源：

	```java
	@Configuration
	public class SchedulerConfig {
	
	    @Resource
	    private MyJobFactory myJobFactory;
	
	    /**
	     * 将 Quartz 的 SchedulerFactory 集成官方提供的 Mysql 数据源后的 Bean
	     * @param dataSource Quartz 官方提供的 Mysql 数据源
	     */
	    @Bean
	    public SchedulerFactoryBean schedulerFactoryBean(@Qualifier("dataSource") DataSource dataSource) throws IOException {
	        SchedulerFactoryBean factory = new SchedulerFactoryBean();
	        factory.setDataSource(dataSource);
	        factory.setJobFactory(myJobFactory);
	        factory.setStartupDelay(2); // 启动之后多少秒，开始执行 Quartz
	        return factory;
	    }
	}
	```

7. 对外提供的操作 Quartz Mysql 数据源的 http 接口：

	```java
	@Slf4j
	@RestController
	@RequestMapping(value = "/admin/job")
	public class JobController {
	    // 这里必须是 Autowired，不能是 Resource，
	    // 否则会报错: Bean named 'schedulerFactoryBean' is expected to be of type 'org.springframework.scheduling.quartz.SchedulerFactoryBean' but was actually of type 'org.quartz.impl.StdScheduler'
	    // 猜测原因是 MyFactory 中:
	    //    @Override
	    //    protected Object createJobInstance(TriggerFiredBundle bundle) throws Exception {
	    //        Object jobInstance = super.createJobInstance(bundle);
	    //        beanFactory.autowireBean(jobInstance);
	    //        return jobInstance;
	    //    }
	    // `beanFactory.autowireBean(jobInstance);` 中写到了 autowire
	    @Autowired
	    private SchedulerFactoryBean schedulerFactoryBean;
	
	    /**
	     * 手动立马执行一次任务
	     */
	    @RequestMapping(value = "/run", method = RequestMethod.POST)
	    public ResponseVo run(@Valid @RequestBody CronForm form) throws SchedulerException {
	        String jobClassName = form.getName();
	        String jobGroupName = form.getGroup();
	        log.info("手动执行任务开始: {}, {}", jobClassName, jobGroupName);
	
	        try {
	            schedulerFactoryBean.getScheduler().triggerJob(JobKey.jobKey(jobClassName, jobGroupName));
	
	        } catch (SchedulerException e) {
	            log.error("手动执行任务失败，调度异常: ", e);
	            return ResponseVo.error(ResponseEnum.BATCH_SCHEDULER_RUN_FAILED_DISPATCH_ERROR);
	        }
	        return ResponseVo.success();
	    }
	
	    /**
	     * 添加新任务，要传入全类名
	     */
	    @RequestMapping(value = "/add", method = RequestMethod.POST)
	    public ResponseVo add(@Valid @RequestBody CronForm form) {
	        String jobClassName = form.getName();
	        String jobGroupName = form.getGroup();
	        String cronExpression = form.getCronExpression();
	        String description = form.getDescription();
	        log.info("创建定时任务开始: {}，{}，{}，{}", jobClassName, jobGroupName, cronExpression, description);
	
	        try {
	            // 通过SchedulerFactory 获取一个调度器实例
	            Scheduler scheduler = schedulerFactoryBean.getScheduler();
	
	            // 启动调度器
	            scheduler.start();
	
	            // 构建 job 信息
	            JobDetail jobDetail = JobBuilder
	                    .newJob((Class<? extends Job>) Class.forName(jobClassName))
	                    .withIdentity(jobClassName, jobGroupName)
	                    .build();
	
	            // 表达式调度构建器(即任务执行的时间)
	            CronScheduleBuilder scheduleBuilder = CronScheduleBuilder.cronSchedule(cronExpression);
	
	            // 按新的 cronExpression 表达式构建一个新的 trigger
	            CronTrigger trigger = TriggerBuilder
	                    .newTrigger()
	                    .withIdentity(jobClassName, jobGroupName)
	                    .withDescription(description)
	                    .withSchedule(scheduleBuilder)
	                    .build();
	
	            scheduler.scheduleJob(jobDetail, trigger);
	        } catch (SchedulerException e) {
	            log.error("创建定时任务失败，调度异常: ", e);
	            return ResponseVo.error(ResponseEnum.BATCH_SCHEDULER_ADD_FAILED_DISPATCH_ERROR);
	        } catch (ClassNotFoundException e) {
	            log.error("创建定时任务失败，任务类不存在: ", e);
	            return ResponseVo.error(ResponseEnum.BATCH_SCHEDULER_ADD_FAILED_JOB_NOT_FOUND);
	        }
	
	        return ResponseVo.success();
	    }
	
	    /**
	     * 暂停指定任务
	     */
	    @RequestMapping(value = "/pause", method = RequestMethod.POST)
	    public ResponseVo pause(@Valid @RequestBody CronForm form) {
	        String jobClassName = form.getName();
	        String jobGroupName = form.getGroup();
	        log.info("暂停定时任务开始: {}，{}", jobClassName, jobGroupName);
	
	        try {
	            Scheduler scheduler = schedulerFactoryBean.getScheduler();
	            scheduler.pauseJob(JobKey.jobKey(jobClassName, jobGroupName));
	        } catch (SchedulerException e) {
	            log.error("暂停定时任务失败，调度异常: ", e);
	            return ResponseVo.error(ResponseEnum.BATCH_SCHEDULER_PAUSE_FAILED_DISPATCH_ERROR);
	        }
	
	        return ResponseVo.success();
	    }
	
	    /**
	     * 恢复指定任务
	     */
	    @RequestMapping(value = "/resume", method = RequestMethod.POST)
	    public ResponseVo resume(@Valid @RequestBody CronForm form) {
	        String jobClassName = form.getName();
	        String jobGroupName = form.getGroup();
	        log.info("重启定时任务开始: {}，{}", jobClassName, jobGroupName);
	
	        try {
	            Scheduler scheduler = schedulerFactoryBean.getScheduler();
	            scheduler.resumeJob(JobKey.jobKey(jobClassName, jobGroupName));
	        } catch (SchedulerException e) {
	            log.error("重启定时任务失败，调度异常: ", e);
	            return ResponseVo.error(ResponseEnum.BATCH_SCHEDULER_RESUME_FAILED_DISPATCH_ERROR);
	        }
	
	        return ResponseVo.success();
	    }
	
	    /**
	     * 重定义指定任务
	     */
	    @RequestMapping(value = "/reschedule", method = RequestMethod.POST)
	    public ResponseVo reschedule(@Valid @RequestBody CronForm form) {
	        String jobClassName = form.getName();
	        String jobGroupName = form.getGroup();
	        String cronExpression = form.getCronExpression();
	        String description = form.getDescription();
	        log.info("更新定时任务开始：{}，{}，{}，{}", jobClassName, jobGroupName, cronExpression, description);
	
	        try {
	            Scheduler scheduler = schedulerFactoryBean.getScheduler();
	            TriggerKey triggerKey = TriggerKey.triggerKey(jobClassName, jobGroupName);
	
	            // 表达式调度构建器
	            CronScheduleBuilder scheduleBuilder = CronScheduleBuilder.cronSchedule(cronExpression);
	            CronTriggerImpl _trigger = (CronTriggerImpl) scheduler.getTrigger(triggerKey);
	            _trigger.setStartTime(new Date()); // 重新设置开始时间
	            CronTrigger trigger = _trigger;
	
	            // 按新的 cronExpression 表达式重新构建 trigger
	            trigger = trigger.getTriggerBuilder()
	                    .withIdentity(triggerKey)
	                    .withDescription(description)
	                    .withSchedule(scheduleBuilder)
	                    .build();
	
	            // 按新的trigger重新设置job执行
	            scheduler.rescheduleJob(triggerKey, trigger);
	
	        } catch (Exception e) {
	            log.error("更新定时任务失败，调度异常: ", e);
	            return ResponseVo.error(ResponseEnum.BATCH_SCHEDULER_RESCHEDULE_FAILED_DISPATCH_ERROR);
	        }
	
	        return ResponseVo.success();
	    }
	
	    /**
	     * 删除指定任务
	     */
	    @RequestMapping(value = "/delete", method = RequestMethod.POST)
	    public ResponseVo delete(@Valid @RequestBody CronForm form) {
	        String jobClassName = form.getName();
	        String jobGroupName = form.getGroup();
	        log.info("删除定时任务开始: {}，{}", jobClassName, jobGroupName);
	
	        try {
	            Scheduler scheduler = schedulerFactoryBean.getScheduler();
	            scheduler.pauseTrigger(TriggerKey.triggerKey(jobClassName, jobGroupName));
	            scheduler.unscheduleJob(TriggerKey.triggerKey(jobClassName, jobGroupName));
	            scheduler.deleteJob(JobKey.jobKey(jobClassName, jobGroupName));
	
	        } catch (SchedulerException e) {
	            log.error("删除定时任务失败，调度异常:", e);
	            return ResponseVo.error(ResponseEnum.BATCH_SCHEDULER_DELETE_FAILED_DISPATCH_ERROR);
	        }
	
	        return ResponseVo.success();
	    }
	
	    /**
	     * 查看所有任务
	     */
	    @RequestMapping(value = "/query", method = RequestMethod.GET)
	    public ResponseVo query() {
	        log.info("查看所有定时任务开始");
	
	        List<CronVo> cronJobList = new ArrayList<>();
	        try {
	            Scheduler scheduler = schedulerFactoryBean.getScheduler();
	            for (String groupName : scheduler.getJobGroupNames()) {
	                for (JobKey jobKey : scheduler.getJobKeys(GroupMatcher.jobGroupEquals(groupName))) {
	                    CronVo vo = getCronVo(jobKey, scheduler);
	                    cronJobList.add(vo);
	                }
	            }
	
	        } catch (SchedulerException e) {
	            log.error("查看定时任务失败，调度异常:", e);
	            return ResponseVo.error(ResponseEnum.BATCH_SCHEDULER_QUERY_FAILED_DISPATCH_ERROR);
	        }
	
	        return ResponseVo.success(cronJobList);
	    }
	
	    private static CronVo getCronVo(JobKey jobKey, Scheduler scheduler) throws SchedulerException {
	        CronVo vo = new CronVo();
	        vo.setName(jobKey.getName());
	        vo.setGroup(jobKey.getGroup());
	
	        List<Trigger> triggers = (List<Trigger>) scheduler.getTriggersOfJob(jobKey);
	        CronTrigger cronTrigger = (CronTrigger) triggers.get(0);
	        vo.setDescription(cronTrigger.getDescription());
	        vo.setCronExpression(cronTrigger.getCronExpression());
	
	        Trigger.TriggerState triggerState = scheduler.getTriggerState(cronTrigger.getKey());
	        vo.setState(triggerState.name());
	        vo.setNextFireTime(cronTrigger.getNextFireTime());
	        vo.setPreFireTime(cronTrigger.getPreviousFireTime());
	        return vo;
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



### 基于 freemarker 的代码生成器

1. 引入依赖：

  ```xml
  <!--模板引擎 freemarker-->
  <dependency>
      <groupId>org.freemarker</groupId>
      <artifactId>freemarker</artifactId>
      <version>2.3.31</version>
  </dependency>
  <!--dom4j，读取 xml 文件-->
  <dependency>
      <groupId>org.dom4j</groupId>
      <artifactId>dom4j</artifactId>
  </dependency>
  <!--jaxen，使用 XPATH，可用于在 xml 中寻找所需的标签-->
  <dependency>
      <groupId>jaxen</groupId>
      <artifactId>jaxen</artifactId>
  </dependency>
  <!--mysql驱动，5.1开头的版本支持mysql5.7-->
  <dependency>
      <groupId>mysql</groupId>
      <artifactId>mysql-connector-java</artifactId>
  </dependency>
  ```

2. FreemarkerUtil 工具类：

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

3. ftl_demo 模板：

	```js
	public class ${domain} {
	    public String str;
	}
	```

4. Demo 的使用：

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
	
5. 读取数据库信息的工具类 DBUtil：

  ```java
  public class DBUtil {
  
      public static String url = "";
  
      public static String user = "";
  
      public static String password = "";
  
      private static final String MYSQL_JDBC_DRIVER_VERSION_5_7 = "com.mysql.jdbc.Driver";
  
      private static final String MYSQL_JDBC_DRIVER_VERSION_8_0 = "com.mysql.cj.jdbc.Driver";
  
      public static Connection getConnection() {
          Connection conn = null;
          try {
              Class.forName(MYSQL_JDBC_DRIVER_VERSION_5_7);
              String url = DBUtil.url;
              String user = DBUtil.user;
              String password = DBUtil.password;
              conn = DriverManager.getConnection(url, user, password);
          } catch (ClassNotFoundException e) {
              System.out.println("【看你是不是忘了在 pom.xml 中引入对应版本的 Mysql 驱动】");
              e.printStackTrace();
          } catch (SQLException e) {
              System.out.println("【看你是不是忘了在使用 DBUtil 之前先对 url, user, password 赋值】");
              e.printStackTrace();
          }
          return conn;
      }
  
      /**
       * 获得表注释
       */
      public static String getTableComment(String tableName) throws Exception {
          Connection conn = getConnection();
          Statement stmt = conn.createStatement();
          ResultSet rs = stmt.executeQuery("select table_comment from information_schema.tables Where table_name = '" + tableName + "'");
          String tableNameCH = "";
          if (rs != null) {
              while (rs.next()) {
                  tableNameCH = rs.getString("table_comment");
                  break;
              }
          }
          rs.close();
          stmt.close();
          conn.close();
          System.out.println("表名：" + tableNameCH);
          return tableNameCH;
      }
  
      /**
       * 获得所有列信息
       */
      public static List<Field> getColumnByTableName(String tableName) throws Exception {
          List<Field> fieldList = new ArrayList<>();
          Connection conn = getConnection();
          Statement stmt = conn.createStatement();
          ResultSet rs = stmt.executeQuery("show full columns from `" + tableName + "`");
          if (rs != null) {
              while (rs.next()) {
                  String columnName = rs.getString("Field");
                  String type = rs.getString("Type");
                  String comment = rs.getString("Comment");
                  String nullAble = rs.getString("Null"); //YES NO
                  Field field = new Field();
                  field.setName(columnName);
                  field.setNameHump(lineToHump(columnName));
                  field.setNameBigHump(lineToBigHump(columnName));
                  field.setType(type);
                  field.setJavaType(DBUtil.sqlTypeToJavaType(type));
                  field.setComment(comment);
                  if (comment.contains("|")) {
                      field.setNameCn(comment.substring(0, comment.indexOf("|")));
                  } else {
                      field.setNameCn(comment);
                  }
                  field.setNullAble("YES".equals(nullAble));
                  if (type.toUpperCase().contains("varchar".toUpperCase())) {
                      String lengthStr = type.substring(type.indexOf("(") + 1, type.length() - 1);
                      field.setLength(Integer.valueOf(lengthStr));
                  } else {
                      field.setLength(0);
                  }
                  if (comment.contains("枚举")) {
                      field.setEnums(true);
  
                      // 以课程等级为例：从注释中的“枚举[CourseLevelEnum]”，得到enumsConst = COURSE_LEVEL
                      int start = comment.indexOf("[");
                      int end = comment.indexOf("]");
                      String enumsName = comment.substring(start + 1, end); // CourseLevelEnum
                      String enumsConst = StrUtil.toUnderlineCase(enumsName)
                              .toUpperCase().replace("_ENUM", "");
                      field.setEnumsConst(enumsConst);
                  } else {
                      field.setEnums(false);
                  }
                  fieldList.add(field);
              }
          }
          rs.close();
          stmt.close();
          conn.close();
          System.out.println("列信息：" + JSONUtil.toJsonPrettyStr(fieldList));
          return fieldList;
      }
  
      /**
       * 下划线转小驼峰：member_id 转成 memberId
       */
      public static String lineToHump(String str) {
          Pattern linePattern = Pattern.compile("_(\\w)");
          str = str.toLowerCase();
          Matcher matcher = linePattern.matcher(str);
          StringBuffer sb = new StringBuffer();
          while (matcher.find()) {
              matcher.appendReplacement(sb, matcher.group(1).toUpperCase());
          }
          matcher.appendTail(sb);
          return sb.toString();
      }
  
      /**
       * 下划线转大驼峰：member_id 转成 MemberId
       */
      public static String lineToBigHump(String str) {
          String s = lineToHump(str);
          return s.substring(0, 1).toUpperCase() + s.substring(1);
      }
  
      /**
       * 数据库类型转为Java类型
       */
      public static String sqlTypeToJavaType(String sqlType) {
          if (sqlType.toUpperCase().contains("varchar".toUpperCase())
                  || sqlType.toUpperCase().contains("char".toUpperCase())
                  || sqlType.toUpperCase().contains("text".toUpperCase())) {
              return "String";
          } else if (sqlType.toUpperCase().contains("datetime".toUpperCase())) {
              return "Date";
          } else if (sqlType.toUpperCase().contains("time".toUpperCase())) {
              return "Date";
          } else if (sqlType.toUpperCase().contains("date".toUpperCase())) {
              return "Date";
          } else if (sqlType.toUpperCase().contains("bigint".toUpperCase())) {
              return "Long";
          } else if (sqlType.toUpperCase().contains("int".toUpperCase())) {
              return "Integer";
          } else if (sqlType.toUpperCase().contains("long".toUpperCase())) {
              return "Long";
          } else if (sqlType.toUpperCase().contains("decimal".toUpperCase())) {
              return "BigDecimal";
          } else if (sqlType.toUpperCase().contains("boolean".toUpperCase())) {
              return "Boolean";
          } else {
              return "String";
          }
      }
  
      public static void main(String[] args) throws Exception {
          DBUtil.url = "jdbc:mysql://localhost:3306/train_business?characterEncoding=UTF-8&amp;autoReconnect=true&amp;useSSL=false&amp;serverTimezone=Asia/Shanghai";
          DBUtil.user = "root";
          DBUtil.password = "1234";
          Connection conn = getConnection();
          Statement stmt = conn.createStatement();
          ResultSet rs = stmt.executeQuery("show tables");
          if (rs != null) {
              while (rs.next()) {
                  String tableName = rs.getString("Tables_in_train_business");
                  String str = "<table tableName=\"%s\" domainObjectName=\"%s\"/>".formatted(tableName, DBUtil.lineToBigHump(tableName));
                  System.out.println(str);
              }
          }
          rs.close();
          stmt.close();
          conn.close();
      }
  }
  ```

6. 读取数据库时，需要读出来的属性 Field：

	```java
	@Data
	public class Field {
	    /**
	     * 字段名：course_id
	     */
	    private String name;
	
	    /**
	     * 字段名小驼峰：courseId
	     */
	    private String nameHump;
	
	    /**
	     * 字段名大驼峰：CourseId
	     */
	    private String nameBigHump;
	
	    /**
	     * 中文名：课程
	     */
	    private String nameCn;
	
	    /**
	     * 字段类型：char(8)
	     */
	    private String type;
	
	    /**
	     * java类型：String
	     */
	    private String javaType;
	
	    /**
	     * 注释：课程|ID
	     */
	    private String comment;
	
	    /**
	     * 是否可为空
	     */
	    private Boolean nullAble;
	
	    /**
	     * 字符串长度
	     */
	    private Integer length;
	
	    /**
	     * 是否是枚举
	     */
	    private Boolean enums;
	
	    /**
	     * 枚举常量 COURSE_LEVEL，用于生成前端的 js 静态文件
	     */
	    private String enumsConst;
	}
	```

7. 集成读取数据库功能后的前后端代码生成器 ServerGenerator：

	> 1. 需要从 pom.xml 中读取 Mybatis-Generator_Path
	> 2. 从 generator-config-[module_name].xml 中读取需要生成前后端代码的表名
	> 3. 

	```java
	public class ServerGenerator {
	
	    private static String pomPath = "generator/pom.xml/";
	
	    private static String serverPath = "[module]/src/main/java/garry/train/[module]/";
	
	    private static String vuePath = "[isAdmin]/src/views/main/";
	
	    private static String module = "";
	
	    public static void main(String[] args) throws Exception {
	        // 获取 mybatis-generator 配置文件的路径
	        String generatorPath = getGeneratorPath();
	
	        // 获取 module，替换 serverPath 中的 [module]
	        module = generatorPath.replace("src/main/resources/generator-config-", "").replace(".xml", "");
	        System.out.println("module = " + module);
	        serverPath = serverPath.replace("[module]", module);
	
	        Document document = new SAXReader().read("generator/" + generatorPath);
	        // 获取数据库连接的参数
	        Node jdbcConnection = document.selectSingleNode("//jdbcConnection");
	        Node connectionURL = jdbcConnection.selectSingleNode("@connectionURL");
	        System.out.println("connectionURL = " + connectionURL.getText());
	        Node userId = jdbcConnection.selectSingleNode("@userId");
	        System.out.println("userId = " + userId.getText());
	        Node password = jdbcConnection.selectSingleNode("@password");
	        System.out.println("password = " + password.getText());
	        DBUtil.url = connectionURL.getText();
	        DBUtil.user = userId.getText();
	        DBUtil.password = password.getText();
	
	        // 遍历每一个 table
	        List<Node> tables = document.selectNodes("//table");
	        for (Node table : tables) {
	            Node tableName = table.selectSingleNode("@tableName");
	            Node domainObjectName = table.selectSingleNode("@domainObjectName");
	            System.out.println("tableName: " + tableName.getText() + " / " + "domainObjectName: " + domainObjectName.getText());
	
	            // 示例：表名 garry_test
	            // GarryTest，类名
	            String Domain = domainObjectName.getText();
	            // garryTest，属性变量名
	            String domain = Domain.substring(0, 1).toLowerCase() + Domain.substring(1);
	            // garry-test，url 名
	            String do_main = tableName.getText().replace("_", "-");
	            // 表中文名
	            String tableNameCn = DBUtil.getTableComment(tableName.getText());
	            List<Field> fieldList = DBUtil.getColumnByTableName(tableName.getText());
	            Set<String> typeSet = getJavaTypes(fieldList);
	
	            // 组装参数
	            HashMap<String, Object> param = new HashMap<>();
	            param.put("module", module);
	            param.put("Domain", Domain);
	            param.put("domain", domain);
	            param.put("do_main", do_main);
	            param.put("DateTime", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")));
	            param.put("tableNameCn", tableNameCn);
	            param.put("fieldList", fieldList);
	            param.put("typeSet", typeSet);
	            System.out.println("组装参数: " + JSONUtil.toJsonPrettyStr(param));
	
	//            generateAll(Domain, do_main, param, true);
	            generateVue(do_main, param, true, true);
	        }
	    }
	
	    /**
	     * 执行代码生成
	     *
	     * @param Domain      pojo 类名，Passenger
	     * @param param       额外携带的参数
	     * @param packageName 包名，service/impl/，vo/，form/
	     * @param target      freemarker 模板名，service-impl，save-vo，save-form
	     */
	    private static void generate(String Domain, HashMap<String, Object> param, String packageName, String target) throws IOException, TemplateException {
	        System.out.println("\n------------- generate 开始 -------------");
	        FreemarkerUtil.initConfig(target + ".ftl"); // service-impl.ftl
	        String[] strings = target.split("-"); // ["service", "impl"]
	        StringBuilder suffixClass = new StringBuilder(); // 类名的后缀，ServiceImpl
	        for (String str : strings) {
	            suffixClass.append(str.substring(0, 1).toUpperCase()).append(str.substring(1));
	        }
	        String toPath = serverPath + packageName; // [module]/src/main/java/garry/train/[module]/service/impl/
	        System.out.println("toPath = " + toPath);
	        new File(toPath).mkdirs(); // 生成 toPath 路径，避免生成时还没有这个路径
	        String fullClassName = (Domain + suffixClass + ".java").replace("Pojo", ""); // PassengerServiceImpl.java
	        System.out.println("fullClassName = " + fullClassName);
	        String fullPath = toPath + fullClassName; // [module]/src/main/java/garry/train/[module]/service/impl/PassengerServiceImpl.java
	        System.out.println("fullPath = " + fullPath);
	        FreemarkerUtil.generator(fullPath, param);
	        System.out.println("------------- generate 结束 -------------\n");
	    }
	
	    private static void generateAll(String Domain, String do_main, HashMap<String, Object> param, Boolean isAdmin) throws IOException, TemplateException {
	        generateBackend(Domain, param, isAdmin);
	        generateVue(do_main, param, false, isAdmin);
	    }
	
	    /**
	     * 生成后端代码
	     */
	    private static void generateBackend(String Domain, HashMap<String, Object> param, Boolean isAdmin) throws IOException, TemplateException {
	        generate(Domain, param, "pojo/", "pojo");
	        generate(Domain, param, "form/", "save-form");
	        generate(Domain, param, "form/", "query-form");
	        generate(Domain, param, "vo/", "query-vo");
	        generate(Domain, param, "service/", "service");
	        generate(Domain, param, "service/impl/", "service-impl");
	        if (!isAdmin)
	            generate(Domain, param, "controller/", "controller");
	        else
	            generate(Domain, param, "controller/admin/", "admin-controller");
	    }
	
	    /**
	     * 专门生成前端 vue 页面的生成器
	     */
	    private static void generateVue(String do_main, HashMap<String, Object> param, Boolean readOnly, Boolean isAdmin) throws IOException, TemplateException {
	        System.out.println("\n------------- generateVue 开始 -------------");
	        param.put("readOnly", readOnly);
	        String fullPath = "";
	        if (!isAdmin) {
	            FreemarkerUtil.initConfig("vue.ftl");
	            vuePath = vuePath.replace("[isAdmin]", "web");
	            new File(vuePath).mkdirs();
	            fullPath = vuePath + do_main + ".vue";
	        } else {
	            FreemarkerUtil.initConfig("admin-vue.ftl");
	            vuePath = vuePath.replace("[isAdmin]", "admin");
	            new File(vuePath).mkdirs();
	            fullPath = vuePath + do_main + ".vue";
	        }
	        System.out.println("fullPath = " + fullPath);
	        FreemarkerUtil.generator(fullPath, param);
	        System.out.println("------------- generateVue 结束 -------------\n");
	    }
	
	    /**
	     * 从 generator/pom.xml/ 中获取 Mybatis-generator 配置文件的路径
	     */
	    private static String getGeneratorPath() throws DocumentException {
	        SAXReader saxReader = new SAXReader();
	        HashMap<String, String> map = new HashMap<>();
	        map.put("pom", "http://maven.apache.org/POM/4.0.0");
	        saxReader.getDocumentFactory().setXPathNamespaceURIs(map);
	        Document document = saxReader.read(pomPath);
	        /*
	          使用 XPATH 在 xml 文件中找寻所需的标签
	          解释 "//pom:configurationFile"：
	          // : 从根目录下寻找
	          pom : xml 的命名空间
	          configurationFile : 节点名
	          若要找 configurationFile 下的某属性，就用:
	          Node.selectSingleNode("@propertyName")
	         */
	        Node node = document.selectSingleNode("//pom:configurationFile");
	        System.out.println("generatorPath = " + node.getText());
	        return node.getText();
	    }
	
	    /**
	     * 获取所有的Java类型，使用Set去重
	     */
	    private static Set<String> getJavaTypes(List<Field> fieldList) {
	        Set<String> set = new HashSet<>();
	        for (int i = 0; i < fieldList.size(); i++) {
	            Field field = fieldList.get(i);
	            set.add(field.getJavaType());
	        }
	        return set;
	    }
	}
	```

8. ftl 模板复制到了当前目录下 (xxx.ftl)

----



### 枚举类前端 enum.js 生成器

1. EnumGenerator：

	```java
	public class EnumGenerator {
	    private static String path = "admin/src/assets/js/enums.js";
	
	    public static void main(String[] args) {
	        StringBuffer bufferObject = new StringBuffer();
	        StringBuffer bufferArray = new StringBuffer();
	        long begin = System.currentTimeMillis();
	        try {
	            toJson(PassengerTypeEnum.class, bufferObject, bufferArray);
	            toJson(TrainTypeEnum.class, bufferObject, bufferArray);
	            toJson(SeatTypeEnum.class, bufferObject, bufferArray);
	            toJson(SeatColEnum.class, bufferObject, bufferArray);
	
	            StringBuffer buffer = bufferObject.append("\r\n").append(bufferArray);
	            writeJs(buffer);
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	        long end = System.currentTimeMillis();
	        System.out.println("执行耗时:" + (end - begin) + " 毫秒");
	    }
	
	    private static void toJson(Class clazz, StringBuffer bufferObject, StringBuffer bufferArray) throws Exception {
	        String enumConst = StrUtil.toUnderlineCase(clazz.getSimpleName())
	                .toUpperCase().replace("_ENUM", "");
	        Object[] objects = clazz.getEnumConstants(); // enumConst：将 YesNoEnum 变成 YES_NO
	        Method name = clazz.getMethod("name");
	
	        // 排除枚举属性和$VALUES，只获取code desc等
	        List<Field> targetFields = new ArrayList<>();
	        Field[] fields = clazz.getDeclaredFields();
	        for (Field field : fields) {
	            if (!Modifier.isPrivate(field.getModifiers()) || "$VALUES".equals(field.getName())) {
	                continue;
	            }
	            targetFields.add(field);
	        }
	
	        // 生成对象
	        bufferObject.append(enumConst).append("={");
	        for (int i = 0; i < objects.length; i++) {
	            Object obj = objects[i];
	            bufferObject.append(name.invoke(obj)).append(":");
	
	            // 将一个枚举值转成JSON对象字符串
	            formatJsonObj(bufferObject, targetFields, clazz, obj);
	
	            if (i < objects.length - 1) {
	                bufferObject.append(",");
	            }
	        }
	        bufferObject.append("};\r\n");
	
	        // 生成数组
	        bufferArray.append(enumConst).append("_ARRAY=[");
	        for (int i = 0; i < objects.length; i++) {
	            Object obj = objects[i];
	
	            // 将一个枚举值转成JSON对象字符串
	            formatJsonObj(bufferArray, targetFields, clazz, obj);
	
	            if (i < objects.length - 1) {
	                bufferArray.append(",");
	            }
	        }
	        bufferArray.append("];\r\n");
	    }
	
	    /**
	     * 将一个枚举值转成JSON对象字符串
	     * 比如：SeatColEnum.YDZ_A("A", "A", "1")
	     * 转成：{code:"A",desc:"A",type:"1"}
	     */
	    private static void formatJsonObj(StringBuffer bufferObject, List<Field> targetFields, Class clazz, Object obj) throws IllegalAccessException, InvocationTargetException, NoSuchMethodException {
	        bufferObject.append("{");
	        for (int j = 0; j < targetFields.size(); j++) {
	            Field field = targetFields.get(j);
	            String fieldName = field.getName();
	            // 获取 targetFields 字段对应的 get 方法
	            String getMethod = "get" + fieldName.substring(0, 1).toUpperCase() + fieldName.substring(1);
	            bufferObject.append(fieldName).append(":\"").append(clazz.getMethod(getMethod).invoke(obj)).append("\"");
	            if (j < targetFields.size() - 1) {
	                bufferObject.append(",");
	            }
	        }
	        bufferObject.append("}");
	    }
	
	    /**
	     * 写文件
	     * @param stringBuffer
	     */
	    public static void writeJs(StringBuffer stringBuffer) {
	        FileOutputStream out = null;
	        try {
	            out = new FileOutputStream(path);
	            OutputStreamWriter osw = new OutputStreamWriter(out, "UTF-8");
	            System.out.println(path);
	            osw.write(stringBuffer.toString());
	            osw.close();
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	        finally {
	            try {
	                out.close();
	            } catch (Exception e) {
	                e.printStackTrace();
	            }
	        }
	    }
	}
	```

2. 效果 enum.js：

	```js
	PASSENGER_TYPE={ADULT:{code:"1",desc:"成人"},CHILD:{code:"2",desc:"儿童"},STUDENT:{code:"3",desc:"学生"}};
	TRAIN_TYPE={G:{code:"G",desc:"高铁",priceRate:"1.2"},D:{code:"D",desc:"动车",priceRate:"1"},K:{code:"K",desc:"快速",priceRate:"0.8"}};
	SEAT_TYPE={YDZ:{code:"1",desc:"一等座",price:"0.4"},EDZ:{code:"2",desc:"二等座",price:"0.3"},RW:{code:"3",desc:"软卧",price:"0.6"},YW:{code:"4",desc:"硬卧",price:"0.5"}};
	SEAT_COL={YDZ_A:{code:"A",desc:"A",type:"1"},YDZ_C:{code:"C",desc:"C",type:"1"},YDZ_D:{code:"D",desc:"D",type:"1"},YDZ_F:{code:"F",desc:"F",type:"1"},EDZ_A:{code:"A",desc:"A",type:"2"},EDZ_B:{code:"B",desc:"B",type:"2"},EDZ_C:{code:"C",desc:"C",type:"2"},EDZ_D:{code:"D",desc:"D",type:"2"},EDZ_F:{code:"F",desc:"F",type:"2"}};
	
	PASSENGER_TYPE_ARRAY=[{code:"1",desc:"成人"},{code:"2",desc:"儿童"},{code:"3",desc:"学生"}];
	TRAIN_TYPE_ARRAY=[{code:"G",desc:"高铁",priceRate:"1.2"},{code:"D",desc:"动车",priceRate:"1"},{code:"K",desc:"快速",priceRate:"0.8"}];
	SEAT_TYPE_ARRAY=[{code:"1",desc:"一等座",price:"0.4"},{code:"2",desc:"二等座",price:"0.3"},{code:"3",desc:"软卧",price:"0.6"},{code:"4",desc:"硬卧",price:"0.5"}];
	SEAT_COL_ARRAY=[{code:"A",desc:"A",type:"1"},{code:"C",desc:"C",type:"1"},{code:"D",desc:"D",type:"1"},{code:"F",desc:"F",type:"1"},{code:"A",desc:"A",type:"2"},{code:"B",desc:"B",type:"2"},{code:"C",desc:"C",type:"2"},{code:"D",desc:"D",type:"2"},{code:"F",desc:"F",type:"2"}];
	
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

