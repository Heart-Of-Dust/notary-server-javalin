package com.notary;

import io.javalin.Javalin;
import io.javalin.plugin.bundled.CorsPluginConfig;
import com.notary.config.AppConfig;
import com.notary.controller.NotaryController;
import com.notary.controller.HealthController;
import com.notary.exception.ExceptionHandler;
import com.notary.interceptor.RequestLoggingInterceptor;

public class NotaryApplication {
    public static void main(String[] args) {
        // 初始化配置
        AppConfig config = AppConfig.load();

        // 创建Javalin应用
        Javalin app = Javalin.create(cfg -> {
            cfg.plugins.enableCors(cors -> cors.add(CorsPluginConfig::anyHost));
            cfg.http.defaultContentType = "application/json";
            cfg.showJavalinBanner = false;
        });

        // 注册请求日志拦截器
        app.before(RequestLoggingInterceptor::logRequest);
        app.after(RequestLoggingInterceptor::logResponse);
        app.exception(Exception.class, (e, ctx) -> RequestLoggingInterceptor.logException(ctx, e));

        // 注册路由
        NotaryController.registerRoutes(app);
        HealthController.registerRoutes(app);

        // 注册异常处理
        ExceptionHandler.register(app);

        // 启动服务
        app.start(config.getServerPort());
    }
}