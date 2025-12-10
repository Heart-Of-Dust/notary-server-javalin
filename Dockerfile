FROM openjdk:17-jdk-slim

WORKDIR /app

# 安装必要的工具
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# 复制JAR文件
COPY target/trustless-notary-service-1.1.3.jar app.jar

# 创建非root用户运行
RUN useradd -m -u 1000 notary
USER notary

# 暴露端口
EXPOSE 8080

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# 启动命令
ENTRYPOINT ["java", "-jar", "app.jar"]