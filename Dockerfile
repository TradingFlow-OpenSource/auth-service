FROM node:22-alpine

# 安装 pnpm
RUN corepack enable && corepack prepare pnpm@latest --activate

# 设置工作目录
WORKDIR /app


# 复制 package.json
COPY ./package.json ./

# 安装依赖
RUN pnpm install --prod

# 复制源代码
COPY ./src /app/src

# 暴露端口
EXPOSE 4000

# 启动命令
CMD ["node", "src/index.js"]
