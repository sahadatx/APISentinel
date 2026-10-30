FROM python:3.12-slim
RUN groupadd --system --gid 10002 apkparser && useradd --system --uid 10002 --gid apkparser --home-dir /app apkparser
WORKDIR /app
COPY server.py ./server.py
COPY static_analysis.py ./static_analysis.py
USER 10002:10002
EXPOSE 8090
CMD ["python", "-I", "/app/server.py"]
