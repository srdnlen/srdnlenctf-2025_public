FROM python:3.11-bullseye

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

RUN apt-get update && apt-get install -y openjdk-11-jdk && apt-get clean

RUN cd $(python -c "import os, pyspark; print(os.path.dirname(pyspark.__file__))")/jars && \
    rm log4j* && \
    wget https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar && \
    wget https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar && \
    wget https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-slf4j-impl/2.14.1/log4j-slf4j-impl-2.14.1.jar && \
    wget https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-1.2-api/2.14.1/log4j-1.2-api-2.14.1.jar

RUN useradd -m appuser
RUN mv /app/flag.txt /
RUN mv /app/instance /

RUN chown -R appuser:appuser /app
RUN chmod 444 /flag.txt

USER appuser

EXPOSE 5000

CMD ["python", "run.py"]