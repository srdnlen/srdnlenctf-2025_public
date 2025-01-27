# How to run the checker

To run the checker, you need pwntools, xoflib, and SageMath installed via src, system package, or other means. Then you simply run the following command in the terminal:

```bash
sage --python solve.py <host> <port>
```

Note that `echelonize.cpp` was compiled on my machine, so you may need to compile it on your machine. To do so, run the following command:

```bash
g++ -Ofast -funroll-loops -o echelonize echelonize.cpp -lntl
```

## Docker

In case you don't have SageMath installed, you can use the provided Dockerfile to build a Docker image and run the checker inside a container. To do so, run the following commands:

```bash
docker build -t checker-based-sbox .
docker run -it checker-based-sbox <host> <port>
```

From `Dockerfile`:

```dockerfile
FROM docker.io/sagemath/sagemath:10.4

WORKDIR /usr/app/src
COPY ./__main__.py ./requirements.txt ./echelonize.cpp /usr/app/src/

USER root
RUN apt-get update && apt-get install -y python3-pip && apt-get clean
RUN sage -pip install --no-cache-dir pwntools
RUN sage -pip install --no-cache-dir -r requirements.txt
RUN apt-get install -y libntl-dev
RUN g++ -Ofast -funroll-loops -o echelonize echelonize.cpp -lntl
RUN chown -R sage:sage /usr/app/src
USER sage

ENTRYPOINT ["sage", "--python", "__main__.py"]
```
