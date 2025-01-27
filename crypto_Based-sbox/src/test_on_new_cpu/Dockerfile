FROM docker.io/sagemath/sagemath:10.5

WORKDIR /usr/app/src
COPY ./test.py /usr/app/src/

ENTRYPOINT ["sage", "--python", "test.py"]
