FROM docker.io/sagemath/sagemath:10.5

WORKDIR /usr/app/src
COPY ./__main__.py ./requirements.txt ./echelonize.cpp /usr/app/src/

USER root
RUN apt-get update && apt-get install -y python3-pip && apt-get clean
RUN sage -pip install --no-cache-dir -r requirements.txt
RUN apt-get install -y libntl-dev
RUN g++ -Ofast -funroll-loops -o echelonize echelonize.cpp -lntl
RUN chown -R sage:sage /usr/app/src
USER sage

ENTRYPOINT ["sage", "--python", "__main__.py"]
