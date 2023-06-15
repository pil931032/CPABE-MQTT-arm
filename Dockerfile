FROM arm64v8/python:3.8-bullseye

ENV PYTHONUNBUFFERED 1

RUN apt-get update && apt-get install -y --no-install-recommends \
                bison \
                flex \
        && rm -rf /var/lib/apt/lists/*

ENV LIBRARY_PATH /usr/local/lib
ENV LD_LIBRARY_PATH /usr/local/lib
ENV LIBRARY_INCLUDE_PATH /usr/local/include

# PBC
RUN apt-get install libgmp-dev flex bison -y
RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz \
    && tar zxvf pbc-0.5.14.tar.gz pbc \
    && cd pbc \
    && ./configure \
    && make \
    && make install


# COPY --from=initc3/pbc:0.5.14-buster \
#                 /usr/local/include/pbc \
#                 /usr/local/include/pbc
# COPY --from=initc3/pbc:0.5.14-buster \
#                 /usr/local/lib/libpbc.so.1.0.0  \
#                 /usr/local/lib/libpbc.so.1.0.0

RUN set -ex \
    && cd /usr/local/lib \
    && ln -s libpbc.so.1.0.0 libpbc.so \
    && ln -s libpbc.so.1.0.0 libpbc.so.1

ENV PYTHON_LIBRARY_PATH /opt/venv
ENV PATH ${PYTHON_LIBRARY_PATH}/bin:${PATH}

COPY ./charm /usr/src/charm

RUN chmod -R 777 /usr/src/charm

RUN set -ex \
        \
        && cd /usr/src/charm \
        && python -m venv ${PYTHON_LIBRARY_PATH} \
        && ./configure.sh \
        && make install \
        && rm -rf /usr/src/charm

COPY .bashrc /root/.bashrc
COPY requirements.txt .
RUN  pip install --upgrade pip && pip install -r requirements.txt