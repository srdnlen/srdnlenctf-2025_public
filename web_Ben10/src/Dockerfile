FROM python:3.11-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

ENV FLASK_ENV=production
ENV FLAG="srdnlen{b3n_l0v3s_br0k3n_4cc355_c0ntr0l_vulns}"

CMD ["flask", "run", "--host=0.0.0.0"]
